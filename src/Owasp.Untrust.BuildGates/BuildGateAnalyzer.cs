using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class BuildGateAnalyzer : DiagnosticAnalyzer
{
    public const string NullLiteralId = "UBG001";
    public const string MemberPrefixId = "UBG002";
    public const string ForbiddenMethodId = "UBG003";

    private static readonly DiagnosticDescriptor NullLiteralRule = new(
        NullLiteralId,
        "Null requires a reviewed justification",
        "Null literal requires an immediately preceding '// untrust-allow-null: <reason>' comment with at least {0} characters of explanation",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor MemberPrefixRule = new(
        MemberPrefixId,
        "Member field does not follow the required naming policy",
        "Member field '{0}' must start with '{1}'",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ForbiddenMethodRule = new(
        ForbiddenMethodId,
        "Forbidden API",
        "Call to '{0}' is forbidden: {1}",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(NullLiteralRule, MemberPrefixRule, ForbiddenMethodRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(startContext =>
        {
            BuildGatePolicy policy = BuildGatePolicy.Load(startContext.Options.AdditionalFiles);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeNullLiteral(nodeContext, policy), SyntaxKind.NullLiteralExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeField(nodeContext, policy), SyntaxKind.VariableDeclarator);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeInvocation(nodeContext, policy), SyntaxKind.InvocationExpression);
        });
    }

    private static void AnalyzeNullLiteral(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (HasNullJustification(context.Node, policy))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(NullLiteralRule, context.Node.GetLocation(), policy.MinimumNullJustificationCharacters));
    }

    private static bool HasNullJustification(SyntaxNode nullLiteral, BuildGatePolicy policy)
    {
        FileLinePositionSpan span = nullLiteral.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        string precedingLine = nullLiteral.SyntaxTree.GetText().Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        if (!precedingLine.StartsWith(policy.NullJustificationPrefix, StringComparison.Ordinal))
        {
            return false;
        }

        string reason = precedingLine.Substring(policy.NullJustificationPrefix.Length).Trim();
        return reason.Length >= policy.MinimumNullJustificationCharacters;
    }

    private static void AnalyzeField(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var variable = (VariableDeclaratorSyntax)context.Node;
        if (variable.Parent?.Parent is not FieldDeclarationSyntax ||
            variable.Identifier.ValueText.StartsWith(policy.MemberPrefix, StringComparison.Ordinal))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            MemberPrefixRule,
            variable.Identifier.GetLocation(),
            variable.Identifier.ValueText,
            policy.MemberPrefix));
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;
        if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method)
        {
            return;
        }

        ForbiddenMethodPolicy? match = policy.ForbiddenMethods.FirstOrDefault(rule => rule.Matches(method));
        if (match is null)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            ForbiddenMethodRule,
            invocation.GetLocation(),
            method.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat),
            match.Message));
    }
}

internal sealed class BuildGatePolicy
{
    private const string DefaultNullJustificationPrefix = "// untrust-allow-null:";

    public string MemberPrefix { get; set; } = "m_";
    public string NullJustificationPrefix { get; set; } = DefaultNullJustificationPrefix;
    public int MinimumNullJustificationCharacters { get; set; } = 40;
    public ImmutableArray<ForbiddenMethodPolicy> ForbiddenMethods { get; set; } = ImmutableArray<ForbiddenMethodPolicy>.Empty;

    public static BuildGatePolicy Load(ImmutableArray<AdditionalText> additionalFiles)
    {
        AdditionalText? policyFile = additionalFiles.FirstOrDefault(file =>
            string.Equals(Path.GetFileName(file.Path), "buildgates.json", StringComparison.OrdinalIgnoreCase));
        if (policyFile?.GetText() is not SourceText sourceText)
        {
            return new BuildGatePolicy();
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(sourceText.ToString());
            JsonElement root = document.RootElement;
            return new BuildGatePolicy
            {
                MemberPrefix = ReadString(root, "memberPrefix") ?? "m_",
                NullJustificationPrefix = ReadString(root, "nullJustificationPrefix") ?? DefaultNullJustificationPrefix,
                MinimumNullJustificationCharacters = ReadPositiveInteger(root, "minimumNullJustificationCharacters", 40),
                ForbiddenMethods = ReadForbiddenMethods(root),
            };
        }
        catch (JsonException)
        {
            return new BuildGatePolicy();
        }
    }

    private static string? ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int ReadPositiveInteger(JsonElement root, string propertyName, int defaultValue) =>
        root.TryGetProperty(propertyName, out JsonElement value) && value.TryGetInt32(out int number) && number > 0
            ? number
            : defaultValue;

    private static ImmutableArray<ForbiddenMethodPolicy> ReadForbiddenMethods(JsonElement root)
    {
        if (!root.TryGetProperty("forbiddenMethods", out JsonElement rules) || rules.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<ForbiddenMethodPolicy>.Empty;
        }

        var result = ImmutableArray.CreateBuilder<ForbiddenMethodPolicy>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? containingType = ReadString(rule, "containingType");
            string? method = ReadString(rule, "method");
            string? message = ReadString(rule, "message");
            if (string.IsNullOrWhiteSpace(containingType) || string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            bool includeSubclasses = rule.TryGetProperty("includeSubclasses", out JsonElement includeValue) && includeValue.ValueKind == JsonValueKind.True;
            result.Add(new ForbiddenMethodPolicy(containingType!, method!, message!, includeSubclasses));
        }

        return result.ToImmutable();
    }
}

internal sealed class ForbiddenMethodPolicy
{
    public ForbiddenMethodPolicy(string containingType, string method, string message, bool includeSubclasses)
    {
        ContainingType = containingType;
        Method = method;
        Message = message;
        IncludeSubclasses = includeSubclasses;
    }

    public string ContainingType { get; }
    public string Method { get; }
    public string Message { get; }
    public bool IncludeSubclasses { get; }

    public bool Matches(IMethodSymbol candidate) =>
        string.Equals(candidate.Name, Method, StringComparison.Ordinal) && MatchesType(candidate.ContainingType);

    private bool MatchesType(INamedTypeSymbol? candidate)
    {
        for (INamedTypeSymbol? current = candidate; current is not null; current = IncludeSubclasses ? current.BaseType : null)
        {
            if (string.Equals(current.ToDisplayString(), ContainingType, StringComparison.Ordinal))
            {
                return true;
            }

            if (!IncludeSubclasses)
            {
                return false;
            }
        }

        return IncludeSubclasses && candidate?.AllInterfaces.Any(@interface =>
            string.Equals(@interface.ToDisplayString(), ContainingType, StringComparison.Ordinal)) == true;
    }
}
