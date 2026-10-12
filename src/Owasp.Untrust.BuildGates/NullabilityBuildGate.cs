using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class NullabilityBuildGateAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor NullLiteralRule = new(
        BuildGateDiagnosticIds.NullLiteral,
        "Null requires a reviewed justification",
        "Null literal requires either a preceding '//' or one-line '/* */' comment using 'untrust-allow-null: <reason>' (minimum {0} characters) or 'untrust-null-represents-no-value: <description>' (minimum {1} characters); the latter may instead be an end-of-line '//' comment after the null literal. Use nullabilityExemptions only for recurring reviewed type/context cases.",
        "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor NullableFirstArgumentRule = new(
        BuildGateDiagnosticIds.NullableFirstArgument,
        "Nullable first argument requires a reviewed boundary contract",
        "Method '{0}' accepts nullable first argument '{1}'. First preserve the nullable contract when implementing an interface or override. Otherwise prefer a non-nullable parameter: move the null check to the caller and do not call this method when the argument is null. Use a reviewed untrust-null-represents-no-value escape hatch only when neither design is viable.",
        "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(
        BuildGateDiagnosticIds.ConfigurationConflict, "BuildGate configuration error", "BuildGate configuration error: {0}", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(NullLiteralRule, NullableFirstArgumentRule, ConfigurationConflictRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(startContext =>
        {
            startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? configurationDirectory);
            if (string.IsNullOrWhiteSpace(configurationDirectory)) startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out configurationDirectory);
            SharedBuildGateConfiguration shared = SharedBuildGateConfigurationProvider.Get(startContext.Compilation, startContext.Options.AdditionalFiles, configurationDirectory);
            NullabilityPolicy policy = NullabilityPolicy.Load(shared);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeNullLiteral(nodeContext, policy), SyntaxKind.NullLiteralExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeNullableFirstArgument(nodeContext, policy), SyntaxKind.MethodDeclaration);
            startContext.RegisterCompilationEndAction(endContext =>
            {
                foreach (string conflict in policy.ConfigurationConflicts) endContext.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, conflict));
            });
        });
    }
    private static void AnalyzeNullLiteral(SyntaxNodeAnalysisContext context, NullabilityPolicy policy)
    {
        if (context.Node.Parent is ConstantPatternSyntax || policy.AllowsNullAssignment(context) || HasNullJustification(context.Node, policy))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(NullLiteralRule, context.Node.GetLocation(), policy.MinimumNullJustificationCharacters, policy.MinimumNoValueDescriptionCharacters));
    }

    private static bool HasNullJustification(SyntaxNode nullLiteral, NullabilityPolicy policy)
    {
        FileLinePositionSpan span = nullLiteral.GetLocation().GetLineSpan();
        SourceText source = nullLiteral.SyntaxTree.GetText();
        string currentLine = source.Lines[span.StartLinePosition.Line].ToString();
        if (HasEndOfLineJustification(currentLine, span.StartLinePosition.Character, policy))
        {
            return true;
        }

        return span.StartLinePosition.Line > 0 && HasCommentJustification(source.Lines[span.StartLinePosition.Line - 1].ToString().Trim(), policy);
    }

    private static bool HasEndOfLineJustification(string line, int nullStartColumn, NullabilityPolicy policy)
    {
        int commentStart = line.IndexOf("//", nullStartColumn, StringComparison.Ordinal);
        return commentStart >= 0 && HasCommentJustification(line.Substring(commentStart), policy);
    }

    private static bool HasCommentJustification(string comment, NullabilityPolicy policy)
    {
        string? content = SharedHelpers.GetCommentContent(comment);
        if (content is null)
        {
            return false;
        }

        foreach (string marker in policy.NullJustificationMarkers)
        {
            if (content.StartsWith(marker, StringComparison.Ordinal))
            {
                int minimumLength = policy.UsesLegacyNullMarker(marker)
                    ? policy.MinimumNullJustificationCharacters
                    : policy.MinimumNoValueDescriptionCharacters;
                return content.Substring(marker.Length).Trim().Length >= minimumLength;
            }
        }

        return false;
    }

    private static void AnalyzeNullableFirstArgument(SyntaxNodeAnalysisContext context, NullabilityPolicy policy)
    {
        var declaration = (MethodDeclarationSyntax)context.Node;
        if (declaration.ParameterList.Parameters.Count == 0 || context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not IMethodSymbol method)
        {
            return;
        }

        IParameterSymbol firstParameter = method.Parameters[0];
        if (firstParameter.NullableAnnotation == NullableAnnotation.Annotated && !policy.AllowsNullableFirstArgument(firstParameter, method) && !HasNullJustification(declaration, policy))
        {
            context.ReportDiagnostic(Diagnostic.Create(NullableFirstArgumentRule, declaration.Identifier.GetLocation(), method.Name, firstParameter.Name));
        }
    }
}
