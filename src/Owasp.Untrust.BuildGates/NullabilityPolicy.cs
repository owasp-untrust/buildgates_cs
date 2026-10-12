using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

internal sealed class NullabilityPolicy
{
    private const string ConfigurationName = "nullability-enforcement";
    private const string DefaultNullJustificationMarker = "untrust-null-represents-no-value:";
    private const string LegacyNullJustificationMarker = "untrust-allow-null:";

    private readonly ImmutableArray<NullabilityExemptionPolicy> exemptions;

    private NullabilityPolicy(
        string nullJustificationPrefix,
        int minimumNullJustificationCharacters,
        int minimumNoValueDescriptionCharacters,
        ImmutableArray<NullabilityExemptionPolicy> exemptions,
        ImmutableArray<string> configurationConflicts)
    {
        NullJustificationPrefix = nullJustificationPrefix;
        MinimumNullJustificationCharacters = minimumNullJustificationCharacters;
        MinimumNoValueDescriptionCharacters = minimumNoValueDescriptionCharacters;
        this.exemptions = exemptions;
        ConfigurationConflicts = configurationConflicts;
    }

    public string NullJustificationPrefix { get; }
    public int MinimumNullJustificationCharacters { get; }
    public int MinimumNoValueDescriptionCharacters { get; }
    public ImmutableArray<string> ConfigurationConflicts { get; }

    public ImmutableArray<string> NullJustificationMarkers => ImmutableArray.Create(
        NormalizeCommentMarker(NullJustificationPrefix),
        DefaultNullJustificationMarker,
        LegacyNullJustificationMarker);

    public static NullabilityPolicy Load(SharedBuildGateConfiguration sharedConfiguration)
    {
        string prefix = DefaultNullJustificationMarker;
        int minimumJustificationCharacters = 40;
        int minimumNoValueCharacters = 15;
        var exemptions = ImmutableArray.CreateBuilder<NullabilityExemptionPolicy>();
        var conflicts = ImmutableArray.CreateBuilder<string>();
        var configuredScalars = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (BuildGateConfigurationDocument document in sharedConfiguration.GetDocuments(ConfigurationName))
        {
            if (!BuildGateJson.TryParseObject(document.Text.ToString(), document.Path, conflicts.Add, out JsonDocument? jsonDocument))
            {
                continue;
            }

            using (jsonDocument!)
            {
                JsonElement root = jsonDocument!.RootElement;
                MergeString(root, "nullJustificationPrefix", document.Path, sharedConfiguration, configuredScalars, conflicts, value => prefix = value);
                BuildGateJson.MergePositiveInteger(root, "minimumNullJustificationCharacters", (name, value, apply) => MergeScalar(name, value, document.Path, configuredScalars, conflicts, apply), value => minimumJustificationCharacters = value);
                BuildGateJson.MergePositiveInteger(root, "minimumNoValueDescriptionCharacters", (name, value, apply) => MergeScalar(name, value, document.Path, configuredScalars, conflicts, apply), value => minimumNoValueCharacters = value);
                exemptions.AddRange(ReadExemptions(root, sharedConfiguration, conflicts));
            }
        }

        return new NullabilityPolicy(prefix, minimumJustificationCharacters, minimumNoValueCharacters, exemptions.ToImmutable(), conflicts.ToImmutable());
    }

    public bool UsesLegacyNullMarker(string marker) => string.Equals(marker, LegacyNullJustificationMarker, StringComparison.Ordinal);

    public bool AllowsNullableFirstArgument(IParameterSymbol firstParameter, IMethodSymbol method) =>
        exemptions.Any(rule => rule.AllowsNullableFirstArgument(firstParameter.Type, method));

    public bool AllowsNullAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node.Parent is ArgumentSyntax argument && argument.Parent is BaseArgumentListSyntax argumentList && argumentList.Parent is InvocationExpressionSyntax invocation && context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is IMethodSymbol invokedMethod)
        {
            int argumentIndex = argumentList.Arguments.IndexOf(argument);
            if (argumentIndex >= 0 && argumentIndex < invokedMethod.Parameters.Length && exemptions.Any(rule => rule.AllowsArgument(invokedMethod.Parameters[argumentIndex].Type, invokedMethod))) return true;
        }

        if (context.Node.Parent?.Parent is ParameterSyntax parameter && parameter.Default?.Value == context.Node && context.SemanticModel.GetDeclaredSymbol(parameter, context.CancellationToken) is IParameterSymbol parameterSymbol)
            return exemptions.Any(rule => rule.AllowsDefaultArgument(parameterSymbol.Type));
        if (context.Node.Parent is AssignmentExpressionSyntax { Right: var assignedValue } assignment && assignedValue == context.Node && context.SemanticModel.GetSymbolInfo(assignment.Left, context.CancellationToken).Symbol is IParameterSymbol { RefKind: RefKind.Out } outParameter && context.SemanticModel.GetEnclosingSymbol(context.Node.SpanStart, context.CancellationToken) is IMethodSymbol outMethod)
            return exemptions.Any(rule => rule.AllowsOutValue(outParameter.Type, outMethod));
        if (context.Node.Ancestors().OfType<ReturnStatementSyntax>().FirstOrDefault() is not null && context.SemanticModel.GetEnclosingSymbol(context.Node.SpanStart, context.CancellationToken) is IMethodSymbol methodSymbol)
            return exemptions.Any(rule => rule.AllowsReturned(methodSymbol));
        if (context.Node.Ancestors().OfType<ArrowExpressionClauseSyntax>().FirstOrDefault() is { Parent: MethodDeclarationSyntax method })
            return context.SemanticModel.GetDeclaredSymbol(method, context.CancellationToken) is IMethodSymbol arrowMethod && exemptions.Any(rule => rule.AllowsReturned(arrowMethod));
        return false;
    }

    private static void MergeString(JsonElement root, string propertyName, string sourcePath, SharedBuildGateConfiguration sharedConfiguration, Dictionary<string, string> configuredScalars, ImmutableArray<string>.Builder conflicts, Action<string> setValue)
    {
        if (BuildGateJson.GetString(root, propertyName) is string value)
        {
            string resolved = ResolveMessage(value, sharedConfiguration, conflicts);
            MergeScalar(propertyName, JsonSerializer.Serialize(resolved), sourcePath, configuredScalars, conflicts, () => setValue(resolved));
        }
    }

    private static void MergeScalar(string propertyName, string value, string sourcePath, Dictionary<string, string> configuredScalars, ImmutableArray<string>.Builder conflicts, Action setValue)
    {
        if (configuredScalars.TryGetValue(propertyName, out string? existingValue))
        {
            if (!string.Equals(existingValue, value, StringComparison.Ordinal)) conflicts.Add($"'{propertyName}' has incompatible values; '{sourcePath}' cannot override a parent or earlier configuration.");
            return;
        }
        configuredScalars.Add(propertyName, value);
        setValue();
    }

    private static ImmutableArray<NullabilityExemptionPolicy> ReadExemptions(JsonElement root, SharedBuildGateConfiguration sharedConfiguration, ImmutableArray<string>.Builder conflicts)
    {
        if (!root.TryGetProperty("nullabilityExemptions", out JsonElement rules) || rules.ValueKind != JsonValueKind.Array) return ImmutableArray<NullabilityExemptionPolicy>.Empty;
        var result = ImmutableArray.CreateBuilder<NullabilityExemptionPolicy>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? typeAssignedTo = BuildGateJson.GetString(rule, "typeAssignedTo");
            string? methodName = BuildGateJson.GetString(rule, "methodName");
            string? methodNamePrefix = BuildGateJson.GetString(rule, "methodNamePrefix");
            string? justification = BuildGateJson.GetString(rule, "justification");
            if ((string.IsNullOrWhiteSpace(typeAssignedTo) && string.IsNullOrWhiteSpace(methodName) && string.IsNullOrWhiteSpace(methodNamePrefix)) || string.IsNullOrWhiteSpace(justification)) continue;
            result.Add(new NullabilityExemptionPolicy(typeAssignedTo, methodName, methodNamePrefix, ResolveMessage(justification!, sharedConfiguration, conflicts), rule.TryGetProperty("asDefaultArg", out JsonElement defaultArg) && defaultArg.ValueKind == JsonValueKind.True, rule.TryGetProperty("asReturned", out JsonElement returned) && returned.ValueKind == JsonValueKind.True, rule.TryGetProperty("asOutValue", out JsonElement outValue) && outValue.ValueKind == JsonValueKind.True, rule.TryGetProperty("asNullableFirstArgument", out JsonElement nullableFirstArgument) && nullableFirstArgument.ValueKind == JsonValueKind.True, rule.TryGetProperty("asArgument", out JsonElement argument) && argument.ValueKind == JsonValueKind.True));
        }
        return result.ToImmutable();
    }

    private static string ResolveMessage(string value, SharedBuildGateConfiguration sharedConfiguration, ImmutableArray<string>.Builder? conflicts)
    {
        if (!value.StartsWith("@", StringComparison.Ordinal)) return value;
        if (sharedConfiguration.TryGetMessage(value.Substring(1), out string? message)) return message!;
        conflicts?.Add($"Message reference '{value}' does not exist in messages.json.");
        return value;
    }

    private static string NormalizeCommentMarker(string marker) => marker.Trim().TrimStart('/', '*').TrimEnd('/', '*').Trim();
}

internal sealed class NullabilityExemptionPolicy
{
    public NullabilityExemptionPolicy(string? typeAssignedTo, string? methodName, string? methodNamePrefix, string justification, bool asDefaultArg, bool asReturned, bool asOutValue, bool asNullableFirstArgument, bool asArgument)
    {
        TypeAssignedTo = typeAssignedTo;
        MethodName = methodName;
        MethodNamePrefix = methodNamePrefix;
        Justification = justification;
        AsDefaultArg = asDefaultArg;
        AsReturned = asReturned;
        AsOutValue = asOutValue;
        AsNullableFirstArgument = asNullableFirstArgument;
        AsArgument = asArgument;
    }

    public string? TypeAssignedTo { get; }
    public string? MethodName { get; }
    public string? MethodNamePrefix { get; }
    public string Justification { get; }
    public bool AsDefaultArg { get; }
    public bool AsReturned { get; }
    public bool AsOutValue { get; }
    public bool AsNullableFirstArgument { get; }
    public bool AsArgument { get; }

    public bool AllowsDefaultArgument(ITypeSymbol candidate) => AsDefaultArg && MatchesType(candidate);
    public bool AllowsReturned(IMethodSymbol method) => AsReturned && IsNullableReturn(method) && MatchesType(method.ReturnType) && MatchesMethod(method);
    public bool AllowsOutValue(ITypeSymbol valueType, IMethodSymbol method) => AsOutValue && MatchesType(valueType) && MatchesMethod(method);
    public bool AllowsNullableFirstArgument(ITypeSymbol valueType, IMethodSymbol method) => AsNullableFirstArgument && MatchesType(valueType) && MatchesMethod(method);
    public bool AllowsArgument(ITypeSymbol valueType, IMethodSymbol method) => AsArgument && MatchesType(valueType) && MatchesMethod(method);

    public bool SelectorEquals(NullabilityExemptionPolicy other) =>
        string.Equals(TypeAssignedTo, other.TypeAssignedTo, StringComparison.Ordinal) &&
        string.Equals(MethodName, other.MethodName, StringComparison.Ordinal) &&
        string.Equals(MethodNamePrefix, other.MethodNamePrefix, StringComparison.Ordinal) &&
        AsDefaultArg == other.AsDefaultArg && AsReturned == other.AsReturned && AsOutValue == other.AsOutValue &&
        AsNullableFirstArgument == other.AsNullableFirstArgument && AsArgument == other.AsArgument;

    private bool MatchesType(ITypeSymbol candidate) => string.IsNullOrWhiteSpace(TypeAssignedTo) || GlobMatches(candidate.ToDisplayString().TrimEnd('?'), TypeAssignedTo!);
    private bool MatchesMethod(IMethodSymbol candidate) =>
        (string.IsNullOrWhiteSpace(MethodName) || string.Equals(candidate.Name, MethodName, StringComparison.Ordinal)) &&
        (string.IsNullOrWhiteSpace(MethodNamePrefix) || candidate.Name.StartsWith(MethodNamePrefix, StringComparison.Ordinal));
    private static bool IsNullableReturn(IMethodSymbol method) => method.ReturnNullableAnnotation == NullableAnnotation.Annotated || method.ReturnType is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T };

    private static bool GlobMatches(string value, string pattern)
    {
        string[] parts = pattern.Split('*');
        if (parts.Length == 1) return string.Equals(value, pattern, StringComparison.Ordinal);
        int offset = 0;
        if (!pattern.StartsWith("*", StringComparison.Ordinal) && !value.StartsWith(parts[0], StringComparison.Ordinal)) return false;
        foreach (string part in parts)
        {
            if (part.Length == 0) continue;
            int foundAt = value.IndexOf(part, offset, StringComparison.Ordinal);
            if (foundAt < 0) return false;
            offset = foundAt + part.Length;
        }
        return pattern.EndsWith("*", StringComparison.Ordinal) || offset == value.Length;
    }
}
