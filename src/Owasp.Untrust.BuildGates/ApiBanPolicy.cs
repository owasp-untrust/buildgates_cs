using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

internal sealed class ApiBanPolicy
{
    private const string ConfigurationName = "forbidden-methods";
    internal static readonly DiagnosticDescriptor ForbiddenMethodRule = new(
        BuildGateDiagnosticIds.ForbiddenMethod, "Forbidden API", "Call to '{0}' is forbidden: {1}", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private ApiBanPolicy(ImmutableArray<ForbiddenMethodPolicy> methods, ImmutableArray<ForbiddenTypePolicy> types, ImmutableArray<ForbiddenImportPolicy> imports, ImmutableArray<string> conflicts)
    {
        ForbiddenMethods = methods;
        ForbiddenTypes = types;
        ForbiddenImports = imports;
        ConfigurationConflicts = conflicts;
    }

    public ImmutableArray<ForbiddenMethodPolicy> ForbiddenMethods { get; }
    public ImmutableArray<ForbiddenTypePolicy> ForbiddenTypes { get; }
    public ImmutableArray<ForbiddenImportPolicy> ForbiddenImports { get; }
    public ImmutableArray<string> ConfigurationConflicts { get; }

    public static ApiBanPolicy Load(SharedBuildGateConfiguration shared, ImmutableArray<AdditionalText> additionalFiles)
    {
        var methods = ImmutableArray.CreateBuilder<ForbiddenMethodPolicy>();
        var types = ImmutableArray.CreateBuilder<ForbiddenTypePolicy>();
        var imports = ImmutableArray.CreateBuilder<ForbiddenImportPolicy>();
        var conflicts = ImmutableArray.CreateBuilder<string>();
        Dictionary<string, string> restoredPackages = ReadRestoredPackages(additionalFiles, conflicts);
        foreach (BuildGateConfigurationDocument document in shared.GetDocuments(ConfigurationName))
        {
            if (!BuildGateJson.TryParseObject(document.Text.ToString(), document.Path, conflicts.Add, out JsonDocument? json)) continue;
            using (json!)
            {
                JsonElement root = json!.RootElement;
                methods.AddRange(ReadMethods(root, shared, restoredPackages));
                types.AddRange(ReadNames(root, "forbiddenTypes", shared, restoredPackages).Select(rule => new ForbiddenTypePolicy(rule.Name, rule.Guidance)));
                imports.AddRange(ReadNames(root, "forbiddenImports", shared, restoredPackages).Select(rule => new ForbiddenImportPolicy(rule.Name, rule.Guidance)));
            }
        }
        return new ApiBanPolicy(methods.ToImmutable(), types.ToImmutable(), imports.ToImmutable(), conflicts.ToImmutable());
    }

    private static ImmutableArray<ForbiddenMethodPolicy> ReadMethods(JsonElement root, SharedBuildGateConfiguration shared, Dictionary<string, string> restoredPackages)
    {
        if (!root.TryGetProperty("forbiddenMethods", out JsonElement rules) || rules.ValueKind != JsonValueKind.Array) return ImmutableArray<ForbiddenMethodPolicy>.Empty;
        var result = ImmutableArray.CreateBuilder<ForbiddenMethodPolicy>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? type = BuildGateJson.GetString(rule, "containingType");
            string? method = BuildGateJson.GetString(rule, "method");
            string guidance = ReadGuidance(rule, shared, restoredPackages);
            if (!string.IsNullOrWhiteSpace(type) && !string.IsNullOrWhiteSpace(method) && !string.IsNullOrWhiteSpace(guidance)) result.Add(new ForbiddenMethodPolicy(type!, method!, guidance, rule.TryGetProperty("includeSubclasses", out JsonElement include) && include.ValueKind == JsonValueKind.True));
        }
        return result.ToImmutable();
    }

    private static ImmutableArray<(string Name, string Guidance)> ReadNames(JsonElement root, string propertyName, SharedBuildGateConfiguration shared, Dictionary<string, string> restoredPackages)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement rules) || rules.ValueKind != JsonValueKind.Array) return ImmutableArray<(string Name, string Guidance)>.Empty;
        var result = ImmutableArray.CreateBuilder<(string Name, string Guidance)>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? name = BuildGateJson.GetString(rule, "name");
            string guidance = ReadGuidance(rule, shared, restoredPackages);
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(guidance)) result.Add((name!, guidance));
        }
        return result.ToImmutable();
    }

    private static string ReadGuidance(JsonElement rule, SharedBuildGateConfiguration shared, Dictionary<string, string> restoredPackages)
    {
        var guidance = new List<string>();
        foreach (string propertyName in new[] { "message", "alternative" })
        {
            if (BuildGateJson.GetString(rule, propertyName) is string value)
            {
                string resolved = value.StartsWith("@", StringComparison.Ordinal) && shared.TryGetMessage(value.Substring(1), out string? message) ? message! : value;
                guidance.Add(propertyName == "alternative" ? $"Use {resolved} instead." : resolved);
            }
        }
        string? nugget = BuildGateJson.GetString(rule, "nugget");
        string? nuggetVersion = BuildGateJson.GetString(rule, "nuggetVersion");
        if (!string.IsNullOrWhiteSpace(nugget))
        {
            if (!restoredPackages.TryGetValue(nugget!, out string? installedVersion)) guidance.Add($"Install NuGet package '{nugget}'{(string.IsNullOrWhiteSpace(nuggetVersion) ? "." : $" version '{nuggetVersion}'.")}");
            else if (!string.IsNullOrWhiteSpace(nuggetVersion) && !string.Equals(installedVersion, nuggetVersion, StringComparison.Ordinal)) guidance.Add($"Update NuGet package '{nugget}' from version '{installedVersion}' to version '{nuggetVersion}'.");
        }
        return string.Join(" ", guidance);
    }

    private static Dictionary<string, string> ReadRestoredPackages(ImmutableArray<AdditionalText> additionalFiles, ImmutableArray<string>.Builder conflicts)
    {
        var packages = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (AdditionalText file in additionalFiles.Where(file => string.Equals(Path.GetFileName(file.Path), "project.assets.json", StringComparison.OrdinalIgnoreCase)))
        {
            try
            {
                using JsonDocument document = JsonDocument.Parse(file.GetText()?.ToString() ?? string.Empty);
                if (!document.RootElement.TryGetProperty("libraries", out JsonElement libraries) || libraries.ValueKind != JsonValueKind.Object) continue;
                foreach (JsonProperty library in libraries.EnumerateObject())
                {
                    int separator = library.Name.LastIndexOf('/');
                    if (separator > 0 && separator < library.Name.Length - 1) packages[library.Name.Substring(0, separator)] = library.Name.Substring(separator + 1);
                }
            }
            catch (JsonException exception) { conflicts.Add($"Could not parse restored package graph '{file.Path}': {exception.Message}"); }
        }
        return packages;
    }
}

internal sealed class ForbiddenMethodPolicy
{
    public ForbiddenMethodPolicy(string containingType, string method, string guidance, bool includeSubclasses)
    {
        ContainingType = containingType;
        Method = method;
        Guidance = guidance;
        IncludeSubclasses = includeSubclasses;
    }

    public string ContainingType { get; }
    public string Method { get; }
    public string Guidance { get; }
    public bool IncludeSubclasses { get; }
    public bool Matches(IMethodSymbol candidate) => string.Equals(candidate.Name, Method, StringComparison.Ordinal) && MatchesType(candidate.ContainingType);
    public bool Matches(ISymbol candidate) => string.Equals(candidate.Name, Method, StringComparison.Ordinal) && MatchesType(candidate.ContainingType);

    private bool MatchesType(INamedTypeSymbol? candidate)
    {
        for (INamedTypeSymbol? current = candidate; current is not null; current = IncludeSubclasses ? current.BaseType : null)
        {
            if (string.Equals(current.ToDisplayString(), ContainingType, StringComparison.Ordinal)) return true;
            if (!IncludeSubclasses) return false;
        }
        return IncludeSubclasses && candidate?.AllInterfaces.Any(@interface => string.Equals(@interface.ToDisplayString(), ContainingType, StringComparison.Ordinal)) is true;
    }
}

internal sealed class ForbiddenTypePolicy
{
    public ForbiddenTypePolicy(string name, string guidance) { Name = name; Guidance = guidance; }
    public string Name { get; }
    public string Guidance { get; }
    public bool Matches(INamedTypeSymbol type) => string.Equals(type.ToDisplayString(), Name, StringComparison.Ordinal);
}

internal sealed class ForbiddenImportPolicy
{
    public ForbiddenImportPolicy(string name, string guidance) { Name = name; Guidance = guidance; }
    public string Name { get; }
    public string Guidance { get; }
    public bool Matches(string importedNamespace) => string.Equals(importedNamespace, Name, StringComparison.Ordinal);
}
