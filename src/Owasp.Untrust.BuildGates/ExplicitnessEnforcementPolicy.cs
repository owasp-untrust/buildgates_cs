using System.Collections.Immutable;
using System.Text.Json;

namespace Owasp.Untrust.BuildGates;

internal sealed class ExplicitnessEnforcementPolicy
{
    private const string ConfigurationName = "explicitness-enforcement";

    private ExplicitnessEnforcementPolicy(bool requireObviousVarType, ImmutableArray<string> conflicts)
    {
        RequireObviousVarType = requireObviousVarType;
        ConfigurationConflicts = conflicts;
    }

    public bool RequireObviousVarType { get; }
    public ImmutableArray<string> ConfigurationConflicts { get; }

    public static ExplicitnessEnforcementPolicy Load(SharedBuildGateConfiguration shared)
    {
        bool obviousVar = true;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var conflicts = ImmutableArray.CreateBuilder<string>();
        foreach (BuildGateConfigurationDocument document in shared.GetDocuments(ConfigurationName))
        {
            if (!BuildGateJson.TryParseObject(document.Text.ToString(), document.Path, conflicts.Add, out JsonDocument? json)) continue;
            using (json!)
            {
                JsonElement root = json!.RootElement;
                MergeBoolean(root, "requireObviousVarType", document.Path, values, conflicts, value => obviousVar = value);
            }
        }
        return new ExplicitnessEnforcementPolicy(obviousVar, conflicts.ToImmutable());
    }

    private static void MergeBoolean(JsonElement root, string name, string path, Dictionary<string, string> values, ImmutableArray<string>.Builder conflicts, Action<bool> setValue)
    {
        if (BuildGateJson.GetBoolean(root, name) is bool value)
        {
            string serialized = value ? "true" : "false";
            if (values.TryGetValue(name, out string? existing))
            {
                if (!string.Equals(existing, serialized, StringComparison.Ordinal)) conflicts.Add($"'{name}' has incompatible values; '{path}' cannot override a parent or earlier configuration.");
                return;
            }
            values.Add(name, serialized);
            setValue(value);
        }
    }
}
