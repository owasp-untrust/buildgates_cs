using System.Collections.Immutable;
using System.Text.Json;

namespace Owasp.Untrust.BuildGates;

internal sealed class CodeStylePolicy
{
    private const string ConfigurationName = "code-style";

    private CodeStylePolicy(string memberPrefix, bool constFieldsExemptMemberPrefix, bool constantsInUpperCase, bool requireBlocksForControlFlow, bool onePublicClassPerFile, bool allowGroupingOfCompleteClassHierarchies, bool allowAttributeClassesToShareFile, bool banComparingBoolValueToLiteral, bool forbidLockKeyword, bool enforceIsMethodContract, bool enforceTryMethodOutContract, bool forbidStaticVirtualInterfaceMembers, string staticVirtualJustificationPrefix, int minimumStaticVirtualJustificationCharacters, ImmutableArray<string> configurationConflicts)
    {
        MemberPrefix = memberPrefix;
        ConstFieldsExemptMemberPrefix = constFieldsExemptMemberPrefix;
        ConstantsInUpperCase = constantsInUpperCase;
        RequireBlocksForControlFlow = requireBlocksForControlFlow;
        OnePublicClassPerFile = onePublicClassPerFile;
        AllowGroupingOfCompleteClassHierarchies = allowGroupingOfCompleteClassHierarchies;
        AllowAttributeClassesToShareFile = allowAttributeClassesToShareFile;
        BanComparingBoolValueToLiteral = banComparingBoolValueToLiteral;
        ForbidLockKeyword = forbidLockKeyword;
        EnforceIsMethodContract = enforceIsMethodContract;
        EnforceTryMethodOutContract = enforceTryMethodOutContract;
        ForbidStaticVirtualInterfaceMembers = forbidStaticVirtualInterfaceMembers;
        StaticVirtualJustificationPrefix = staticVirtualJustificationPrefix;
        MinimumStaticVirtualJustificationCharacters = minimumStaticVirtualJustificationCharacters;
        ConfigurationConflicts = configurationConflicts;
    }

    public string MemberPrefix { get; }
    public bool ConstFieldsExemptMemberPrefix { get; }
    public bool ConstantsInUpperCase { get; }
    public bool RequireBlocksForControlFlow { get; }
    public bool OnePublicClassPerFile { get; }
    public bool AllowGroupingOfCompleteClassHierarchies { get; }
    public bool AllowAttributeClassesToShareFile { get; }
    public bool BanComparingBoolValueToLiteral { get; }
    public bool ForbidLockKeyword { get; }
    public bool EnforceIsMethodContract { get; }
    public bool EnforceTryMethodOutContract { get; }
    public bool ForbidStaticVirtualInterfaceMembers { get; }
    public string StaticVirtualJustificationPrefix { get; }
    public int MinimumStaticVirtualJustificationCharacters { get; }
    public ImmutableArray<string> ConfigurationConflicts { get; }

    public static CodeStylePolicy Load(SharedBuildGateConfiguration shared)
    {
        string memberPrefix = "m_";
        bool constFieldsExemptMemberPrefix = true, constantsInUpperCase = true, requireBlocksForControlFlow = true, onePublicClassPerFile = true, allowGroupingOfCompleteClassHierarchies = true, allowAttributeClassesToShareFile = true, banComparingBoolValueToLiteral = true, forbidLockKeyword = true, enforceIsMethodContract = true, enforceTryMethodOutContract = true, forbidStaticVirtualInterfaceMembers = false;
        string staticVirtualJustificationPrefix = "untrust-static-virtual-is-safe:";
        int minimumStaticVirtualJustificationCharacters = 40;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        var conflicts = ImmutableArray.CreateBuilder<string>();
        foreach (BuildGateConfigurationDocument document in shared.GetDocuments(ConfigurationName))
        {
            if (!BuildGateJson.TryParseObject(document.Text.ToString(), document.Path, conflicts.Add, out JsonDocument? json)) continue;
            using (json!)
            {
                JsonElement root = json!.RootElement;
                MergeString(root, "memberPrefix", document.Path, values, conflicts, value => memberPrefix = value);
                MergeBoolean(root, "constFieldsExmptMemberPrefix", document.Path, values, conflicts, value => constFieldsExemptMemberPrefix = value);
                MergeBoolean(root, "konstantsInUpperCase", document.Path, values, conflicts, value => constantsInUpperCase = value);
                MergeBoolean(root, "requireBlocksForControlFlow", document.Path, values, conflicts, value => requireBlocksForControlFlow = value);
                MergeBoolean(root, "onePublicClassPerFile", document.Path, values, conflicts, value => onePublicClassPerFile = value);
                MergeBoolean(root, "allowGroupingOfCompleteClassHierarchies", document.Path, values, conflicts, value => allowGroupingOfCompleteClassHierarchies = value);
                MergeBoolean(root, "allowAttributeClassesToShareFile", document.Path, values, conflicts, value => allowAttributeClassesToShareFile = value);
                MergeBoolean(root, "banComparingBoolValueToLiteral", document.Path, values, conflicts, value => banComparingBoolValueToLiteral = value);
                MergeBoolean(root, "forbidLockKeyword", document.Path, values, conflicts, value => forbidLockKeyword = value);
                MergeBoolean(root, "enforceIsMethodContract", document.Path, values, conflicts, value => enforceIsMethodContract = value);
                MergeBoolean(root, "enforceTryMethodOutContract", document.Path, values, conflicts, value => enforceTryMethodOutContract = value);
                MergeBoolean(root, "forbidStaticVirtualInterfaceMembers", document.Path, values, conflicts, value => forbidStaticVirtualInterfaceMembers = value);
                MergeString(root, "staticVirtualJustificationPrefix", document.Path, values, conflicts, value => staticVirtualJustificationPrefix = value);
                BuildGateJson.MergePositiveInteger(root, "minimumStaticVirtualJustificationCharacters", (name, value, apply) => Merge(name, value, document.Path, values, conflicts, apply), value => minimumStaticVirtualJustificationCharacters = value);
            }
        }
        return new CodeStylePolicy(memberPrefix, constFieldsExemptMemberPrefix, constantsInUpperCase, requireBlocksForControlFlow, onePublicClassPerFile, allowGroupingOfCompleteClassHierarchies, allowAttributeClassesToShareFile, banComparingBoolValueToLiteral, forbidLockKeyword, enforceIsMethodContract, enforceTryMethodOutContract, forbidStaticVirtualInterfaceMembers, staticVirtualJustificationPrefix, minimumStaticVirtualJustificationCharacters, conflicts.ToImmutable());
    }

    private static void MergeString(JsonElement root, string name, string path, Dictionary<string, string> values, ImmutableArray<string>.Builder conflicts, Action<string> setValue)
    {
        if (BuildGateJson.GetString(root, name) is string value) Merge(name, JsonSerializer.Serialize(value), path, values, conflicts, () => setValue(value));
    }

    private static void MergeBoolean(JsonElement root, string name, string path, Dictionary<string, string> values, ImmutableArray<string>.Builder conflicts, Action<bool> setValue)
    {
        if (BuildGateJson.GetBoolean(root, name) is bool value) Merge(name, value ? "true" : "false", path, values, conflicts, () => setValue(value));
    }

    private static void Merge(string name, string value, string path, Dictionary<string, string> values, ImmutableArray<string>.Builder conflicts, Action setValue)
    {
        if (values.TryGetValue(name, out string? existing))
        {
            if (!string.Equals(existing, value, StringComparison.Ordinal)) conflicts.Add($"'{name}' has incompatible values; '{path}' cannot override a parent or earlier configuration.");
            return;
        }
        values.Add(name, value);
        setValue();
    }
}
