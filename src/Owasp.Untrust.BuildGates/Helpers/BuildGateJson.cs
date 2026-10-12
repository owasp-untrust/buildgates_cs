using System.Text.Json;

namespace Owasp.Untrust.BuildGates;

internal static class BuildGateJson
{
    public static bool TryParseObject(string json, string sourcePath, Action<string> reportError, out JsonDocument? document)
    {
        try
        {
            document = JsonDocument.Parse(json);
            if (document.RootElement.ValueKind == JsonValueKind.Object) return true;
            document.Dispose();
            document = null;
            reportError($"'{sourcePath}' must contain a JSON object.");
            return false;
        }
        catch (JsonException exception)
        {
            document = null;
            reportError($"Could not parse '{sourcePath}': {exception.Message}");
            return false;
        }
    }

    public static string? GetString(JsonElement objectElement, string propertyName) =>
        objectElement.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    public static int? GetPositiveInteger(JsonElement objectElement, string propertyName) =>
        objectElement.TryGetProperty(propertyName, out JsonElement value) && value.TryGetInt32(out int number) && number > 0 ? number : null;
    public static bool? GetBoolean(JsonElement objectElement, string propertyName) =>
        objectElement.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind is JsonValueKind.True or JsonValueKind.False ? value.GetBoolean() : null;

    public static void MergePositiveInteger(JsonElement root, string propertyName, Action<string, string, Action> mergeScalar, Action<int> setValue)
    {
        if (GetPositiveInteger(root, propertyName) is int value)
        {
            mergeScalar(propertyName, value.ToString(System.Globalization.CultureInfo.InvariantCulture), () => setValue(value));
        }
    }
}
