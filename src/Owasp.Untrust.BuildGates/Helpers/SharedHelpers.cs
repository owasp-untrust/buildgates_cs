using System.Collections.Immutable;
using Microsoft.CodeAnalysis;

namespace Owasp.Untrust.BuildGates;

internal static class SharedHelpers
{
    public static AdditionalText? FindAdditionalFile(ImmutableArray<AdditionalText> additionalFiles, string fileName) =>
        additionalFiles.FirstOrDefault(file => string.Equals(Path.GetFileName(file.Path), fileName, StringComparison.OrdinalIgnoreCase));

    public static AdditionalText? FindAdditionalFileAtPath(ImmutableArray<AdditionalText> additionalFiles, string path)
    {
        string expectedPath = Path.GetFullPath(path);
        return additionalFiles.FirstOrDefault(file => string.Equals(Path.GetFullPath(file.Path), expectedPath, StringComparison.OrdinalIgnoreCase));
    }

    public static bool DerivesFromType(INamedTypeSymbol type, string fullyQualifiedTypeName)
    {
        for (INamedTypeSymbol? current = type; current is not null; current = current.BaseType)
        {
            if (string.Equals(current.ToDisplayString(), fullyQualifiedTypeName, StringComparison.Ordinal)) return true;
        }
        return false;
    }

    public static bool HasCommentWithMarker(string comment, string marker, int minimumDescriptionCharacters)
    {
        string? content = GetCommentContent(comment);
        return content is not null && content.StartsWith(marker, StringComparison.Ordinal) && content.Substring(marker.Length).Trim().Length >= minimumDescriptionCharacters;
    }

    public static string? GetCommentContent(string comment)
    {
        string content = comment.Trim();
        if (content.StartsWith("//", StringComparison.Ordinal)) return content.Substring(2).TrimStart();
        return content.StartsWith("/*", StringComparison.Ordinal) && content.EndsWith("*/", StringComparison.Ordinal) ? content.Substring(2, content.Length - 4).Trim() : null;
    }
}
