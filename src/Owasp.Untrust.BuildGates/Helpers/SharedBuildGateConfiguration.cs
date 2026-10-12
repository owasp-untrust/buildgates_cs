using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.BuildGates;

internal sealed class SharedBuildGateConfiguration
{
    private const string ActiveConfigurationFileName = "active-buildgates.json";
    private const string MessagesFileName = "messages.json";
    private readonly ImmutableDictionary<string, ImmutableArray<BuildGateConfigurationDocument>> documentsByName;

    private SharedBuildGateConfiguration(ImmutableDictionary<string, string> messages, ImmutableDictionary<string, ImmutableArray<BuildGateConfigurationDocument>> documentsByName, ImmutableArray<string> errors)
    {
        Messages = messages;
        this.documentsByName = documentsByName;
        Errors = errors;
    }

    public ImmutableArray<string> Errors { get; }
    private ImmutableDictionary<string, string> Messages { get; }
    public bool TryGetMessage(string messageId, out string? message) => Messages.TryGetValue(messageId, out message);
    public ImmutableArray<BuildGateConfigurationDocument> GetDocuments(string configurationName) => documentsByName.TryGetValue(configurationName, out ImmutableArray<BuildGateConfigurationDocument> documents) ? documents : ImmutableArray<BuildGateConfigurationDocument>.Empty;

    public static SharedBuildGateConfiguration Load(ImmutableArray<AdditionalText> additionalFiles, string? configurationDirectory)
    {
        var errors = ImmutableArray.CreateBuilder<string>();
        ImmutableDictionary<string, string> messages = LoadMessages(additionalFiles, errors);
        var documentsByName = ImmutableDictionary.CreateBuilder<string, ImmutableArray<BuildGateConfigurationDocument>>(StringComparer.Ordinal);
        foreach (AdditionalText activeConfiguration in FindActiveConfigurations(additionalFiles, configurationDirectory)) LoadActiveConfiguration(activeConfiguration, additionalFiles, documentsByName, errors);
        return new SharedBuildGateConfiguration(messages, documentsByName.ToImmutable(), errors.ToImmutable());
    }

    private static ImmutableDictionary<string, string> LoadMessages(ImmutableArray<AdditionalText> additionalFiles, ImmutableArray<string>.Builder errors)
    {
        var messages = ImmutableDictionary.CreateBuilder<string, string>(StringComparer.Ordinal);
        foreach (AdditionalText file in additionalFiles.Where(file => string.Equals(Path.GetFileName(file.Path), MessagesFileName, StringComparison.OrdinalIgnoreCase)))
        {
            if (!BuildGateJson.TryParseObject(file.GetText()?.ToString() ?? string.Empty, file.Path, errors.Add, out JsonDocument? document)) continue;
            using (document!)
            {
                foreach (JsonProperty message in document!.RootElement.EnumerateObject())
                {
                    if (message.Value.ValueKind != JsonValueKind.Array || message.Value.EnumerateArray().Any(line => line.ValueKind != JsonValueKind.String)) { errors.Add($"Message '{message.Name}' in '{file.Path}' must be an array of strings."); continue; }
                    messages[message.Name] = string.Join(Environment.NewLine, message.Value.EnumerateArray().Select(line => line.GetString()));
                }
            }
        }
        return messages.ToImmutable();
    }

    private static ImmutableArray<AdditionalText> FindActiveConfigurations(ImmutableArray<AdditionalText> additionalFiles, string? configurationDirectory)
    {
        if (string.IsNullOrWhiteSpace(configurationDirectory))
        {
            AdditionalText? configuration = SharedHelpers.FindAdditionalFile(additionalFiles, ActiveConfigurationFileName);
            return configuration is null ? ImmutableArray<AdditionalText>.Empty : ImmutableArray.Create(configuration);
        }
        string currentDirectory = Path.GetFullPath(configurationDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var ancestors = new Stack<string>();
        for (DirectoryInfo? directory = new DirectoryInfo(currentDirectory); directory is not null; directory = directory.Parent) ancestors.Push(directory.FullName);
        var configurations = ImmutableArray.CreateBuilder<AdditionalText>();
        while (ancestors.Count > 0)
        {
            AdditionalText? configuration = SharedHelpers.FindAdditionalFileAtPath(additionalFiles, Path.Combine(ancestors.Pop(), ActiveConfigurationFileName));
            if (configuration is not null) configurations.Add(configuration);
        }
        return configurations.ToImmutable();
    }

    private static void LoadActiveConfiguration(AdditionalText activeConfiguration, ImmutableArray<AdditionalText> additionalFiles, ImmutableDictionary<string, ImmutableArray<BuildGateConfigurationDocument>>.Builder documentsByName, ImmutableArray<string>.Builder errors)
    {
        if (!BuildGateJson.TryParseObject(activeConfiguration.GetText()?.ToString() ?? string.Empty, activeConfiguration.Path, errors.Add, out JsonDocument? document)) return;
        using (document!)
        {
            foreach (JsonProperty reference in document!.RootElement.EnumerateObject())
            {
                if (reference.Value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(reference.Value.GetString())) { errors.Add($"'{activeConfiguration.Path}' entry '{reference.Name}' must name a configuration file."); continue; }
                string configurationPath = Path.Combine(Path.GetDirectoryName(activeConfiguration.Path) ?? string.Empty, reference.Value.GetString()!);
                AdditionalText? configurationFile = SharedHelpers.FindAdditionalFileAtPath(additionalFiles, configurationPath);
                if (configurationFile?.GetText() is not SourceText configurationText) { errors.Add($"'{activeConfiguration.Path}' references unreadable or missing configuration file '{configurationPath}'."); continue; }
                ImmutableArray<BuildGateConfigurationDocument> documents = documentsByName.TryGetValue(reference.Name, out ImmutableArray<BuildGateConfigurationDocument> existing) ? existing : ImmutableArray<BuildGateConfigurationDocument>.Empty;
                documentsByName[reference.Name] = documents.Add(new BuildGateConfigurationDocument(configurationFile.Path, configurationText));
            }
        }
    }
}

internal sealed class BuildGateConfigurationDocument
{
    public BuildGateConfigurationDocument(string path, SourceText text) { Path = path; Text = text; }
    public string Path { get; }
    public SourceText Text { get; }
}
