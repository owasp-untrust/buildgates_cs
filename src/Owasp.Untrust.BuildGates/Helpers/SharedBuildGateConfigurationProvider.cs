using System.Collections.Immutable;
using System.Runtime.CompilerServices;
using Microsoft.CodeAnalysis;

namespace Owasp.Untrust.BuildGates;

internal static class SharedBuildGateConfigurationProvider
{
    private static readonly ConditionalWeakTable<Compilation, Lazy<SharedBuildGateConfiguration>> configurations = new();

    public static SharedBuildGateConfiguration Get(Compilation compilation, ImmutableArray<AdditionalText> additionalFiles, string? configurationDirectory)
    {
        Lazy<SharedBuildGateConfiguration> configuration = configurations.GetValue(compilation, _ => new Lazy<SharedBuildGateConfiguration>(() => SharedBuildGateConfiguration.Load(additionalFiles, configurationDirectory), LazyThreadSafetyMode.ExecutionAndPublication));
        return configuration.Value;
    }
}
