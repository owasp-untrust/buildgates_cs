using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class SharedBuildGateConfigurationAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(
        BuildGateDiagnosticIds.ConfigurationConflict,
        "BuildGate configuration error",
        "BuildGate configuration error: {0}",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(ConfigurationConflictRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationAction(compilationContext =>
        {
            compilationContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? directory);
            if (string.IsNullOrWhiteSpace(directory)) compilationContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out directory);
            SharedBuildGateConfiguration shared = SharedBuildGateConfigurationProvider.Get(compilationContext.Compilation, compilationContext.Options.AdditionalFiles, directory);
            foreach (string error in shared.Errors) compilationContext.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, error));
        });
    }
}
