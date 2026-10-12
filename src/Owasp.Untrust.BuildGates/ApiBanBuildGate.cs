using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using System.Collections.Immutable;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ApiBanBuildGateAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(
        BuildGateDiagnosticIds.ConfigurationConflict, "BuildGate configuration error", "BuildGate configuration error: {0}", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(ApiBanPolicy.ForbiddenMethodRule, ConfigurationConflictRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(startContext =>
        {
            startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? directory);
            if (string.IsNullOrWhiteSpace(directory)) startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out directory);
            SharedBuildGateConfiguration shared = SharedBuildGateConfigurationProvider.Get(startContext.Compilation, startContext.Options.AdditionalFiles, directory);
            ApiBanPolicy policy = ApiBanPolicy.Load(shared, startContext.Options.AdditionalFiles);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeInvocation(nodeContext, policy), SyntaxKind.InvocationExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeForbiddenMemberAccess(nodeContext, policy), SyntaxKind.SimpleMemberAccessExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeForbiddenTypeUse(nodeContext, policy), SyntaxKind.IdentifierName);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeForbiddenImport(nodeContext, policy), SyntaxKind.UsingDirective);
            startContext.RegisterCompilationEndAction(endContext => { foreach (string conflict in policy.ConfigurationConflicts) endContext.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, conflict)); });
        });
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context, ApiBanPolicy policy)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;
        if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method || policy.ForbiddenMethods.FirstOrDefault(rule => rule.Matches(method)) is not ForbiddenMethodPolicy match)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(ApiBanPolicy.ForbiddenMethodRule, invocation.GetLocation(), method.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat), match.Guidance));
    }

    private static void AnalyzeForbiddenMemberAccess(SyntaxNodeAnalysisContext context, ApiBanPolicy policy)
    {
        if (context.Node is MemberAccessExpressionSyntax memberAccess && context.SemanticModel.GetSymbolInfo(memberAccess, context.CancellationToken).Symbol is ISymbol member && member is not IMethodSymbol && policy.ForbiddenMethods.FirstOrDefault(rule => rule.Matches(member)) is ForbiddenMethodPolicy match)
        {
            context.ReportDiagnostic(Diagnostic.Create(ApiBanPolicy.ForbiddenMethodRule, memberAccess.GetLocation(), member.ToDisplayString(), match.Guidance));
        }
    }

    private static void AnalyzeForbiddenTypeUse(SyntaxNodeAnalysisContext context, ApiBanPolicy policy)
    {
        if (context.Node is IdentifierNameSyntax identifier && context.SemanticModel.GetSymbolInfo(identifier, context.CancellationToken).Symbol is INamedTypeSymbol type && policy.ForbiddenTypes.FirstOrDefault(rule => rule.Matches(type)) is ForbiddenTypePolicy match)
        {
            context.ReportDiagnostic(Diagnostic.Create(ApiBanPolicy.ForbiddenMethodRule, identifier.GetLocation(), type.ToDisplayString(), match.Guidance));
        }
    }

    private static void AnalyzeForbiddenImport(SyntaxNodeAnalysisContext context, ApiBanPolicy policy)
    {
        if (context.Node is UsingDirectiveSyntax { Name: not null } usingDirective && policy.ForbiddenImports.FirstOrDefault(rule => rule.Matches(usingDirective.Name.ToString())) is ForbiddenImportPolicy match)
        {
            context.ReportDiagnostic(Diagnostic.Create(ApiBanPolicy.ForbiddenMethodRule, usingDirective.Name.GetLocation(), usingDirective.Name.ToString(), match.Guidance));
        }
    }
}
