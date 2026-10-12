using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ExplicitnessEnforcementBuildGateAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(BuildGateDiagnosticIds.ConfigurationConflict, "BuildGate configuration error", "BuildGate configuration error: {0}", "OWASP Untrust", DiagnosticSeverity.Error, true);
    private static readonly DiagnosticDescriptor VarTypeRule = new(BuildGateDiagnosticIds.VarTypeObviousness, "Var requires an obvious type", "'var' is allowed only when its type is obvious from the right-hand side: an explicit object creation, literal, or explicit cast. Use an explicit type for values returned by methods, properties, target-typed creation, or other inferred expressions.", "OWASP Untrust", DiagnosticSeverity.Error, true);
    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(ConfigurationConflictRule, VarTypeRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(start =>
        {
            start.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? directory);
            if (string.IsNullOrWhiteSpace(directory)) start.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out directory);
            ExplicitnessEnforcementPolicy policy = ExplicitnessEnforcementPolicy.Load(SharedBuildGateConfigurationProvider.Get(start.Compilation, start.Options.AdditionalFiles, directory));
            start.RegisterCompilationEndAction(end => { foreach (string conflict in policy.ConfigurationConflicts) end.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, conflict)); });
            start.RegisterSyntaxNodeAction(node => AnalyzeVarDeclaration(node, policy), SyntaxKind.VariableDeclaration);
            start.RegisterSyntaxNodeAction(node => AnalyzeDeclarationExpression(node, policy), SyntaxKind.DeclarationExpression);
            start.RegisterSyntaxNodeAction(node => AnalyzeForeachVar(node, policy), SyntaxKind.ForEachStatement, SyntaxKind.ForEachVariableStatement);
        });
    }

    private static void AnalyzeVarDeclaration(SyntaxNodeAnalysisContext context, ExplicitnessEnforcementPolicy policy)
    {
        var declaration = (VariableDeclarationSyntax)context.Node;
        if (policy.RequireObviousVarType && IsVar(declaration.Type) && declaration.Variables.Any(variable => variable.Initializer is not { Value: var value } || !HasObviousType(value, context.SemanticModel, context.CancellationToken))) context.ReportDiagnostic(Diagnostic.Create(VarTypeRule, declaration.Type.GetLocation()));
    }
    private static void AnalyzeDeclarationExpression(SyntaxNodeAnalysisContext context, ExplicitnessEnforcementPolicy policy)
    {
        var declaration = (DeclarationExpressionSyntax)context.Node;
        if (policy.RequireObviousVarType && IsVar(declaration.Type) && !IsSelfReturningTryParse(declaration, context.SemanticModel, context.CancellationToken)) context.ReportDiagnostic(Diagnostic.Create(VarTypeRule, declaration.Type.GetLocation()));
    }
    private static void AnalyzeForeachVar(SyntaxNodeAnalysisContext context, ExplicitnessEnforcementPolicy policy)
    {
        if (!policy.RequireObviousVarType) return;
        TypeSyntax? type = context.Node switch { ForEachStatementSyntax each => each.Type, ForEachVariableStatementSyntax { Variable: DeclarationExpressionSyntax declaration } => declaration.Type, _ => null };
        if (type is not null && IsVar(type)) context.ReportDiagnostic(Diagnostic.Create(VarTypeRule, type.GetLocation()));
    }
    private static bool IsVar(TypeSyntax type) => type is IdentifierNameSyntax identifier && identifier.Identifier.ValueText == "var";
    private static bool HasObviousType(ExpressionSyntax expression, SemanticModel model, CancellationToken token)
    {
        ExpressionSyntax value = expression is ParenthesizedExpressionSyntax parenthesized ? parenthesized.Expression : expression;
        return value is ObjectCreationExpressionSyntax or AnonymousObjectCreationExpressionSyntax or ArrayCreationExpressionSyntax or ImplicitArrayCreationExpressionSyntax or LiteralExpressionSyntax or CastExpressionSyntax or DefaultExpressionSyntax or TypeOfExpressionSyntax || IsSelfReturningParse(value, model, token);
    }
    private static bool IsSelfReturningParse(ExpressionSyntax expression, SemanticModel model, CancellationToken token) => expression is InvocationExpressionSyntax invocation && model.GetSymbolInfo(invocation, token).Symbol is IMethodSymbol { IsStatic: true, Name: "Parse" or "ParseValue", ContainingType: INamedTypeSymbol type } method && SymbolEqualityComparer.Default.Equals(method.ReturnType, type);
    private static bool IsSelfReturningTryParse(DeclarationExpressionSyntax declaration, SemanticModel model, CancellationToken token)
    {
        if (declaration.Parent is not ArgumentSyntax { RefKindKeyword.RawKind: (int)SyntaxKind.OutKeyword } argument || argument.Parent is not BaseArgumentListSyntax arguments || arguments.Parent is not InvocationExpressionSyntax invocation || invocation.Expression is not MemberAccessExpressionSyntax access || model.GetSymbolInfo(invocation, token).Symbol is not IMethodSymbol { IsStatic: true, Name: "TryParse", ReturnType.SpecialType: SpecialType.System_Boolean } method) return false;
        int index = arguments.Arguments.IndexOf(argument);
        return index >= 0 && index < method.Parameters.Length && method.Parameters[index].RefKind == RefKind.Out && model.GetTypeInfo(access.Expression, token).Type is ITypeSymbol receiver && SymbolEqualityComparer.Default.Equals(method.Parameters[index].Type, receiver);
    }

}
