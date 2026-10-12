using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Owasp.Untrust.BuildGates.Helpers;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CodeStyleBuildGateAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor MemberPrefixRule = new(
        BuildGateDiagnosticIds.MemberPrefix, "Member field does not follow the required naming policy",
        "Member field '{0}' must start with '{1}'", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(
        BuildGateDiagnosticIds.ConfigurationConflict, "BuildGate configuration error",
        "BuildGate configuration error: {0}", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ControlFlowBlockRule = new(
        BuildGateDiagnosticIds.ControlFlowBlock, "Control-flow bodies require blocks",
        "{0} body must use curly braces and a block, even when it contains one statement.", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor PublicClassFileRule = new(
        BuildGateDiagnosticIds.PublicClassFile, "Public classes have dedicated files",
        "Source file '{0}' must contain one public top-level class named '{1}', unless it groups a complete class or interface hierarchy headed by that type.", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor BooleanLiteralComparisonRule = new(
        BuildGateDiagnosticIds.BooleanLiteralComparison, "Boolean values must not be compared with literals",
        "Do not compare a Boolean value to '{0}'. Use the Boolean expression directly or negate it. For example, replace 'User.Identity?.IsAuthenticated == true' with 'User.Identity is { IsAuthenticated: true } identity'.", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ConstantFieldCapitalizationRule = new(
        BuildGateDiagnosticIds.ConstantFieldCapitalization, "Constant fields use upper-case names",
        "Constant field '{0}' must use an upper-case name.", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor LockKeywordRule = new(
        BuildGateDiagnosticIds.LockKeyword, "Lock does not provide distributed coordination",
        "The 'lock' keyword coordinates only threads in one process and is forbidden in distributed systems. Use a distributed coordination mechanism. Escape only with an immediately preceding '//' or one-line '/* */' comment starting 'untrust-allow-local-threads-lock' and a minimum 100-character explanation of why this local lock remains effective in the distributed system.", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor StaticVirtualInterfaceMemberRule = new(
        BuildGateDiagnosticIds.StaticVirtualInterfaceMember, "Static virtual interface members require a security justification",
        "Static virtual interface member '{0}' supplies a default that can let implementers omit value constraints. Use static abstract instead, unless an immediately preceding '//' or one-line '/* */' comment starting 'untrust-static-virtual-is-safe:' explains why the default cannot weaken security or cause an overlooked override (minimum {1} characters). A valid exception is when an override is required to pass an enforced validation whose failure is visible to the developer.",
        "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor IsMethodContractRule = new(
        BuildGateDiagnosticIds.IsMethodContract, "Is methods are predicate-only",
        "Method '{0}' starts with 'Is' and must return bool without any out parameters. Use TryXxx naming semantics instead for operations that produce output, for example: TryExtract..., TryConvert..., or TryParse.... When an out value is null on a false result, declare the TryParse-style [MaybeNullWhen(false)] contract.",
        "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor TryMethodOutContractRule = new(
        BuildGateDiagnosticIds.TryMethodOutContract, "Try methods accurately document out nullability",
        "Method '{0}' starts with 'Try' and out parameter '{1}' {2}", "OWASP Untrust", DiagnosticSeverity.Error, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => ImmutableArray.Create(
        MemberPrefixRule, ConfigurationConflictRule, ControlFlowBlockRule, PublicClassFileRule,
        BooleanLiteralComparisonRule, ConstantFieldCapitalizationRule, StaticVirtualInterfaceMemberRule,
        IsMethodContractRule, TryMethodOutContractRule, LockKeywordRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterCompilationStartAction(startContext =>
        {
            startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? directory);
            if (string.IsNullOrWhiteSpace(directory))
            {
                startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out directory);
            }

            SharedBuildGateConfiguration shared = SharedBuildGateConfigurationProvider.Get(startContext.Compilation, startContext.Options.AdditionalFiles, directory);
            CodeStylePolicy policy = CodeStylePolicy.Load(shared);
            var publicClasses = new PublicClassesPerFileInfoCollector();
            startContext.RegisterCompilationEndAction(endContext =>
            {
                foreach (string conflict in policy.ConfigurationConflicts)
                {
                    endContext.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, conflict));
                }

                PublicClassesPerFileEvaluator.Evaluate(endContext, policy, publicClasses, PublicClassFileRule);
            });
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeField(nodeContext, policy), SyntaxKind.VariableDeclarator);
            startContext.RegisterSyntaxNodeAction(publicClasses.Collect,
                SyntaxKind.ClassDeclaration, SyntaxKind.InterfaceDeclaration,
                SyntaxKind.RecordDeclaration, SyntaxKind.RecordStructDeclaration);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeControlFlowBlock(nodeContext, policy),
                SyntaxKind.IfStatement, SyntaxKind.ForStatement, SyntaxKind.ForEachStatement,
                SyntaxKind.ForEachVariableStatement, SyntaxKind.WhileStatement, SyntaxKind.DoStatement,
                SyntaxKind.UsingStatement, SyntaxKind.LockStatement, SyntaxKind.FixedStatement);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeBooleanLiteralComparison(nodeContext, policy),
                SyntaxKind.EqualsExpression, SyntaxKind.NotEqualsExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeLockKeyword(nodeContext, policy), SyntaxKind.LockStatement);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => MethodCodeStyleChecker.AnalyzeIsMethodContract(nodeContext, policy.EnforceIsMethodContract, IsMethodContractRule),
                SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => MethodCodeStyleChecker.AnalyzeTryMethodOutContract(nodeContext, policy.EnforceTryMethodOutContract, TryMethodOutContractRule),
                SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => ClassCodeStyleChecker.AnalyzeStaticVirtualInterfaceMember(nodeContext, policy, StaticVirtualInterfaceMemberRule),
                SyntaxKind.MethodDeclaration, SyntaxKind.PropertyDeclaration, SyntaxKind.IndexerDeclaration,
                SyntaxKind.EventDeclaration);
        });
    }

    private static void AnalyzeField(SyntaxNodeAnalysisContext context, CodeStylePolicy policy)
    {
        var variable = (VariableDeclaratorSyntax)context.Node;
        if (variable.Parent?.Parent is not FieldDeclarationSyntax field) return;
        bool isConst = field.Modifiers.Any(SyntaxKind.ConstKeyword);
        bool isStaticReadOnly = IsStaticReadOnlyField(field);
        if (!string.IsNullOrEmpty(policy.MemberPrefix) &&
            !((isConst || isStaticReadOnly) && policy.ConstFieldsExemptMemberPrefix) &&
            !variable.Identifier.ValueText.StartsWith(policy.MemberPrefix, StringComparison.Ordinal))
        {
            context.ReportDiagnostic(Diagnostic.Create(MemberPrefixRule, variable.Identifier.GetLocation(), variable.Identifier.ValueText, policy.MemberPrefix));
        }
        if (policy.ConstantsInUpperCase && IsConstantLikeField(field, variable) && !IsUpperCaseName(variable.Identifier.ValueText))
        {
            context.ReportDiagnostic(Diagnostic.Create(ConstantFieldCapitalizationRule, variable.Identifier.GetLocation(), variable.Identifier.ValueText));
        }
    }

    private static bool IsConstantLikeField(FieldDeclarationSyntax field, VariableDeclaratorSyntax variable) =>
        field.Modifiers.Any(SyntaxKind.ConstKeyword) ||
        IsStaticReadOnlyField(field) && variable.Initializer is { Value: var initializer } && (IsLiteral(initializer) || IsLiteralDerivedHardcoded(initializer));

    private static bool IsStaticReadOnlyField(FieldDeclarationSyntax field) =>
        field.Modifiers.Any(SyntaxKind.StaticKeyword) && field.Modifiers.Any(SyntaxKind.ReadOnlyKeyword);

    private static bool IsLiteralDerivedHardcoded(ExpressionSyntax expression)
    {
        ExpressionSyntax value = expression is ParenthesizedExpressionSyntax parenthesized ? parenthesized.Expression : expression;
        SeparatedSyntaxList<ArgumentSyntax> arguments = value switch
        {
            ObjectCreationExpressionSyntax { Type: IdentifierNameSyntax { Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var objectArguments } } => objectArguments,
            InvocationExpressionSyntax { Expression: IdentifierNameSyntax { Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var invocationArguments } } => invocationArguments,
            InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var memberInvocationArguments } } => memberInvocationArguments,
            _ => default
        };
        return arguments.Count > 0 && arguments.All(argument => IsLiteral(argument.Expression));
    }

    private static bool IsLiteral(ExpressionSyntax expression) => expression is LiteralExpressionSyntax || expression is ParenthesizedExpressionSyntax { Expression: LiteralExpressionSyntax };
    private static bool IsUpperCaseName(string name) => name.Any(char.IsLetter) && name.All(character => !char.IsLetter(character) || char.IsUpper(character));

    private static void AnalyzeControlFlowBlock(SyntaxNodeAnalysisContext context, CodeStylePolicy policy)
    {
        StatementSyntax? statement = GetControlledStatement(context.Node);
        if (!policy.RequireBlocksForControlFlow || statement is null || statement is BlockSyntax || statement.IsKind(SyntaxKind.EmptyStatement)) return;
        context.ReportDiagnostic(Diagnostic.Create(ControlFlowBlockRule, statement.GetLocation(), GetControlFlowName(context.Node)));
    }

    private static void AnalyzeBooleanLiteralComparison(SyntaxNodeAnalysisContext context, CodeStylePolicy policy)
    {
        if (!policy.BanComparingBoolValueToLiteral || context.Node is not BinaryExpressionSyntax comparison) return;
        LiteralExpressionSyntax? literal = comparison.Left is LiteralExpressionSyntax left && IsBooleanLiteral(left) ? left : comparison.Right is LiteralExpressionSyntax right && IsBooleanLiteral(right) ? right : null;
        if (literal is not null) context.ReportDiagnostic(Diagnostic.Create(BooleanLiteralComparisonRule, comparison.GetLocation(), literal.Token.ValueText));
    }

    private static void AnalyzeLockKeyword(SyntaxNodeAnalysisContext context, CodeStylePolicy policy)
    {
        var lockStatement = (LockStatementSyntax)context.Node;
        if (!policy.ForbidLockKeyword || HasLocalThreadsLockJustification(lockStatement)) return;
        context.ReportDiagnostic(Diagnostic.Create(LockKeywordRule, lockStatement.LockKeyword.GetLocation()));
    }

    private static bool HasLocalThreadsLockJustification(LockStatementSyntax lockStatement)
    {
        FileLinePositionSpan span = lockStatement.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0) return false;
        SourceText source = lockStatement.SyntaxTree.GetText();
        return SharedHelpers.HasCommentWithMarker(source.Lines[span.StartLinePosition.Line - 1].ToString().Trim(), "untrust-allow-local-threads-lock", 100);
    }

    private static bool IsBooleanLiteral(LiteralExpressionSyntax expression) => expression.IsKind(SyntaxKind.TrueLiteralExpression) || expression.IsKind(SyntaxKind.FalseLiteralExpression);
    private static StatementSyntax? GetControlledStatement(SyntaxNode node) => node switch
    {
        IfStatementSyntax @if => @if.Statement, ForStatementSyntax @for => @for.Statement,
        ForEachStatementSyntax each => each.Statement, ForEachVariableStatementSyntax eachVariable => eachVariable.Statement,
        WhileStatementSyntax @while => @while.Statement, DoStatementSyntax @do => @do.Statement,
        UsingStatementSyntax @using => @using.Statement, LockStatementSyntax @lock => @lock.Statement,
        FixedStatementSyntax fixedStatement => fixedStatement.Statement, _ => null
    };
    private static string GetControlFlowName(SyntaxNode node) => node.Kind() switch
    {
        SyntaxKind.IfStatement => "if", SyntaxKind.ForStatement => "for",
        SyntaxKind.ForEachStatement or SyntaxKind.ForEachVariableStatement => "foreach",
        SyntaxKind.WhileStatement => "while", SyntaxKind.DoStatement => "do",
        SyntaxKind.UsingStatement => "using", SyntaxKind.LockStatement => "lock",
        SyntaxKind.FixedStatement => "fixed", _ => "control-flow"
    };
}
