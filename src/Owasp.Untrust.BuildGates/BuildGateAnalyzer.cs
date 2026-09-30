using System.Collections.Immutable;
using System.Text.Json;
using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.BuildGates;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class BuildGateAnalyzer : DiagnosticAnalyzer
{
    public const string NullLiteralId = "UBG001";
    public const string MemberPrefixId = "UBG002";
    public const string ForbiddenMethodId = "UBG003";
    public const string StaticVirtualInterfaceMemberId = "UBG004";
    public const string IsMethodContractId = "UBG005";
    public const string TryMethodOutContractId = "UBG006";
    public const string NullableFirstArgumentId = "UBG007";
    public const string ConfigurationConflictId = "UBG008";
    public const string ControlFlowBlockId = "UBG009";
    public const string PublicClassFileId = "UBG010";
    public const string BooleanLiteralComparisonId = "UBG011";
    public const string LockKeywordId = "UBG012";
    public const string HttpRequestBodyAccessId = "UBG013";
    public const string VarTypeObviousnessId = "UBG014";
    public const string ControllerValidatedArgumentsId = "UBG015";
    public const string DenyByDefaultRouteAuthorizationId = "UBG016";
    public const string ExplicitRouteAuthorizationId = "UBG017";
    public const string ConstantFieldCapitalizationId = "UBG018";

    private static readonly DiagnosticDescriptor NullLiteralRule = new(
        NullLiteralId,
        "Null requires a reviewed justification",
        "Null literal requires either a preceding '//' or one-line '/* */' comment using 'untrust-allow-null: <reason>' (minimum {0} characters) or 'untrust-null-represents-no-value: <description>' (minimum {1} characters); the latter may instead be an end-of-line '//' comment after the null literal. Use nullabilityExemptions only for recurring reviewed type/context cases.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor MemberPrefixRule = new(
        MemberPrefixId,
        "Member field does not follow the required naming policy",
        "Member field '{0}' must start with '{1}'",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ForbiddenMethodRule = new(
        ForbiddenMethodId,
        "Forbidden API",
        "Call to '{0}' is forbidden: {1}",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor StaticVirtualInterfaceMemberRule = new(
        StaticVirtualInterfaceMemberId,
        "Static virtual interface members require a security justification",
        "Static virtual interface member '{0}' supplies a default that can let implementers omit value constraints. Use static abstract instead, unless an immediately preceding '//' or one-line '/* */' comment starting 'untrust-static-virtual-is-safe:' explains why the default cannot weaken security or cause an overlooked override (minimum {1} characters). A valid exception is when an override is required to pass an enforced validation whose failure is visible to the developer.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor IsMethodContractRule = new(
        IsMethodContractId,
        "Is methods are predicate-only",
        "Method '{0}' starts with 'Is' and must return bool without any out parameters. Use TryXxx naming semantics instead for operations that produce output, for example: TryExtract..., TryConvert..., or TryParse.... When an out value is null on a false result, declare the TryParse-style [MaybeNullWhen(false)] contract.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor TryMethodOutContractRule = new(
        TryMethodOutContractId,
        "Try methods accurately document out nullability",
        "Method '{0}' starts with 'Try' and out parameter '{1}' {2}",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor NullableFirstArgumentRule = new(
        NullableFirstArgumentId,
        "Nullable first argument requires a reviewed boundary contract",
        "Method '{0}' accepts nullable first argument '{1}'. First preserve the nullable contract when implementing an interface or override. Otherwise prefer a non-nullable parameter: move the null check to the caller and do not call this method when the argument is null. Use a reviewed untrust-null-represents-no-value escape hatch only when neither design is viable.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ConfigurationConflictRule = new(
        ConfigurationConflictId,
        "BuildGate configuration error",
        "BuildGate configuration error: {0}",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ControlFlowBlockRule = new(
        ControlFlowBlockId,
        "Control-flow bodies require blocks",
        "{0} body must use curly braces and a block, even when it contains one statement.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor PublicClassFileRule = new(
        PublicClassFileId,
        "Public classes have dedicated files",
        "Source file '{0}' must contain one public top-level class named '{1}', unless it groups a complete class or interface hierarchy headed by that type.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor BooleanLiteralComparisonRule = new(
        BooleanLiteralComparisonId,
        "Boolean values must not be compared with literals",
        "Do not compare a Boolean value to '{0}'. Use the Boolean expression directly or negate it. For example, replace 'User.Identity?.IsAuthenticated == true' with 'User.Identity is { IsAuthenticated: true } identity'.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor LockKeywordRule = new(
        LockKeywordId,
        "Lock does not provide distributed coordination",
        "The 'lock' keyword coordinates only threads in one process and is forbidden in distributed systems. Use a distributed coordination mechanism. Escape only with an immediately preceding '//' or one-line '/* */' comment starting 'untrust-allow-local-threads-lock' and a minimum 100-character explanation of why this local lock remains effective in the distributed system.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor HttpRequestBodyAccessRule = new(
        HttpRequestBodyAccessId,
        "Unsafe HTTP request-body access",
        "'{0}' is forbidden. Use the application's validated request-binding boundary instead. Escape only with an immediately preceding comment of the form 'untrust-use-banned-method: {0} <justification>' whose justification has at least 100 characters.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor VarTypeObviousnessRule = new(
        VarTypeObviousnessId,
        "Var requires an obvious type",
        "'var' is allowed only when its type is obvious from the right-hand side: an explicit object creation, literal, or explicit cast. Use an explicit type for values returned by methods, properties, target-typed creation, or other inferred expressions.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ControllerValidatedArgumentsRule = new(
        ControllerValidatedArgumentsId,
        "Controller route input requires validated values",
        "Route input '{0}' must be a type derived from a VV validated-value base class, or a DTO whose public instance fields and properties are all such validated values.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor DenyByDefaultRouteAuthorizationRule = new(
        DenyByDefaultRouteAuthorizationId,
        "Routes must deny by default",
        "Controller routes require Program.cs to call builder.EnableDenyByDefaultRouteAuthorization() from Owasp.Untrust.NoOwnershipNeeded.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ExplicitRouteAuthorizationRule = new(
        ExplicitRouteAuthorizationId,
        "Routes require explicit authorization metadata",
        "Controller route '{0}' must declare [Authorize(...)] or [AllowAnonymous].",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor ConstantFieldCapitalizationRule = new(
        ConstantFieldCapitalizationId,
        "Constant fields use upper-case names",
        "Constant field '{0}' must use an upper-case name.",
        "OWASP Untrust",
        DiagnosticSeverity.Error,
        isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics =>
        ImmutableArray.Create(NullLiteralRule, MemberPrefixRule, ForbiddenMethodRule, StaticVirtualInterfaceMemberRule, IsMethodContractRule, TryMethodOutContractRule, NullableFirstArgumentRule, ConfigurationConflictRule, ControlFlowBlockRule, PublicClassFileRule, BooleanLiteralComparisonRule, LockKeywordRule, HttpRequestBodyAccessRule, VarTypeObviousnessRule, ControllerValidatedArgumentsRule, DenyByDefaultRouteAuthorizationRule, ExplicitRouteAuthorizationRule, ConstantFieldCapitalizationRule);

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();

        context.RegisterCompilationStartAction(startContext =>
        {
            AnalyzerConfigOptions globalOptions = startContext.Options.AnalyzerConfigOptionsProvider.GlobalOptions;
            globalOptions.TryGetValue("build_property.BuildGatesConfigurationDirectory", out string? configurationDirectory);
            if (string.IsNullOrWhiteSpace(configurationDirectory))
            {
                globalOptions.TryGetValue("build_property.MSBuildProjectDirectory", out configurationDirectory);
            }

            BuildGatePolicy policy = BuildGatePolicy.Load(startContext.Options.AdditionalFiles, configurationDirectory);
            var publicClassesByFile = new ConcurrentDictionary<SyntaxTree, ConcurrentBag<INamedTypeSymbol>>();
            var routeAuthorizationState = new RouteAuthorizationState();
            startContext.RegisterCompilationEndAction(compilationContext =>
            {
                foreach (string conflict in policy.ConfigurationConflicts)
                {
                    compilationContext.ReportDiagnostic(Diagnostic.Create(ConfigurationConflictRule, Location.None, conflict));
                }

                AnalyzePublicClassesPerFile(compilationContext, policy, publicClassesByFile);
                AnalyzeDenyByDefaultRouteAuthorization(compilationContext, policy, routeAuthorizationState);
            });
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeNullLiteral(nodeContext, policy), SyntaxKind.NullLiteralExpression);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeField(nodeContext, policy), SyntaxKind.VariableDeclarator);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeInvocation(nodeContext, policy), SyntaxKind.InvocationExpression);
            startContext.RegisterSyntaxNodeAction(AnalyzeIsMethodContract, SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(AnalyzeTryMethodOutContract, SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeNullableFirstArgument(nodeContext, policy), SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeControllerRouteMethod(nodeContext, policy, routeAuthorizationState), SyntaxKind.MethodDeclaration);
            startContext.RegisterSyntaxNodeAction(nodeContext => AnalyzeDenyByDefaultRouteAuthorizationInvocation(nodeContext, routeAuthorizationState), SyntaxKind.InvocationExpression);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => CollectPublicTopLevelClass(nodeContext, publicClassesByFile),
                SyntaxKind.ClassDeclaration,
                SyntaxKind.InterfaceDeclaration);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeControlFlowBlock(nodeContext, policy),
                SyntaxKind.IfStatement,
                SyntaxKind.ForStatement,
                SyntaxKind.ForEachStatement,
                SyntaxKind.ForEachVariableStatement,
                SyntaxKind.WhileStatement,
                SyntaxKind.DoStatement,
                SyntaxKind.UsingStatement,
                SyntaxKind.LockStatement,
                SyntaxKind.FixedStatement);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeBooleanLiteralComparison(nodeContext, policy),
                SyntaxKind.EqualsExpression,
                SyntaxKind.NotEqualsExpression);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeLockKeyword(nodeContext, policy),
                SyntaxKind.LockStatement);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeHttpRequestBodyMemberAccess(nodeContext, policy),
                SyntaxKind.SimpleMemberAccessExpression);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeIFormCollectionUse(nodeContext, policy),
                SyntaxKind.IdentifierName);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeVarDeclaration(nodeContext, policy),
                SyntaxKind.VariableDeclaration);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeVarDeclarationExpression(nodeContext, policy),
                SyntaxKind.DeclarationExpression);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeForeachVar(nodeContext, policy),
                SyntaxKind.ForEachStatement,
                SyntaxKind.ForEachVariableStatement);
            startContext.RegisterSyntaxNodeAction(
                nodeContext => AnalyzeStaticVirtualInterfaceMember(nodeContext, policy),
                SyntaxKind.MethodDeclaration,
                SyntaxKind.PropertyDeclaration,
                SyntaxKind.IndexerDeclaration,
                SyntaxKind.EventDeclaration);
        });
    }

    private static void AnalyzeNullLiteral(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (context.Node.Parent is ConstantPatternSyntax)
        {
            return;
        }

        if (policy.AllowsNullAssignment(context))
        {
            return;
        }

        if (HasNullJustification(context.Node, policy))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            NullLiteralRule,
            context.Node.GetLocation(),
            policy.MinimumNullJustificationCharacters,
            policy.MinimumNoValueDescriptionCharacters));
    }

    private static bool HasNullJustification(SyntaxNode nullLiteral, BuildGatePolicy policy)
    {
        FileLinePositionSpan span = nullLiteral.GetLocation().GetLineSpan();
        SourceText source = nullLiteral.SyntaxTree.GetText();
        string currentLine = source.Lines[span.StartLinePosition.Line].ToString();
        if (HasEndOfLineJustification(currentLine, span.StartLinePosition.Character, policy))
        {
            return true;
        }

        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        string precedingLine = source.Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        return HasCommentJustification(precedingLine, policy);
    }

    private static bool HasEndOfLineJustification(string line, int nullStartColumn, BuildGatePolicy policy)
    {
        int commentStart = line.IndexOf("//", nullStartColumn, StringComparison.Ordinal);
        return commentStart >= 0 && HasCommentJustification(line.Substring(commentStart), policy);
    }

    private static bool HasCommentJustification(string comment, BuildGatePolicy policy)
    {
        string content = comment.Trim();
        if (content.StartsWith("//", StringComparison.Ordinal))
        {
            content = content.Substring(2).TrimStart();
        }
        else if (content.StartsWith("/*", StringComparison.Ordinal) && content.EndsWith("*/", StringComparison.Ordinal))
        {
            content = content.Substring(2, content.Length - 4).Trim();
        }
        else
        {
            return false;
        }

        foreach (string marker in policy.NullJustificationMarkers)
        {
            if (content.StartsWith(marker, StringComparison.Ordinal))
            {
                int minimumLength = policy.UsesLegacyNullMarker(marker)
                    ? policy.MinimumNullJustificationCharacters
                    : policy.MinimumNoValueDescriptionCharacters;
                return content.Substring(marker.Length).Trim().Length >= minimumLength;
            }
        }

        return false;
    }

    private static void AnalyzeField(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var variable = (VariableDeclaratorSyntax)context.Node;
        if (variable.Parent?.Parent is not FieldDeclarationSyntax field)
        {
            return;
        }

        bool isConst = field.Modifiers.Any(SyntaxKind.ConstKeyword);
        bool isStaticReadOnly = IsStaticReadOnlyField(field);
        if (!string.IsNullOrEmpty(policy.MemberPrefix) &&
            !((isConst || isStaticReadOnly) && policy.ConstFieldsExmptMemberPrefix) &&
            !variable.Identifier.ValueText.StartsWith(policy.MemberPrefix, StringComparison.Ordinal))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                MemberPrefixRule,
                variable.Identifier.GetLocation(),
                variable.Identifier.ValueText,
                policy.MemberPrefix));
        }

        if (policy.KonstantsInUpperCase && IsConstantLikeField(field, variable) && !IsUpperCaseName(variable.Identifier.ValueText))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                ConstantFieldCapitalizationRule,
                variable.Identifier.GetLocation(),
                variable.Identifier.ValueText));
        }
    }

    private static bool IsConstantLikeField(FieldDeclarationSyntax field, VariableDeclaratorSyntax variable) =>
        field.Modifiers.Any(SyntaxKind.ConstKeyword) ||
        (IsStaticReadOnlyField(field) &&
            variable.Initializer is { Value: var initializer } &&
            (IsLiteral(initializer) || IsLiteralDerivedHardcoded(initializer)));

    private static bool IsStaticReadOnlyField(FieldDeclarationSyntax field) =>
        field.Modifiers.Any(SyntaxKind.StaticKeyword) && field.Modifiers.Any(SyntaxKind.ReadOnlyKeyword);

    private static bool IsLiteralDerivedHardcoded(ExpressionSyntax expression)
    {
        ExpressionSyntax value = expression is ParenthesizedExpressionSyntax parenthesized
            ? parenthesized.Expression
            : expression;
        SeparatedSyntaxList<ArgumentSyntax> arguments = value switch
        {
            ObjectCreationExpressionSyntax { Type: IdentifierNameSyntax { Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var objectArguments } } => objectArguments,
            InvocationExpressionSyntax { Expression: IdentifierNameSyntax { Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var invocationArguments } } => invocationArguments,
            InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax { Name.Identifier.ValueText: "Hardcoded" }, ArgumentList: { Arguments: var memberInvocationArguments } } => memberInvocationArguments,
            _ => default
        };

        return arguments.Count > 0 && arguments.All(argument => IsLiteral(argument.Expression));
    }

    private static bool IsLiteral(ExpressionSyntax expression) =>
        expression is LiteralExpressionSyntax ||
        expression is ParenthesizedExpressionSyntax { Expression: LiteralExpressionSyntax };

    private static bool IsUpperCaseName(string name) =>
        name.Any(char.IsLetter) && name.All(character => !char.IsLetter(character) || char.IsUpper(character));

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var invocation = (InvocationExpressionSyntax)context.Node;
        if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method)
        {
            return;
        }

        ForbiddenMethodPolicy? match = policy.ForbiddenMethods.FirstOrDefault(rule => rule.Matches(method));
        if (match is null)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            ForbiddenMethodRule,
            invocation.GetLocation(),
            method.ToDisplayString(SymbolDisplayFormat.CSharpErrorMessageFormat),
            match.Message));
    }

    private static void AnalyzeIsMethodContract(SyntaxNodeAnalysisContext context)
    {
        var declaration = (MethodDeclarationSyntax)context.Node;
        if (!ViolatesIsMethodContract(declaration, context.SemanticModel, context.CancellationToken, out IMethodSymbol? method))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            IsMethodContractRule,
            declaration.Identifier.GetLocation(),
            method!.Name));
    }

    private static bool ViolatesIsMethodContract(
        MethodDeclarationSyntax declaration,
        SemanticModel semanticModel,
        CancellationToken cancellationToken,
        out IMethodSymbol? method)
    {
        method = semanticModel.GetDeclaredSymbol(declaration, cancellationToken);
        return declaration.Identifier.ValueText.StartsWith("Is", StringComparison.Ordinal) &&
            method is not null &&
            (method.ReturnType.SpecialType != SpecialType.System_Boolean || method.Parameters.Any(parameter => parameter.RefKind == RefKind.Out));
    }

    private static void AnalyzeTryMethodOutContract(SyntaxNodeAnalysisContext context)
    {
        var declaration = (MethodDeclarationSyntax)context.Node;
        if (!declaration.Identifier.ValueText.StartsWith("Try", StringComparison.Ordinal) ||
            context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not IMethodSymbol method)
        {
            return;
        }

        foreach (IParameterSymbol parameter in method.Parameters.Where(parameter => parameter.RefKind == RefKind.Out))
        {
            bool isNonNullableValueType = parameter.Type.IsValueType &&
                parameter.Type is not INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T };
            bool canRepresentNull = !isNonNullableValueType;
            bool hasMaybeNullWhenFalse = HasMaybeNullWhenFalse(parameter);
            if (canRepresentNull && !hasMaybeNullWhenFalse)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    TryMethodOutContractRule,
                    declaration.Identifier.GetLocation(),
                    method.Name,
                    parameter.Name,
                    "can represent null and must declare [MaybeNullWhen(false)]. Add the annotation so a false result explicitly documents that the out value can be null."));
            }
            else if (!canRepresentNull && hasMaybeNullWhenFalse)
            {
                context.ReportDiagnostic(Diagnostic.Create(
                    TryMethodOutContractRule,
                    declaration.Identifier.GetLocation(),
                    method.Name,
                    parameter.Name,
                    "is a non-nullable value type and must not declare [MaybeNullWhen(false)]. Remove the annotation; false results use the type's default value, not null."));
            }
        }
    }

    private static bool HasMaybeNullWhenFalse(IParameterSymbol parameter) =>
        parameter.GetAttributes().Any(attribute =>
            attribute.AttributeClass?.ToDisplayString() == "System.Diagnostics.CodeAnalysis.MaybeNullWhenAttribute" &&
            attribute.ConstructorArguments.Length == 1 &&
            attribute.ConstructorArguments[0].Value is false);

    private static void AnalyzeNullableFirstArgument(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var declaration = (MethodDeclarationSyntax)context.Node;
        if (declaration.ParameterList.Parameters.Count == 0 ||
            context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not IMethodSymbol method)
        {
            return;
        }

        IParameterSymbol firstParameter = method.Parameters[0];
        if (firstParameter.NullableAnnotation != NullableAnnotation.Annotated ||
            policy.AllowsNullableFirstArgument(firstParameter, method) ||
            HasNullJustification(declaration, policy))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            NullableFirstArgumentRule,
            declaration.Identifier.GetLocation(),
            method.Name,
            firstParameter.Name));
    }

    private static void AnalyzeStaticVirtualInterfaceMember(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.ForbidStaticVirtualInterfaceMembers ||
            context.Node.Parent is not InterfaceDeclarationSyntax ||
            context.Node is not MemberDeclarationSyntax member ||
            !member.Modifiers.Any(SyntaxKind.StaticKeyword) ||
            !member.Modifiers.Any(SyntaxKind.VirtualKeyword) ||
            HasStaticVirtualJustification(member, policy))
        {
            return;
        }

        string name = context.SemanticModel.GetDeclaredSymbol(member, context.CancellationToken)?.Name ?? "member";
        context.ReportDiagnostic(Diagnostic.Create(
            StaticVirtualInterfaceMemberRule,
            member.GetLocation(),
            name,
            policy.MinimumStaticVirtualJustificationCharacters));
    }

    private static void AnalyzeControlFlowBlock(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.RequireBlocksForControlFlow ||
            GetControlledStatement(context.Node) is not StatementSyntax controlledStatement ||
            controlledStatement is BlockSyntax ||
            controlledStatement.IsKind(SyntaxKind.EmptyStatement))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            ControlFlowBlockRule,
            controlledStatement.GetLocation(),
            GetControlFlowName(context.Node)));
    }

    private static void AnalyzeBooleanLiteralComparison(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.BanComparingBoolValueToLiteral || context.Node is not BinaryExpressionSyntax comparison)
        {
            return;
        }

        LiteralExpressionSyntax? booleanLiteral = comparison.Left is LiteralExpressionSyntax left && IsBooleanLiteral(left)
            ? left
            : comparison.Right is LiteralExpressionSyntax right && IsBooleanLiteral(right)
                ? right
                : null;
        if (booleanLiteral is null)
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(
            BooleanLiteralComparisonRule,
            comparison.GetLocation(),
            booleanLiteral.Token.ValueText));
    }

    private static void AnalyzeLockKeyword(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var lockStatement = (LockStatementSyntax)context.Node;
        if (!policy.ForbidLockKeyword || HasLocalThreadsLockJustification(lockStatement))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(LockKeywordRule, lockStatement.LockKeyword.GetLocation()));
    }

    private static void AnalyzeHttpRequestBodyMemberAccess(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.ForbidHttpRequestBodyAccess || context.Node is not MemberAccessExpressionSyntax memberAccess ||
            context.SemanticModel.GetSymbolInfo(memberAccess, context.CancellationToken).Symbol is not ISymbol member ||
            !string.Equals(member.ContainingType?.ToDisplayString(), "Microsoft.AspNetCore.Http.HttpRequest", StringComparison.Ordinal))
        {
            return;
        }

        string? bannedMember = member switch
        {
            IMethodSymbol { Name: "ReadFormAsync" } => "HttpRequest.ReadFormAsync",
            IPropertySymbol { Name: "Form" } => "HttpRequest.Form",
            IPropertySymbol { Name: "Body" } => "HttpRequest.Body",
            IPropertySymbol { Name: "BodyReader" } => "HttpRequest.BodyReader",
            _ => null
        };
        if (bannedMember is not null && !HasBannedMethodJustification(memberAccess, bannedMember))
        {
            context.ReportDiagnostic(Diagnostic.Create(HttpRequestBodyAccessRule, memberAccess.GetLocation(), bannedMember));
        }
    }

    private static void AnalyzeIFormCollectionUse(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.ForbidHttpRequestBodyAccess || context.Node is not IdentifierNameSyntax identifier ||
            context.SemanticModel.GetSymbolInfo(identifier, context.CancellationToken).Symbol is not INamedTypeSymbol type ||
            !string.Equals(type.ToDisplayString(), "Microsoft.AspNetCore.Http.IFormCollection", StringComparison.Ordinal) ||
            HasBannedMethodJustification(identifier, "IFormCollection"))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(HttpRequestBodyAccessRule, identifier.GetLocation(), "IFormCollection"));
    }

    private static void AnalyzeVarDeclaration(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var declaration = (VariableDeclarationSyntax)context.Node;
        if (!policy.RequireObviousVarType || !IsVar(declaration.Type) ||
            declaration.Variables.All(variable => variable.Initializer is { Value: var value } &&
                HasObviousVarType(value, context.SemanticModel, context.CancellationToken)))
        {
            return;
        }

        context.ReportDiagnostic(Diagnostic.Create(VarTypeObviousnessRule, declaration.Type.GetLocation()));
    }

    private static void AnalyzeVarDeclarationExpression(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        var declaration = (DeclarationExpressionSyntax)context.Node;
        if (policy.RequireObviousVarType && IsVar(declaration.Type) &&
            !IsSelfReturningTryParseOutArgument(declaration, context.SemanticModel, context.CancellationToken))
        {
            context.ReportDiagnostic(Diagnostic.Create(VarTypeObviousnessRule, declaration.Type.GetLocation()));
        }
    }

    private static bool IsSelfReturningTryParseOutArgument(
        DeclarationExpressionSyntax declaration,
        SemanticModel semanticModel,
        CancellationToken cancellationToken)
    {
        if (declaration.Parent is not ArgumentSyntax argument ||
            !argument.RefKindKeyword.IsKind(SyntaxKind.OutKeyword) ||
            argument.Parent is not BaseArgumentListSyntax arguments ||
            arguments.Parent is not InvocationExpressionSyntax invocation ||
            invocation.Expression is not MemberAccessExpressionSyntax memberAccess ||
            semanticModel.GetSymbolInfo(invocation, cancellationToken).Symbol is not IMethodSymbol method ||
            !method.IsStatic ||
            !string.Equals(method.Name, "TryParse", StringComparison.Ordinal) ||
            method.ReturnType.SpecialType != SpecialType.System_Boolean)
        {
            return false;
        }

        int argumentIndex = arguments.Arguments.IndexOf(argument);
        if (argumentIndex < 0 || argumentIndex >= method.Parameters.Length ||
            method.Parameters[argumentIndex].RefKind != RefKind.Out ||
            semanticModel.GetTypeInfo(memberAccess.Expression, cancellationToken).Type is not ITypeSymbol receiverType)
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(method.Parameters[argumentIndex].Type, receiverType);
    }

    private static void AnalyzeForeachVar(SyntaxNodeAnalysisContext context, BuildGatePolicy policy)
    {
        if (!policy.RequireObviousVarType)
        {
            return;
        }

        TypeSyntax? type = context.Node switch
        {
            ForEachStatementSyntax foreachStatement => foreachStatement.Type,
            ForEachVariableStatementSyntax { Variable: DeclarationExpressionSyntax declaration } => declaration.Type,
            _ => null
        };
        if (type is not null && IsVar(type))
        {
            context.ReportDiagnostic(Diagnostic.Create(VarTypeObviousnessRule, type.GetLocation()));
        }
    }

    private static bool IsVar(TypeSyntax type) =>
        type is IdentifierNameSyntax identifier && string.Equals(identifier.Identifier.ValueText, "var", StringComparison.Ordinal);

    private static bool HasObviousVarType(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        CancellationToken cancellationToken)
    {
        ExpressionSyntax value = expression is ParenthesizedExpressionSyntax parenthesized
            ? parenthesized.Expression
            : expression;
        return value is ObjectCreationExpressionSyntax or
            AnonymousObjectCreationExpressionSyntax or
            ArrayCreationExpressionSyntax or
            ImplicitArrayCreationExpressionSyntax or
            LiteralExpressionSyntax or
            CastExpressionSyntax or
            DefaultExpressionSyntax or
            TypeOfExpressionSyntax ||
            IsSelfReturningStaticParse(value, semanticModel, cancellationToken);
    }

    private static bool IsSelfReturningStaticParse(
        ExpressionSyntax expression,
        SemanticModel semanticModel,
        CancellationToken cancellationToken)
    {
        if (expression is not InvocationExpressionSyntax invocation ||
            semanticModel.GetSymbolInfo(invocation, cancellationToken).Symbol is not IMethodSymbol method ||
            !method.IsStatic ||
            (method.Name is not "Parse" and not "ParseValue") ||
            method.ContainingType is not INamedTypeSymbol containingType)
        {
            return false;
        }

        return SymbolEqualityComparer.Default.Equals(method.ReturnType, containingType);
    }

    private static void AnalyzeControllerRouteMethod(
        SyntaxNodeAnalysisContext context,
        BuildGatePolicy policy,
        RouteAuthorizationState routeAuthorizationState)
    {
        if (context.Node is not MethodDeclarationSyntax declaration ||
            context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not IMethodSymbol method ||
            !IsControllerHttpRoute(method))
        {
            return;
        }

        routeAuthorizationState.MarkControllerRoute();
        if (policy.RequireExplicitControllerRouteAuthorization && !HasExplicitRouteAuthorization(method))
        {
            context.ReportDiagnostic(Diagnostic.Create(
                ExplicitRouteAuthorizationRule,
                declaration.Identifier.GetLocation(),
                method.Name));
        }

        if (!policy.RequireValidatedControllerRouteArguments)
        {
            return;
        }

        foreach (IParameterSymbol parameter in method.Parameters)
        {
            if (IsValidatedValue(parameter.Type))
            {
                continue;
            }

            if (parameter.Type is INamedTypeSymbol dto && IsSourceDto(dto))
            {
                ImmutableArray<ISymbol> invalidMembers = GetUnvalidatedDtoMembers(dto);
                if (!invalidMembers.IsDefaultOrEmpty)
                {
                    foreach (ISymbol member in invalidMembers)
                    {
                        context.ReportDiagnostic(Diagnostic.Create(
                            ControllerValidatedArgumentsRule,
                            member.Locations.FirstOrDefault(location => location.IsInSource) ?? parameter.Locations[0],
                            $"{parameter.Name}.{member.Name}"));
                    }

                    continue;
                }

                continue;
            }

            context.ReportDiagnostic(Diagnostic.Create(
                ControllerValidatedArgumentsRule,
                parameter.Locations[0],
                parameter.Name));
        }
    }

    private static bool IsHttpRouteAttribute(AttributeData attribute) =>
        attribute.AttributeClass is not null && DerivesFromType(attribute.AttributeClass, "Microsoft.AspNetCore.Mvc.Routing.HttpMethodAttribute");

    private static bool IsControllerHttpRoute(IMethodSymbol method) =>
        method.ContainingType is INamedTypeSymbol controller &&
        DerivesFromType(controller, "Microsoft.AspNetCore.Mvc.ControllerBase") &&
        method.GetAttributes().Any(IsHttpRouteAttribute);

    private static bool HasExplicitRouteAuthorization(IMethodSymbol method) =>
        method.GetAttributes().Any(attribute =>
            string.Equals(attribute.AttributeClass?.ToDisplayString(), "Microsoft.AspNetCore.Authorization.AuthorizeAttribute", StringComparison.Ordinal) ||
            string.Equals(attribute.AttributeClass?.ToDisplayString(), "Microsoft.AspNetCore.Authorization.AllowAnonymousAttribute", StringComparison.Ordinal));

    private static void AnalyzeDenyByDefaultRouteAuthorizationInvocation(
        SyntaxNodeAnalysisContext context,
        RouteAuthorizationState routeAuthorizationState)
    {
        if (context.Node is not InvocationExpressionSyntax invocation ||
            !string.Equals(Path.GetFileName(invocation.SyntaxTree.FilePath), "Program.cs", StringComparison.OrdinalIgnoreCase) ||
            context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is not IMethodSymbol method)
        {
            return;
        }

        IMethodSymbol definition = method.ReducedFrom ?? method;
        if (string.Equals(definition.Name, "EnableDenyByDefaultRouteAuthorization", StringComparison.Ordinal) &&
            string.Equals(definition.ContainingType.ToDisplayString(), "Owasp.Untrust.NoOwnershipNeeded.DenyByDefaultRouteAuthorization", StringComparison.Ordinal))
        {
            routeAuthorizationState.MarkDenyByDefaultRouteAuthorizationCall();
        }
    }

    private static void AnalyzeDenyByDefaultRouteAuthorization(
        CompilationAnalysisContext context,
        BuildGatePolicy policy,
        RouteAuthorizationState routeAuthorizationState)
    {
        if (policy.RequireDenyByDefaultRouteAuthorization &&
            routeAuthorizationState.HasControllerRoutes &&
            !routeAuthorizationState.HasDenyByDefaultRouteAuthorizationCall)
        {
            context.ReportDiagnostic(Diagnostic.Create(DenyByDefaultRouteAuthorizationRule, Location.None));
        }
    }

    private static bool DerivesFromType(INamedTypeSymbol type, string fullyQualifiedTypeName)
    {
        for (INamedTypeSymbol? current = type; current is not null; current = current.BaseType)
        {
            if (string.Equals(current.ToDisplayString(), fullyQualifiedTypeName, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsValidatedValue(ITypeSymbol type)
    {
        if (type is not INamedTypeSymbol namedType)
        {
            return false;
        }

        for (INamedTypeSymbol? current = namedType; current is not null; current = current.BaseType)
        {
            INamedTypeSymbol definition = current.OriginalDefinition;
            string namespaceName = definition.ContainingNamespace.ToDisplayString();
            if ((string.Equals(namespaceName, "Owasp.Untrust.VV.Core", StringComparison.Ordinal) &&
                    string.Equals(definition.MetadataName, "ValidatedValue`3", StringComparison.Ordinal)) ||
                (string.Equals(namespaceName, "Owasp.Untrust.VV.CrossValidation", StringComparison.Ordinal) &&
                    string.Equals(definition.MetadataName, "CrossValidatedValue`3", StringComparison.Ordinal)))
            {
                return true;
            }
        }

        return false;
    }

    private static ImmutableArray<ISymbol> GetUnvalidatedDtoMembers(INamedTypeSymbol dto)
    {
        return dto.GetMembers()
            .Where(member => member is IFieldSymbol { IsStatic: false, DeclaredAccessibility: Accessibility.Public } or
                IPropertySymbol { IsStatic: false, DeclaredAccessibility: Accessibility.Public })
            .Where(member => member switch
            {
                IFieldSymbol field => !IsValidatedValue(field.Type),
                IPropertySymbol property => !IsValidatedValue(property.Type),
                _ => false
            })
            .ToImmutableArray();
    }

    private static bool IsSourceDto(INamedTypeSymbol type) =>
        type.TypeKind is TypeKind.Class or TypeKind.Struct && type.Locations.Any(location => location.IsInSource);

    private static bool HasBannedMethodJustification(SyntaxNode node, string bannedMember)
    {
        FileLinePositionSpan span = node.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        SourceText source = node.SyntaxTree.GetText();
        string precedingLine = source.Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        string? comment = GetCommentContent(precedingLine);
        const string marker = "untrust-use-banned-method:";
        if (comment is null || !comment.StartsWith(marker, StringComparison.Ordinal))
        {
            return false;
        }

        string value = comment.Substring(marker.Length).TrimStart();
        if (!value.StartsWith(bannedMember, StringComparison.Ordinal) ||
            value.Length == bannedMember.Length ||
            !char.IsWhiteSpace(value[bannedMember.Length]))
        {
            return false;
        }

        return value.Substring(bannedMember.Length).Trim().Length >= 100;
    }

    private static bool HasLocalThreadsLockJustification(LockStatementSyntax lockStatement)
    {
        FileLinePositionSpan span = lockStatement.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        SourceText source = lockStatement.SyntaxTree.GetText();
        string precedingLine = source.Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        return HasCommentWithMarker(precedingLine, "untrust-allow-local-threads-lock", 100);
    }

    private static bool IsBooleanLiteral(LiteralExpressionSyntax expression) =>
        expression.IsKind(SyntaxKind.TrueLiteralExpression) || expression.IsKind(SyntaxKind.FalseLiteralExpression);

    private static void CollectPublicTopLevelClass(
        SyntaxNodeAnalysisContext context,
        ConcurrentDictionary<SyntaxTree, ConcurrentBag<INamedTypeSymbol>> publicClassesByFile)
    {
        if (context.Node is not TypeDeclarationSyntax declaration)
        {
            return;
        }

        if (context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not INamedTypeSymbol @class ||
            @class.ContainingType is not null ||
            @class.DeclaredAccessibility != Accessibility.Public)
        {
            return;
        }

        publicClassesByFile.GetOrAdd(context.Node.SyntaxTree, static _ => new ConcurrentBag<INamedTypeSymbol>()).Add(@class);
    }

    private static void AnalyzePublicClassesPerFile(
        CompilationAnalysisContext context,
        BuildGatePolicy policy,
        ConcurrentDictionary<SyntaxTree, ConcurrentBag<INamedTypeSymbol>> publicClassesByFile)
    {
        if (!policy.OnePublicClassPerFile)
        {
            return;
        }

        foreach (SyntaxTree tree in context.Compilation.SyntaxTrees)
        {
            if (string.IsNullOrWhiteSpace(tree.FilePath))
            {
                continue;
            }

            if (!publicClassesByFile.TryGetValue(tree, out ConcurrentBag<INamedTypeSymbol>? collectedClasses))
            {
                continue;
            }

            var publicClassesBuilder = ImmutableArray.CreateBuilder<INamedTypeSymbol>();
            foreach (INamedTypeSymbol @class in collectedClasses)
            {
                if (!publicClassesBuilder.Any(existing => SymbolEqualityComparer.Default.Equals(existing, @class)))
                {
                    publicClassesBuilder.Add(@class);
                }
            }

            ImmutableArray<INamedTypeSymbol> publicClasses = publicClassesBuilder
                .GroupBy(@class => @class.Name, StringComparer.Ordinal)
                .Select(group => group.OrderBy(@class => @class.Arity).First())
                .ToImmutableArray();
            if (publicClasses.IsDefaultOrEmpty || !publicClasses.Any(@class => @class.TypeKind == TypeKind.Class))
            {
                continue;
            }

            string fileName = Path.GetFileNameWithoutExtension(tree.FilePath);
            if (policy.AllowAttributeClassesToShareFile &&
                IsMainClassWithAttributeClasses(publicClasses, fileName))
            {
                continue;
            }

            if (IsNameBasedInterfaceCompanionGrouping(publicClasses, fileName))
            {
                continue;
            }

            INamedTypeSymbol? hierarchyBase = policy.AllowGroupingOfCompleteClassHierarchies
                ? FindCompleteHierarchyBase(publicClasses, context.Compilation, context.CancellationToken)
                : null;
            if (hierarchyBase is not null)
            {
                continue;
            }

            if (publicClasses.Length == 1 && string.Equals(fileName, publicClasses[0].Name, StringComparison.Ordinal))
            {
                continue;
            }

            INamedTypeSymbol requiredClass = hierarchyBase ?? publicClasses[0];
            context.ReportDiagnostic(Diagnostic.Create(
                PublicClassFileRule,
                publicClasses[0].Locations.FirstOrDefault(location => location.IsInSource) ?? Location.None,
                Path.GetFileName(tree.FilePath),
                requiredClass.Name));
        }
    }

    private static bool IsMainClassWithAttributeClasses(
        ImmutableArray<INamedTypeSymbol> publicClasses,
        string fileName)
    {
        ImmutableArray<INamedTypeSymbol> nonAttributeClasses = publicClasses
            .Where(@class => !DerivesFromType(@class, "System.Attribute"))
            .ToImmutableArray();
        return nonAttributeClasses.Length == 1 &&
            publicClasses.Length > 1 &&
            string.Equals(fileName, nonAttributeClasses[0].Name, StringComparison.Ordinal);
    }

    private static bool IsNameBasedInterfaceCompanionGrouping(
        ImmutableArray<INamedTypeSymbol> publicClasses,
        string fileName)
    {
        foreach (INamedTypeSymbol interfaceType in publicClasses.Where(@class => @class.TypeKind == TypeKind.Interface))
        {
            if (!interfaceType.Name.StartsWith("I", StringComparison.Ordinal) || interfaceType.Name.Length == 1)
            {
                continue;
            }

            string subjectName = interfaceType.Name.Substring(1);
            if ((string.Equals(fileName, subjectName, StringComparison.Ordinal) ||
                    string.Equals(fileName, interfaceType.Name, StringComparison.Ordinal)) &&
                publicClasses.All(@class =>
                    SymbolEqualityComparer.Default.Equals(@class, interfaceType) ||
                    (@class.TypeKind == TypeKind.Class &&
                        string.Equals(@class.Name, subjectName, StringComparison.Ordinal) &&
                        DerivesFrom(@class, interfaceType)) ||
                    (@class.TypeKind == TypeKind.Interface &&
                        string.Equals(@class.Name, interfaceType.Name + "Factory", StringComparison.Ordinal))))
            {
                return true;
            }
        }

        return false;
    }

    private static INamedTypeSymbol? FindCompleteHierarchyBase(
        ImmutableArray<INamedTypeSymbol> fileClasses,
        Compilation compilation,
        CancellationToken cancellationToken)
    {
        if (fileClasses.Length < 2)
        {
            return null;
        }

        ImmutableArray<INamedTypeSymbol> sourceClasses = GetSourceClasses(compilation.GlobalNamespace, cancellationToken);
        foreach (INamedTypeSymbol candidateBase in fileClasses)
        {
            if (fileClasses.Any(@class => !SymbolEqualityComparer.Default.Equals(@class, candidateBase) && !DerivesFrom(@class, candidateBase)))
            {
                continue;
            }

            ImmutableArray<INamedTypeSymbol> knownDerivedClasses = sourceClasses
                .Where(@class => DerivesFrom(@class, candidateBase))
                .ToImmutableArray();
            if (knownDerivedClasses.Length == fileClasses.Length - 1 &&
                knownDerivedClasses.All(derived => fileClasses.Any(@class => SymbolEqualityComparer.Default.Equals(@class, derived))))
            {
                return candidateBase;
            }
        }

        return null;
    }

    private static ImmutableArray<INamedTypeSymbol> GetSourceClasses(INamespaceSymbol @namespace, CancellationToken cancellationToken)
    {
        var classes = ImmutableArray.CreateBuilder<INamedTypeSymbol>();
        foreach (INamedTypeSymbol type in @namespace.GetTypeMembers())
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (type.TypeKind == TypeKind.Class && type.Locations.Any(location => location.IsInSource))
            {
                classes.Add(type);
            }
        }

        foreach (INamespaceSymbol nestedNamespace in @namespace.GetNamespaceMembers())
        {
            classes.AddRange(GetSourceClasses(nestedNamespace, cancellationToken));
        }

        return classes.ToImmutable();
    }

    private static bool DerivesFrom(INamedTypeSymbol candidate, INamedTypeSymbol baseClass)
    {
        if (baseClass.TypeKind == TypeKind.Interface &&
            candidate.AllInterfaces.Any(@interface => SymbolEqualityComparer.Default.Equals(@interface, baseClass)))
        {
            return true;
        }

        for (INamedTypeSymbol? current = candidate.BaseType; current is not null; current = current.BaseType)
        {
            if (SymbolEqualityComparer.Default.Equals(current, baseClass))
            {
                return true;
            }
        }

        return false;
    }

    private static StatementSyntax? GetControlledStatement(SyntaxNode node) => node switch
    {
        IfStatementSyntax @if => @if.Statement,
        ForStatementSyntax @for => @for.Statement,
        ForEachStatementSyntax foreachStatement => foreachStatement.Statement,
        ForEachVariableStatementSyntax foreachVariableStatement => foreachVariableStatement.Statement,
        WhileStatementSyntax @while => @while.Statement,
        DoStatementSyntax @do => @do.Statement,
        UsingStatementSyntax @using => @using.Statement,
        LockStatementSyntax @lock => @lock.Statement,
        FixedStatementSyntax fixedStatement => fixedStatement.Statement,
        _ => null
    };

    private static string GetControlFlowName(SyntaxNode node) => node.Kind() switch
    {
        SyntaxKind.IfStatement => "if",
        SyntaxKind.ForStatement => "for",
        SyntaxKind.ForEachStatement or SyntaxKind.ForEachVariableStatement => "foreach",
        SyntaxKind.WhileStatement => "while",
        SyntaxKind.DoStatement => "do",
        SyntaxKind.UsingStatement => "using",
        SyntaxKind.LockStatement => "lock",
        SyntaxKind.FixedStatement => "fixed",
        _ => "control-flow"
    };

    private static bool HasStaticVirtualJustification(MemberDeclarationSyntax member, BuildGatePolicy policy)
    {
        FileLinePositionSpan span = member.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        SourceText source = member.SyntaxTree.GetText();
        string precedingLine = source.Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        return HasCommentWithMarker(
            precedingLine,
            policy.StaticVirtualJustificationPrefix,
            policy.MinimumStaticVirtualJustificationCharacters);
    }

    private static bool HasCommentWithMarker(string comment, string marker, int minimumDescriptionCharacters)
    {
        string? content = GetCommentContent(comment);
        if (content is null)
        {
            return false;
        }

        return content.StartsWith(marker, StringComparison.Ordinal) &&
            content.Substring(marker.Length).Trim().Length >= minimumDescriptionCharacters;
    }

    private static string? GetCommentContent(string comment)
    {
        string content = comment.Trim();
        if (content.StartsWith("//", StringComparison.Ordinal))
        {
            return content.Substring(2).TrimStart();
        }

        return content.StartsWith("/*", StringComparison.Ordinal) && content.EndsWith("*/", StringComparison.Ordinal)
            ? content.Substring(2, content.Length - 4).Trim()
            : null;
    }

    private sealed class RouteAuthorizationState
    {
        private int hasControllerRoutes;
        private int hasDenyByDefaultRouteAuthorizationCall;

        public bool HasControllerRoutes => Volatile.Read(ref hasControllerRoutes) != 0;
        public bool HasDenyByDefaultRouteAuthorizationCall => Volatile.Read(ref hasDenyByDefaultRouteAuthorizationCall) != 0;

        public void MarkControllerRoute() => Interlocked.Exchange(ref hasControllerRoutes, 1);

        public void MarkDenyByDefaultRouteAuthorizationCall() => Interlocked.Exchange(ref hasDenyByDefaultRouteAuthorizationCall, 1);
    }
}

internal sealed class BuildGatePolicy
{
    private const string ActiveConfigurationFileName = "active-buildgates.json";
    private const string LegacyConfigurationFileName = "buildgates.json";
    private const string DefaultNullJustificationMarker = "untrust-null-represents-no-value:";
    private const string LegacyNullJustificationMarker = "untrust-allow-null:";
    private const string DefaultStaticVirtualJustificationMarker = "untrust-static-virtual-is-safe:";

    public string MemberPrefix { get; set; } = "m_";
    public string NullJustificationPrefix { get; set; } = DefaultNullJustificationMarker;
    public int MinimumNullJustificationCharacters { get; set; } = 40;
    public int MinimumNoValueDescriptionCharacters { get; set; } = 15;
    public bool ForbidStaticVirtualInterfaceMembers { get; set; }
    public string StaticVirtualJustificationPrefix { get; set; } = DefaultStaticVirtualJustificationMarker;
    public int MinimumStaticVirtualJustificationCharacters { get; set; } = 40;
    public bool RequireBlocksForControlFlow { get; set; } = true;
    public bool OnePublicClassPerFile { get; set; } = true;
    public bool AllowGroupingOfCompleteClassHierarchies { get; set; } = true;
    public bool AllowAttributeClassesToShareFile { get; set; } = true;
    public bool BanComparingBoolValueToLiteral { get; set; } = true;
    public bool ForbidLockKeyword { get; set; } = true;
    public bool ForbidHttpRequestBodyAccess { get; set; } = true;
    public bool RequireObviousVarType { get; set; } = true;
    public bool RequireValidatedControllerRouteArguments { get; set; } = true;
    public bool RequireDenyByDefaultRouteAuthorization { get; set; } = true;
    public bool RequireExplicitControllerRouteAuthorization { get; set; } = true;
    public bool ConstFieldsExmptMemberPrefix { get; set; } = true;
    public bool KonstantsInUpperCase { get; set; } = true;
    public ImmutableArray<ForbiddenMethodPolicy> ForbiddenMethods { get; set; } = ImmutableArray<ForbiddenMethodPolicy>.Empty;
    public ImmutableArray<GlobalAllowNullAssignmentPolicy> GlobalAllowNullAssignments { get; set; } = ImmutableArray<GlobalAllowNullAssignmentPolicy>.Empty;
    public ImmutableArray<string> ConfigurationConflicts => configurationConflicts.ToImmutableArray();

    private readonly Dictionary<string, string> configuredScalarValues = new(StringComparer.Ordinal);
    private readonly List<string> configurationConflicts = new();

    public void AddConfigurationError(string error) => configurationConflicts.Add(error);

    public static BuildGatePolicy Load(ImmutableArray<AdditionalText> additionalFiles, string? configurationDirectory)
    {
        var policy = new BuildGatePolicy();
        ImmutableArray<AdditionalText> activeConfigurations = FindActiveConfigurations(additionalFiles, configurationDirectory);
        if (!activeConfigurations.IsDefaultOrEmpty)
        {
            foreach (AdditionalText activeConfiguration in activeConfigurations)
            {
                LoadActiveConfiguration(policy, additionalFiles, activeConfiguration);
            }

            return policy;
        }

        AdditionalText? legacyConfiguration = FindAdditionalFile(additionalFiles, LegacyConfigurationFileName);
        if (legacyConfiguration?.GetText() is not SourceText legacyConfigurationText)
        {
            if (legacyConfiguration is not null)
            {
                policy.AddConfigurationError($"Could not read '{legacyConfiguration.Path}'.");
            }

            return policy;
        }

        ApplyConfiguration(policy, legacyConfigurationText, legacyConfiguration.Path);
        return policy;
    }

    private static ImmutableArray<AdditionalText> FindActiveConfigurations(
        ImmutableArray<AdditionalText> additionalFiles,
        string? configurationDirectory)
    {
        if (string.IsNullOrWhiteSpace(configurationDirectory))
        {
            AdditionalText? singleActiveConfiguration = FindAdditionalFile(additionalFiles, ActiveConfigurationFileName);
            return singleActiveConfiguration is null
                ? ImmutableArray<AdditionalText>.Empty
                : ImmutableArray.Create(singleActiveConfiguration);
        }

        string currentDirectory = Path.GetFullPath(configurationDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        string? parentDirectory = Directory.GetParent(currentDirectory)?.FullName;
        var result = ImmutableArray.CreateBuilder<AdditionalText>();
        if (!string.IsNullOrWhiteSpace(parentDirectory))
        {
            AddIfPresent(result, FindAdditionalFileAtPath(additionalFiles, Path.Combine(parentDirectory, ActiveConfigurationFileName)));
        }

        AddIfPresent(result, FindAdditionalFileAtPath(additionalFiles, Path.Combine(currentDirectory, ActiveConfigurationFileName)));
        return result.ToImmutable();
    }

    private static void AddIfPresent(ImmutableArray<AdditionalText>.Builder result, AdditionalText? file)
    {
        if (file is not null)
        {
            result.Add(file);
        }
    }

    private static void LoadActiveConfiguration(
        BuildGatePolicy policy,
        ImmutableArray<AdditionalText> additionalFiles,
        AdditionalText activeConfiguration)
    {
        if (activeConfiguration.GetText() is not SourceText activeConfigurationText)
        {
            policy.AddConfigurationError($"Could not read '{activeConfiguration.Path}'.");
            return;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(activeConfigurationText.ToString());
            if (document.RootElement.ValueKind != JsonValueKind.Object)
            {
                policy.AddConfigurationError($"'{activeConfiguration.Path}' must contain a JSON object.");
                return;
            }

            foreach (JsonProperty configurationReference in document.RootElement.EnumerateObject())
            {
                if (configurationReference.Value.ValueKind != JsonValueKind.String ||
                    string.IsNullOrWhiteSpace(configurationReference.Value.GetString()))
                {
                    policy.AddConfigurationError($"'{activeConfiguration.Path}' entry '{configurationReference.Name}' must name a configuration file.");
                    continue;
                }

                string configurationPath = Path.Combine(
                    Path.GetDirectoryName(activeConfiguration.Path) ?? string.Empty,
                    configurationReference.Value.GetString()!);
                AdditionalText? configurationFile = FindAdditionalFileAtPath(
                    additionalFiles,
                    configurationPath);
                if (configurationFile?.GetText() is SourceText configurationText)
                {
                    ApplyConfiguration(policy, configurationText, configurationFile.Path);
                }
                else
                {
                    policy.AddConfigurationError($"'{activeConfiguration.Path}' references unreadable or missing configuration file '{configurationPath}'.");
                }
            }
        }
        catch (JsonException exception)
        {
            policy.AddConfigurationError($"Could not parse '{activeConfiguration.Path}': {exception.Message}");
        }

    }

    private static AdditionalText? FindAdditionalFile(
        ImmutableArray<AdditionalText> additionalFiles,
        string fileName) =>
        additionalFiles.FirstOrDefault(file =>
            string.Equals(Path.GetFileName(file.Path), fileName, StringComparison.OrdinalIgnoreCase));

    private static AdditionalText? FindAdditionalFileAtPath(
        ImmutableArray<AdditionalText> additionalFiles,
        string path)
    {
        string expectedPath = Path.GetFullPath(path);
        return additionalFiles.FirstOrDefault(file =>
            string.Equals(Path.GetFullPath(file.Path), expectedPath, StringComparison.OrdinalIgnoreCase));
    }

    private static void ApplyConfiguration(BuildGatePolicy policy, SourceText configurationText, string sourcePath)
    {
        try
        {
            using JsonDocument document = JsonDocument.Parse(configurationText.ToString());
            JsonElement root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                policy.AddConfigurationError($"'{sourcePath}' must contain a JSON object.");
                return;
            }

            MergeString(policy, root, "memberPrefix", sourcePath, value => policy.MemberPrefix = value);
            MergeBoolean(policy, root, "constFieldsExmptMemberPrefix", sourcePath, value => policy.ConstFieldsExmptMemberPrefix = value);
            MergeBoolean(policy, root, "konstantsInUpperCase", sourcePath, value => policy.KonstantsInUpperCase = value);
            MergeString(policy, root, "nullJustificationPrefix", sourcePath, value => policy.NullJustificationPrefix = value);
            MergePositiveInteger(policy, root, "minimumNullJustificationCharacters", sourcePath, value => policy.MinimumNullJustificationCharacters = value);
            MergePositiveInteger(policy, root, "minimumNoValueDescriptionCharacters", sourcePath, value => policy.MinimumNoValueDescriptionCharacters = value);
            MergeBoolean(policy, root, "forbidStaticVirtualInterfaceMembers", sourcePath, value => policy.ForbidStaticVirtualInterfaceMembers = value);
            MergeBoolean(policy, root, "requireBlocksForControlFlow", sourcePath, value => policy.RequireBlocksForControlFlow = value);
            MergeBoolean(policy, root, "onePublicClassPerFile", sourcePath, value => policy.OnePublicClassPerFile = value);
            MergeBoolean(policy, root, "allowGroupingOfCompleteClassHierarchies", sourcePath, value => policy.AllowGroupingOfCompleteClassHierarchies = value);
            MergeBoolean(policy, root, "allowAttributeClassesToShareFile", sourcePath, value => policy.AllowAttributeClassesToShareFile = value);
            MergeBoolean(policy, root, "banComparingBoolValueToLiteral", sourcePath, value => policy.BanComparingBoolValueToLiteral = value);
            MergeBoolean(policy, root, "forbidLockKeyword", sourcePath, value => policy.ForbidLockKeyword = value);
            MergeBoolean(policy, root, "forbidHttpRequestBodyAccess", sourcePath, value => policy.ForbidHttpRequestBodyAccess = value);
            MergeBoolean(policy, root, "requireObviousVarType", sourcePath, value => policy.RequireObviousVarType = value);
            MergeBoolean(policy, root, "requireValidatedControllerRouteArguments", sourcePath, value => policy.RequireValidatedControllerRouteArguments = value);
            MergeBoolean(policy, root, "requireDenyByDefaultRouteAuthorization", sourcePath, value => policy.RequireDenyByDefaultRouteAuthorization = value);
            MergeBoolean(policy, root, "requireExplicitControllerRouteAuthorization", sourcePath, value => policy.RequireExplicitControllerRouteAuthorization = value);
            MergeString(policy, root, "staticVirtualJustificationPrefix", sourcePath, value => policy.StaticVirtualJustificationPrefix = value);
            MergePositiveInteger(policy, root, "minimumStaticVirtualJustificationCharacters", sourcePath, value => policy.MinimumStaticVirtualJustificationCharacters = value);
            if (root.TryGetProperty("forbiddenMethods", out _))
            {
                MergeForbiddenMethods(policy, ReadForbiddenMethods(root), sourcePath);
            }

            if (root.TryGetProperty("nullabilityExemptions", out _))
            {
                MergeGlobalAllowNullAssignments(policy, ReadGlobalAllowNullAssignments(root), sourcePath);
            }
        }
        catch (JsonException exception)
        {
            policy.AddConfigurationError($"Could not parse '{sourcePath}': {exception.Message}");
        }
    }

    private static void MergeString(BuildGatePolicy policy, JsonElement root, string propertyName, string sourcePath, Action<string> setValue)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String && value.GetString() is string stringValue)
        {
            MergeScalar(policy, propertyName, value.GetRawText(), sourcePath, () => setValue(stringValue));
        }
    }

    private static void MergePositiveInteger(BuildGatePolicy policy, JsonElement root, string propertyName, string sourcePath, Action<int> setValue)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value) && value.TryGetInt32(out int integerValue) && integerValue > 0)
        {
            MergeScalar(policy, propertyName, value.GetRawText(), sourcePath, () => setValue(integerValue));
        }
    }

    private static void MergeBoolean(BuildGatePolicy policy, JsonElement root, string propertyName, string sourcePath, Action<bool> setValue)
    {
        if (root.TryGetProperty(propertyName, out JsonElement value) && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
        {
            MergeScalar(policy, propertyName, value.GetRawText(), sourcePath, () => setValue(value.GetBoolean()));
        }
    }

    private static void MergeScalar(BuildGatePolicy policy, string propertyName, string value, string sourcePath, Action setValue)
    {
        if (policy.configuredScalarValues.TryGetValue(propertyName, out string? existingValue))
        {
            if (!string.Equals(existingValue, value, StringComparison.Ordinal))
            {
                policy.configurationConflicts.Add($"'{propertyName}' has incompatible values; '{sourcePath}' cannot override a parent or earlier configuration.");
            }

            return;
        }

        policy.configuredScalarValues.Add(propertyName, value);
        setValue();
    }

    private static void MergeForbiddenMethods(BuildGatePolicy policy, ImmutableArray<ForbiddenMethodPolicy> additions, string sourcePath)
    {
        var merged = policy.ForbiddenMethods.ToBuilder();
        foreach (ForbiddenMethodPolicy addition in additions)
        {
            ForbiddenMethodPolicy? existing = merged.FirstOrDefault(item =>
                string.Equals(item.ContainingType, addition.ContainingType, StringComparison.Ordinal) &&
                string.Equals(item.Method, addition.Method, StringComparison.Ordinal));
            if (existing is null)
            {
                merged.Add(addition);
            }
            else if (!string.Equals(existing.Message, addition.Message, StringComparison.Ordinal) || existing.IncludeSubclasses != addition.IncludeSubclasses)
            {
                policy.configurationConflicts.Add($"forbiddenMethods rule '{addition.ContainingType}.{addition.Method}' in '{sourcePath}' conflicts with an earlier rule.");
            }
        }

        policy.ForbiddenMethods = merged.ToImmutable();
    }

    private static void MergeGlobalAllowNullAssignments(BuildGatePolicy policy, ImmutableArray<GlobalAllowNullAssignmentPolicy> additions, string sourcePath)
    {
        var merged = policy.GlobalAllowNullAssignments.ToBuilder();
        foreach (GlobalAllowNullAssignmentPolicy addition in additions)
        {
            GlobalAllowNullAssignmentPolicy? existing = merged.FirstOrDefault(item => item.SelectorEquals(addition));
            if (existing is null)
            {
                merged.Add(addition);
            }
            else if (!string.Equals(existing.Justification, addition.Justification, StringComparison.Ordinal))
            {
                policy.configurationConflicts.Add($"nullabilityExemptions rule in '{sourcePath}' conflicts with an earlier rule for the same assignment context.");
            }
        }

        policy.GlobalAllowNullAssignments = merged.ToImmutable();
    }

    public ImmutableArray<string> NullJustificationMarkers => ImmutableArray.Create(
        NormalizeCommentMarker(NullJustificationPrefix),
        DefaultNullJustificationMarker,
        LegacyNullJustificationMarker);

    public bool UsesLegacyNullMarker(string marker) =>
        string.Equals(marker, LegacyNullJustificationMarker, StringComparison.Ordinal);

    private static string NormalizeCommentMarker(string marker) => marker.Trim()
        .TrimStart('/', '*')
        .TrimEnd('/', '*')
        .Trim();

    private static string? ReadString(JsonElement root, string propertyName) =>
        root.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static int ReadPositiveInteger(JsonElement root, string propertyName, int defaultValue) =>
        root.TryGetProperty(propertyName, out JsonElement value) && value.TryGetInt32(out int number) && number > 0
            ? number
            : defaultValue;

    private static ImmutableArray<ForbiddenMethodPolicy> ReadForbiddenMethods(JsonElement root)
    {
        if (!root.TryGetProperty("forbiddenMethods", out JsonElement rules) || rules.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<ForbiddenMethodPolicy>.Empty;
        }

        var result = ImmutableArray.CreateBuilder<ForbiddenMethodPolicy>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? containingType = ReadString(rule, "containingType");
            string? method = ReadString(rule, "method");
            string? message = ReadString(rule, "message");
            if (string.IsNullOrWhiteSpace(containingType) || string.IsNullOrWhiteSpace(method) || string.IsNullOrWhiteSpace(message))
            {
                continue;
            }

            bool includeSubclasses = rule.TryGetProperty("includeSubclasses", out JsonElement includeValue) && includeValue.ValueKind == JsonValueKind.True;
            result.Add(new ForbiddenMethodPolicy(containingType!, method!, message!, includeSubclasses));
        }

        return result.ToImmutable();
    }

    private static ImmutableArray<GlobalAllowNullAssignmentPolicy> ReadGlobalAllowNullAssignments(JsonElement root)
    {
        if (!root.TryGetProperty("nullabilityExemptions", out JsonElement rules) || rules.ValueKind != JsonValueKind.Array)
        {
            return ImmutableArray<GlobalAllowNullAssignmentPolicy>.Empty;
        }

        var result = ImmutableArray.CreateBuilder<GlobalAllowNullAssignmentPolicy>();
        foreach (JsonElement rule in rules.EnumerateArray())
        {
            string? typeAssignedTo = ReadString(rule, "typeAssignedTo");
            string? methodName = ReadString(rule, "methodName");
            string? methodNamePrefix = ReadString(rule, "methodNamePrefix");
            string? justification = ReadString(rule, "justification");
            if ((string.IsNullOrWhiteSpace(typeAssignedTo) && string.IsNullOrWhiteSpace(methodName) && string.IsNullOrWhiteSpace(methodNamePrefix)) ||
                string.IsNullOrWhiteSpace(justification))
            {
                continue;
            }

            bool asDefaultArg = rule.TryGetProperty("asDefaultArg", out JsonElement defaultArg) && defaultArg.ValueKind == JsonValueKind.True;
            bool asReturned = rule.TryGetProperty("asReturned", out JsonElement returned) && returned.ValueKind == JsonValueKind.True;
            bool asOutValue = rule.TryGetProperty("asOutValue", out JsonElement outValue) && outValue.ValueKind == JsonValueKind.True;
            bool asNullableFirstArgument = rule.TryGetProperty("asNullableFirstArgument", out JsonElement nullableFirstArgument) && nullableFirstArgument.ValueKind == JsonValueKind.True;
            result.Add(new GlobalAllowNullAssignmentPolicy(typeAssignedTo, methodName, methodNamePrefix, justification!, asDefaultArg, asReturned, asOutValue, asNullableFirstArgument));
        }

        return result.ToImmutable();
    }

    public bool AllowsNullableFirstArgument(IParameterSymbol firstParameter, IMethodSymbol method) =>
        GlobalAllowNullAssignments.Any(rule => rule.AllowsNullableFirstArgument(firstParameter.Type, method));

    public bool AllowsNullAssignment(SyntaxNodeAnalysisContext context)
    {
        if (context.Node.Parent?.Parent is ParameterSyntax parameter &&
            parameter.Default?.Value == context.Node &&
            context.SemanticModel.GetDeclaredSymbol(parameter, context.CancellationToken) is IParameterSymbol parameterSymbol)
        {
            return GlobalAllowNullAssignments.Any(rule => rule.AllowsDefaultArgument(parameterSymbol.Type));
        }

        if (context.Node.Parent is AssignmentExpressionSyntax { Right: var assignedValue } assignment &&
            assignedValue == context.Node &&
            context.SemanticModel.GetSymbolInfo(assignment.Left, context.CancellationToken).Symbol is IParameterSymbol { RefKind: RefKind.Out } outParameter &&
            context.SemanticModel.GetEnclosingSymbol(context.Node.SpanStart, context.CancellationToken) is IMethodSymbol outMethod)
        {
            return GlobalAllowNullAssignments.Any(rule => rule.AllowsOutValue(outParameter.Type, outMethod));
        }

        if (context.Node.Ancestors().OfType<ReturnStatementSyntax>().FirstOrDefault() is not null &&
            context.SemanticModel.GetEnclosingSymbol(context.Node.SpanStart, context.CancellationToken) is IMethodSymbol methodSymbol)
        {
            return GlobalAllowNullAssignments.Any(rule => rule.AllowsReturned(methodSymbol));
        }

        if (context.Node.Ancestors().OfType<ArrowExpressionClauseSyntax>().FirstOrDefault() is { Parent: MethodDeclarationSyntax method })
        {
            return context.SemanticModel.GetDeclaredSymbol(method, context.CancellationToken) is IMethodSymbol arrowMethodSymbol &&
                GlobalAllowNullAssignments.Any(rule => rule.AllowsReturned(arrowMethodSymbol));
        }

        return false;
    }
}

internal sealed class GlobalAllowNullAssignmentPolicy
{
    public GlobalAllowNullAssignmentPolicy(string? typeAssignedTo, string? methodName, string? methodNamePrefix, string justification, bool asDefaultArg, bool asReturned, bool asOutValue, bool asNullableFirstArgument)
    {
        TypeAssignedTo = typeAssignedTo;
        MethodName = methodName;
        MethodNamePrefix = methodNamePrefix;
        Justification = justification;
        AsDefaultArg = asDefaultArg;
        AsReturned = asReturned;
        AsOutValue = asOutValue;
        AsNullableFirstArgument = asNullableFirstArgument;
    }

    public string? TypeAssignedTo { get; }
    public string? MethodName { get; }
    public string? MethodNamePrefix { get; }
    public string Justification { get; }
    public bool AsDefaultArg { get; }
    public bool AsReturned { get; }
    public bool AsOutValue { get; }
    public bool AsNullableFirstArgument { get; }

    public bool AllowsDefaultArgument(ITypeSymbol candidate) =>
        AsDefaultArg && MatchesType(candidate);

    public bool AllowsReturned(IMethodSymbol method) =>
        AsReturned && IsNullableReturn(method) && MatchesType(method.ReturnType) && MatchesMethod(method);

    public bool AllowsOutValue(ITypeSymbol valueType, IMethodSymbol method) =>
        AsOutValue && MatchesType(valueType) && MatchesMethod(method);

    public bool AllowsNullableFirstArgument(ITypeSymbol valueType, IMethodSymbol method) =>
        AsNullableFirstArgument && MatchesType(valueType) && MatchesMethod(method);

    public bool SelectorEquals(GlobalAllowNullAssignmentPolicy other) =>
        string.Equals(TypeAssignedTo, other.TypeAssignedTo, StringComparison.Ordinal) &&
        string.Equals(MethodName, other.MethodName, StringComparison.Ordinal) &&
        string.Equals(MethodNamePrefix, other.MethodNamePrefix, StringComparison.Ordinal) &&
        AsDefaultArg == other.AsDefaultArg &&
        AsReturned == other.AsReturned &&
        AsOutValue == other.AsOutValue &&
        AsNullableFirstArgument == other.AsNullableFirstArgument;

    private bool MatchesType(ITypeSymbol candidate) =>
        string.IsNullOrWhiteSpace(TypeAssignedTo) || GlobMatches(candidate.ToDisplayString().TrimEnd('?'), TypeAssignedTo!);

    private bool MatchesMethod(IMethodSymbol candidate) =>
        (string.IsNullOrWhiteSpace(MethodName) || string.Equals(candidate.Name, MethodName, StringComparison.Ordinal)) &&
        (string.IsNullOrWhiteSpace(MethodNamePrefix) || candidate.Name.StartsWith(MethodNamePrefix, StringComparison.Ordinal));

    private static bool IsNullableReturn(IMethodSymbol method) =>
        method.ReturnNullableAnnotation == NullableAnnotation.Annotated ||
        method.ReturnType is INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T };

    private static bool GlobMatches(string value, string pattern)
    {
        string[] parts = pattern.Split('*');
        if (parts.Length == 1)
        {
            return string.Equals(value, pattern, StringComparison.Ordinal);
        }

        int offset = 0;
        if (!pattern.StartsWith("*", StringComparison.Ordinal) && !value.StartsWith(parts[0], StringComparison.Ordinal))
        {
            return false;
        }

        foreach (string part in parts)
        {
            if (part.Length == 0)
            {
                continue;
            }

            int foundAt = value.IndexOf(part, offset, StringComparison.Ordinal);
            if (foundAt < 0)
            {
                return false;
            }

            offset = foundAt + part.Length;
        }

        return pattern.EndsWith("*", StringComparison.Ordinal) || offset == value.Length;
    }
}

internal sealed class ForbiddenMethodPolicy
{
    public ForbiddenMethodPolicy(string containingType, string method, string message, bool includeSubclasses)
    {
        ContainingType = containingType;
        Method = method;
        Message = message;
        IncludeSubclasses = includeSubclasses;
    }

    public string ContainingType { get; }
    public string Method { get; }
    public string Message { get; }
    public bool IncludeSubclasses { get; }

    public bool Matches(IMethodSymbol candidate) =>
        string.Equals(candidate.Name, Method, StringComparison.Ordinal) && MatchesType(candidate.ContainingType);

    private bool MatchesType(INamedTypeSymbol? candidate)
    {
        for (INamedTypeSymbol? current = candidate; current is not null; current = IncludeSubclasses ? current.BaseType : null)
        {
            if (string.Equals(current.ToDisplayString(), ContainingType, StringComparison.Ordinal))
            {
                return true;
            }

            if (!IncludeSubclasses)
            {
                return false;
            }
        }

        return IncludeSubclasses && candidate?.AllInterfaces.Any(@interface =>
            string.Equals(@interface.ToDisplayString(), ContainingType, StringComparison.Ordinal)) is true;
    }
}
