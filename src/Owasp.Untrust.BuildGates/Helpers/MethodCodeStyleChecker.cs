using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates.Helpers;

internal static class MethodCodeStyleChecker
{
    public static void AnalyzeIsMethodContract(
        SyntaxNodeAnalysisContext context,
        bool enabled,
        DiagnosticDescriptor rule)
    {
        if (!enabled || context.Node is not MethodDeclarationSyntax declaration)
        {
            return;
        }

        IMethodSymbol? method = context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) as IMethodSymbol;
        if (declaration.Identifier.ValueText.StartsWith("Is", StringComparison.Ordinal) && method is not null &&
            (method.ReturnType.SpecialType != SpecialType.System_Boolean || method.Parameters.Any(parameter => parameter.RefKind == RefKind.Out)))
        {
            context.ReportDiagnostic(Diagnostic.Create(rule, declaration.Identifier.GetLocation(), method.Name));
        }
    }

    public static void AnalyzeTryMethodOutContract(
        SyntaxNodeAnalysisContext context,
        bool enabled,
        DiagnosticDescriptor rule)
    {
        if (!enabled || context.Node is not MethodDeclarationSyntax declaration ||
            !declaration.Identifier.ValueText.StartsWith("Try", StringComparison.Ordinal) ||
            context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not IMethodSymbol method)
        {
            return;
        }

        foreach (IParameterSymbol parameter in method.Parameters.Where(parameter => parameter.RefKind == RefKind.Out))
        {
            bool canRepresentNull = !(parameter.Type.IsValueType && parameter.Type is not INamedTypeSymbol { OriginalDefinition.SpecialType: SpecialType.System_Nullable_T });
            bool hasMaybeNullWhenFalse = HasMaybeNullWhenFalse(parameter);
            if (canRepresentNull && !hasMaybeNullWhenFalse)
            {
                context.ReportDiagnostic(Diagnostic.Create(rule, declaration.Identifier.GetLocation(), method.Name, parameter.Name, "can represent null and must declare [MaybeNullWhen(false)]. Add the annotation so a false result explicitly documents that the out value can be null."));
            }
            else if (!canRepresentNull && hasMaybeNullWhenFalse)
            {
                context.ReportDiagnostic(Diagnostic.Create(rule, declaration.Identifier.GetLocation(), method.Name, parameter.Name, "is a non-nullable value type and must not declare [MaybeNullWhen(false)]. Remove the annotation; false results use the type's default value, not null."));
            }
        }
    }

    private static bool HasMaybeNullWhenFalse(IParameterSymbol parameter) => parameter.GetAttributes().Any(attribute =>
        attribute.AttributeClass?.ToDisplayString() == "System.Diagnostics.CodeAnalysis.MaybeNullWhenAttribute" &&
        attribute.ConstructorArguments.Length == 1 &&
        attribute.ConstructorArguments[0].Value is false);
}
