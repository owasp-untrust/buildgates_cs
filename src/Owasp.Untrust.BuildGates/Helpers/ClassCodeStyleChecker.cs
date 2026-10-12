using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace Owasp.Untrust.BuildGates.Helpers;

internal static class ClassCodeStyleChecker
{
    public static void AnalyzeStaticVirtualInterfaceMember(
        SyntaxNodeAnalysisContext context,
        CodeStylePolicy policy,
        DiagnosticDescriptor rule)
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
        context.ReportDiagnostic(Diagnostic.Create(rule, member.GetLocation(), name, policy.MinimumStaticVirtualJustificationCharacters));
    }

    private static bool HasStaticVirtualJustification(MemberDeclarationSyntax member, CodeStylePolicy policy)
    {
        FileLinePositionSpan span = member.GetLocation().GetLineSpan();
        if (span.StartLinePosition.Line == 0)
        {
            return false;
        }

        SourceText source = member.SyntaxTree.GetText();
        string precedingLine = source.Lines[span.StartLinePosition.Line - 1].ToString().Trim();
        return SharedHelpers.HasCommentWithMarker(
            precedingLine,
            policy.StaticVirtualJustificationPrefix,
            policy.MinimumStaticVirtualJustificationCharacters);
    }
}
