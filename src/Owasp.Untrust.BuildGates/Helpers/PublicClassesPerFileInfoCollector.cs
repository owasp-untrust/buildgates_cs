using System.Collections.Concurrent;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

internal sealed class PublicClassesPerFileInfoCollector
{
    private readonly ConcurrentDictionary<SyntaxTree, ConcurrentBag<INamedTypeSymbol>> publicClassesByFile = new();
    public bool TryGetPublicClasses(SyntaxTree syntaxTree, out ConcurrentBag<INamedTypeSymbol> publicClasses) => publicClassesByFile.TryGetValue(syntaxTree, out publicClasses);

    public void Collect(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is not TypeDeclarationSyntax declaration ||
            declaration is RecordDeclarationSyntax record && IsSimpleRecord(record, context.SemanticModel, context.CancellationToken) ||
            context.SemanticModel.GetDeclaredSymbol(declaration, context.CancellationToken) is not INamedTypeSymbol @class ||
            @class.ContainingType is not null || @class.DeclaredAccessibility != Accessibility.Public) return;
        publicClassesByFile.GetOrAdd(context.Node.SyntaxTree, static _ => new ConcurrentBag<INamedTypeSymbol>()).Add(@class);
    }

    private static bool IsSimpleRecord(RecordDeclarationSyntax record, SemanticModel semanticModel, CancellationToken cancellationToken) => record.OpenBraceToken.RawKind == 0 || record.Members.All(member => IsStaticRecordMember(member, semanticModel, cancellationToken));
    private static bool IsStaticRecordMember(MemberDeclarationSyntax member, SemanticModel semanticModel, CancellationToken cancellationToken)
    {
        if (member is FieldDeclarationSyntax field) return field.Declaration.Variables.All(variable => semanticModel.GetDeclaredSymbol(variable, cancellationToken) is IFieldSymbol { IsStatic: true });
        return semanticModel.GetDeclaredSymbol(member, cancellationToken) switch
        {
            IMethodSymbol { IsStatic: true } => true, IPropertySymbol { IsStatic: true } => true,
            IEventSymbol { IsStatic: true } => true, INamedTypeSymbol { IsStatic: true } => true, _ => false
        };
    }
}
