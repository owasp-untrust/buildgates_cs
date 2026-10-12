using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.Diagnostics;

namespace Owasp.Untrust.BuildGates;

internal static class PublicClassesPerFileEvaluator
{
    public static void Evaluate(CompilationAnalysisContext context, CodeStylePolicy policy, PublicClassesPerFileInfoCollector collector, DiagnosticDescriptor rule)
    {
        if (!policy.OnePublicClassPerFile) return;
        foreach (SyntaxTree tree in context.Compilation.SyntaxTrees)
        {
            if (string.IsNullOrWhiteSpace(tree.FilePath) || !collector.TryGetPublicClasses(tree, out var collected)) continue;
            var distinctTypes = ImmutableArray.CreateBuilder<INamedTypeSymbol>();
            foreach (INamedTypeSymbol type in collected)
                if (!distinctTypes.Any(existing => SymbolEqualityComparer.Default.Equals(existing, type))) distinctTypes.Add(type);
            ImmutableArray<INamedTypeSymbol> types = distinctTypes.GroupBy(type => type.Name, StringComparer.Ordinal).Select(group => group.OrderBy(type => type.Arity).First()).ToImmutableArray();
            if (types.IsDefaultOrEmpty || !types.Any(type => type.TypeKind == TypeKind.Class)) continue;
            string fileName = Path.GetFileNameWithoutExtension(tree.FilePath);
            if (policy.AllowAttributeClassesToShareFile && IsMainClassWithAttributeClasses(types, fileName) || IsInterfaceCompanionGrouping(types, fileName)) continue;
            INamedTypeSymbol? hierarchyBase = policy.AllowGroupingOfCompleteClassHierarchies ? FindCompleteHierarchyBase(types, context.Compilation, context.CancellationToken) : null;
            if (hierarchyBase is not null || types.Length == 1 && string.Equals(fileName, types[0].Name, StringComparison.Ordinal)) continue;
            context.ReportDiagnostic(Diagnostic.Create(rule, types[0].Locations.FirstOrDefault(location => location.IsInSource) ?? Location.None, Path.GetFileName(tree.FilePath), (hierarchyBase ?? types[0]).Name));
        }
    }

    private static bool IsMainClassWithAttributeClasses(ImmutableArray<INamedTypeSymbol> types, string fileName)
    {
        ImmutableArray<INamedTypeSymbol> nonAttributes = types.Where(type => !SharedHelpers.DerivesFromType(type, "System.Attribute")).ToImmutableArray();
        return nonAttributes.Length == 1 && types.Length > 1 && string.Equals(fileName, nonAttributes[0].Name, StringComparison.Ordinal);
    }

    private static bool IsInterfaceCompanionGrouping(ImmutableArray<INamedTypeSymbol> types, string fileName) => types.Where(type => type.TypeKind == TypeKind.Interface).Any(@interface =>
    {
        if (!@interface.Name.StartsWith("I", StringComparison.Ordinal) || @interface.Name.Length == 1) return false;
        string subject = @interface.Name.Substring(1);
        return (string.Equals(fileName, subject, StringComparison.Ordinal) || string.Equals(fileName, @interface.Name, StringComparison.Ordinal)) && types.All(type => SymbolEqualityComparer.Default.Equals(type, @interface) || type.TypeKind == TypeKind.Class && type.Name == subject && DerivesFrom(type, @interface) || type.TypeKind == TypeKind.Interface && type.Name == @interface.Name + "Factory");
    });

    private static INamedTypeSymbol? FindCompleteHierarchyBase(ImmutableArray<INamedTypeSymbol> types, Compilation compilation, CancellationToken token)
    {
        if (types.Length < 2) return null;
        ImmutableArray<INamedTypeSymbol> sourceTypes = GetSourceClasses(compilation.GlobalNamespace, token);
        foreach (INamedTypeSymbol candidate in types)
        {
            if (types.Any(type => !SymbolEqualityComparer.Default.Equals(type, candidate) && !DerivesFrom(type, candidate))) continue;
            ImmutableArray<INamedTypeSymbol> derived = sourceTypes.Where(type => DerivesFrom(type, candidate)).ToImmutableArray();
            if (derived.Length == types.Length - 1 && derived.All(type => types.Any(fileType => SymbolEqualityComparer.Default.Equals(fileType, type)))) return candidate;
        }
        return null;
    }

    private static ImmutableArray<INamedTypeSymbol> GetSourceClasses(INamespaceSymbol @namespace, CancellationToken token)
    {
        var result = ImmutableArray.CreateBuilder<INamedTypeSymbol>();
        foreach (INamedTypeSymbol type in @namespace.GetTypeMembers()) { token.ThrowIfCancellationRequested(); if (type.TypeKind == TypeKind.Class && type.Locations.Any(location => location.IsInSource)) result.Add(type); }
        foreach (INamespaceSymbol nested in @namespace.GetNamespaceMembers()) result.AddRange(GetSourceClasses(nested, token));
        return result.ToImmutable();
    }

    private static bool DerivesFrom(INamedTypeSymbol candidate, INamedTypeSymbol baseType) => baseType.TypeKind == TypeKind.Interface ? candidate.AllInterfaces.Any(@interface => SymbolEqualityComparer.Default.Equals(@interface, baseType)) : candidate.BaseType is not null && EnumerateBases(candidate.BaseType).Any(type => SymbolEqualityComparer.Default.Equals(type, baseType));
    private static IEnumerable<INamedTypeSymbol> EnumerateBases(INamedTypeSymbol type) { for (INamedTypeSymbol? current = type; current is not null; current = current.BaseType) yield return current; }
}
