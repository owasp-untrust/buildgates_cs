using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;
using Owasp.Untrust.BuildGates;
using Xunit;

namespace Owasp.Untrust.BuildGates.Tests;

public sealed class BuildGateAnalyzerTests
{
    [Fact]
    public async Task Reports_UnjustifiedNullLiteral()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { object? m_value = null; }");
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_NullLiteralWithImmediatelyPrecedingDetailedJustification()
    {
        const string source = """
            public class Example
            {
                // untrust-allow-null: This external protocol explicitly uses a null sentinel to represent an absent optional value.
                object? m_value = null;
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_MemberFieldWithoutRequiredPrefix()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private string value = \"x\"; }");
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
    }

    [Fact]
    public async Task Reports_ConfiguredForbiddenMethodWithReplacementGuidance()
    {
        const string policy = """
            {
              "forbiddenMethods": [
                {
                  "containingType": "System.Console",
                  "method": "WriteLine",
                  "message": "Use the application's structured logger instead."
                }
              ]
            }
            """;
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { void Run() { System.Console.WriteLine(\"x\"); } }", policy);

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.ForbiddenMethodId));
        Assert.Contains("structured logger", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, string? policy = null)
    {
        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerTest",
            new[] { CSharpSyntaxTree.ParseText(source) },
            new[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Console).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.GCSettings).Assembly.Location),
            },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var options = new AnalyzerOptions(policy is null
            ? ImmutableArray<AdditionalText>.Empty
            : ImmutableArray.Create<AdditionalText>(new InMemoryAdditionalText("buildgates.json", policy)));
        CompilationWithAnalyzers analyzed = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new BuildGateAnalyzer()),
            options);
        return await analyzed.GetAnalyzerDiagnosticsAsync();
    }

    private sealed class InMemoryAdditionalText : AdditionalText
    {
        private readonly string content;

        public InMemoryAdditionalText(string path, string content)
        {
            Path = path;
            this.content = content;
        }

        public override string Path { get; }

        public override SourceText? GetText(CancellationToken cancellationToken = default) => SourceText.From(content);
    }
}
