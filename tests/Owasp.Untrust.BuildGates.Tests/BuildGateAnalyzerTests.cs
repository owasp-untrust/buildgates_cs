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
        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.NullLiteralId));
        Assert.Contains("nullabilityExemptions", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("end-of-line", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("untrust-allow-null", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("untrust-null-represents-no-value", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Allows_NullLiteralWithImmediatelyPrecedingDetailedJustification()
    {
        const string source = """
            public class Example
            {
                /* untrust-null-represents-no-value: This external protocol explicitly uses a null sentinel to represent no optional value. */
                object? m_value = null;
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_NullLiteralWithEndOfLineNoValueJustification()
    {
        const string source = "public class Example { object? m_value = null; // untrust-null-represents-no-value: no value was supplied by the external protocol\n }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullDefaultForIFormatProvider()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "typeAssignedTo": "System.IFormatProvider", "asDefaultArg": true, "justification": "The standard provider convention selects the ambient provider." }
              ]
            }
            """;
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { void Parse(System.IFormatProvider? provider = null) { } }", policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_ConfiguredReturnedNullForExactType()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "typeAssignedTo": "Example.ValidationIssue", "asReturned": true, "justification": "No validation issue represents a successful validation result." }
              ]
            }
            """;
        const string source = "namespace Example { public sealed class ValidationIssue { } public class Subject { public ValidationIssue? Validate() => null; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_ConfiguredReturnedNullNestedInConditionalExpression()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "typeAssignedTo": "Example.ValidationIssue", "asReturned": true, "justification": "No validation issue represents a successful validation result." }
              ]
            }
            """;
        const string source = "namespace Example { public sealed class ValidationIssue { } public class Subject { public ValidationIssue? Validate(bool valid) { return valid ? null : new ValidationIssue(); } } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullableFindReturn()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Find", "asReturned": true, "justification": "Find operations return null when no matching value exists." }
              ]
            }
            """;
        const string source = "public sealed class Item { } public class Subject { public Item? FindById() => null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_ConfiguredFindReturnForOtherMethodName()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Find", "asReturned": true, "justification": "Find operations return null when no matching value exists." }
              ]
            }
            """;
        const string source = "public sealed class Item { } public class Subject { public Item? LoadById() => null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_ConfiguredFindReturnForNonNullableReturnType()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Find", "asReturned": true, "justification": "Find operations return null when no matching value exists." }
              ]
            }
            """;
        const string source = "public sealed class Item { } public class Subject { public Item FindById() => null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_NullOutAssignmentOnTheNullableTryParseReturnPathWithoutPolicyException()
    {
        const string source = "using System.Diagnostics.CodeAnalysis; public class Example { public bool TryParse([MaybeNullWhen(false)] out string value) { value = null; return false; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_NullOutAssignmentOnTheNotNullWhenReturnPath()
    {
        const string source = "using System.Diagnostics.CodeAnalysis; public class Example { public bool TryParse([NotNullWhen(true)] out string value) { value = null; return true; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Reports_StaticVirtualInterfaceMemberWithoutSecurityJustification()
    {
        const string policy = """
            { "forbidStaticVirtualInterfaceMembers": true }
            """;
        const string source = "public interface IValue { static virtual bool IsValid(string value) => true; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.StaticVirtualInterfaceMemberId));
        Assert.Contains("cannot weaken security", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("static abstract", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Allows_IsMethodReturningBoolWithoutOutParameters()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { bool IsValid(string value) => value.Length > 0; }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.IsMethodContractId);
    }

    [Fact]
    public async Task Reports_IsMethodWithOutParameter()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { bool IsNumber(string value, out int number) { number = 0; return true; } }");

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.IsMethodContractId));
        Assert.Contains("TryXxx naming semantics", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("TryExtract", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("TryConvert", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("TryParse", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("MaybeNullWhen(false)", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.DoesNotContain("TryCast", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_IsMethodWithNonBooleanReturnType()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { int IsScore(string value) => value.Length; }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.IsMethodContractId);
    }

    [Fact]
    public async Task Reports_TryMethodWithNullableOutValueWithoutMaybeNullWhenFalse()
    {
        const string source = "#nullable enable\npublic class Example { bool TryFind(string key, out string value) { value = key; return true; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.TryMethodOutContractId);
    }

    [Fact]
    public async Task Reports_TryMethodWithNonNullableValueOutAndMaybeNullWhenFalse()
    {
        const string source = "using System.Diagnostics.CodeAnalysis; public class Example { bool TryParse(string text, [MaybeNullWhen(false)] out decimal value) { value = 0m; return false; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.TryMethodOutContractId));
        Assert.Contains("must not declare", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_NullableFirstArgumentWithoutBoundaryJustification()
    {
        const string source = "#nullable enable\npublic class Example { void Normalize(string? input) { } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.NullableFirstArgumentId));
        Assert.Contains("move the null check to the caller", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("do not call this method", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Allows_NullableFirstArgumentWithReviewedBoundaryJustification()
    {
        const string source = """
            #nullable enable
            public class Example
            {
                // untrust-null-represents-no-value: The public protocol uses an omitted first value to request its documented default behavior.
                void Normalize(string? input) { }
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullableFirstArgumentId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullableEqualsFirstArgument()
    {
        const string policy = """
            {
             "nullabilityExemptions": [
               { "methodName": "Equals", "typeAssignedTo": "object", "asNullableFirstArgument": true, "justification": "The .NET equality contract intentionally accepts a nullable peer for comparison." }
              ]
            }
            """;
        const string source = "#nullable enable\npublic sealed class Example { public bool Equals(object? other) => other is not null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullableFirstArgumentId);
    }

    [Fact]
    public async Task DoesNotAllow_ConfiguredObjectEqualsForTypedNullableEquals()
    {
        const string policy = """
            {
             "nullabilityExemptions": [
               { "methodName": "Equals", "typeAssignedTo": "object", "asNullableFirstArgument": true, "justification": "The .NET equality contract intentionally accepts a nullable peer for comparison." }
              ]
            }
            """;
        const string source = "#nullable enable\npublic sealed class Example { public bool Equals(Example? other) => other is not null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullableFirstArgumentId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullableFirstArgumentMethodPrefix()
    {
        const string policy = """
            {
             "nullabilityExemptions": [
               { "methodNamePrefix": "Require", "asNullableFirstArgument": true, "justification": "Require helpers deliberately accept nullable input to reject it at one validation boundary." }
              ]
            }
            """;
        const string source = "#nullable enable\npublic sealed class Example { public void RequirePresent(string? value) { } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullableFirstArgumentId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullableFirstArgumentForTryMethodPrefix()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Try", "asNullableFirstArgument": true, "justification": "Try helpers may accept optional input and report a false result when it cannot be used." }
              ]
            }
            """;
        const string source = "#nullable enable\npublic sealed class Example { public bool TryNormalize(string? value) => value is not null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullableFirstArgumentId);
    }

    [Fact]
    public async Task Reports_NullOutAssignmentInsideInvalidIsMethodWithoutPolicyException()
    {
        const string source = "public class Example { bool IsNumber(string value, out string result) { result = null; return false; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.IsMethodContractId);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_ConfiguredNullOutValueInsideInvalidIsMethod()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Is", "asOutValue": true, "justification": "Legacy predicates use null out values while their APIs are migrated." }
              ]
            }
            """;
        const string source = "public class Example { bool IsNumber(string value, out string result) { result = null; return false; } }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.IsMethodContractId);
        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task DoesNotAllow_GlobalNullAssignmentRuleWithoutJustification()
    {
        const string policy = """
            {
              "nullabilityExemptions": [
                { "methodNamePrefix": "Find", "asReturned": true }
              ]
            }
            """;
        const string source = "public sealed class Item { } public class Subject { public Item? FindById() => null; }";

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.NullLiteralId);
    }

    [Fact]
    public async Task Allows_StaticVirtualInterfaceMemberWithSecurityJustification()
    {
        const string policy = """
            { "forbidStaticVirtualInterfaceMembers": true }
            """;
        const string source = """
            public interface IValue
            {
                // untrust-static-virtual-is-safe: A caller-visible enforced validation rejects every implementation that does not override this default.
                static virtual bool IsValid(string value) => true;
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.StaticVirtualInterfaceMemberId);
    }

    [Fact]
    public async Task Reports_MemberFieldWithoutRequiredPrefix()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private string value = \"x\"; }");
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
    }

    [Fact]
    public async Task Allows_ConstFieldWithoutMemberPrefixButRequiresUpperCase()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private const string value = \"x\"; }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConstantFieldCapitalizationId);
    }

    [Fact]
    public async Task Requires_MemberPrefixForConstFieldWhenExemptionIsDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { private const string VALUE = \"x\"; }",
            "{ \"constFieldsExmptMemberPrefix\": false }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
    }

    [Fact]
    public async Task Allows_StaticReadonlyFieldWithoutMemberPrefix()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private static readonly object value = new object(); }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
    }

    [Fact]
    public async Task Requires_MemberPrefixForStaticReadonlyFieldWhenExemptionIsDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { private static readonly object value = new object(); }",
            "{ \"constFieldsExmptMemberPrefix\": false }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.MemberPrefixId);
    }

    [Fact]
    public async Task Requires_UpperCaseForLiteralStaticReadonlyField()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private static readonly string value = \"x\"; }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConstantFieldCapitalizationId);
    }

    [Fact]
    public async Task Requires_UpperCaseForLiteralDerivedHardcodedField()
    {
        const string source = """
            public sealed class Hardcoded { }
            public class Example
            {
                private static readonly Hardcoded message = Hardcoded("literal");
                private static Hardcoded Hardcoded(string value) => new Hardcoded();
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source);

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConstantFieldCapitalizationId);
    }

    [Fact]
    public async Task Allows_UpperCaseConstantName()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync("public class Example { private const string VALUE = \"x\"; }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConstantFieldCapitalizationId);
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

    [Fact]
    public async Task Reports_ConfiguredMinimalApiMappingMethod()
    {
        const string policy = """
            {
              "forbiddenMethods": [
                {
                  "containingType": "Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions",
                  "method": "MapGet",
                  "message": "Use an MVC controller action with explicit authorization instead."
                }
              ]
            }
            """;
        const string source = """
            namespace Microsoft.AspNetCore.Builder
            {
                public static class EndpointRouteBuilderExtensions
                {
                    public static void MapGet() { }
                }
            }

            public sealed class Example
            {
                public void Configure()
                {
                    Microsoft.AspNetCore.Builder.EndpointRouteBuilderExtensions.MapGet();
                }
            }
            """;

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(source, policy);

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.ForbiddenMethodId));
        Assert.Contains("MVC controller action", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_ForbiddenMethodConfiguredThroughActiveManifest()
    {
        const string activeConfiguration = """
            { "forbidden-methods": "forbidden-methods.json" }
            """;
        const string forbiddenMethods = """
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

        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { void Run() { System.Console.WriteLine(\"x\"); } }",
            new InMemoryAdditionalText("active-buildgates.json", activeConfiguration),
            new InMemoryAdditionalText("forbidden-methods.json", forbiddenMethods));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ForbiddenMethodId);
    }

    [Fact]
    public async Task Reports_MalformedActiveBuildGateConfiguration()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { }",
            new InMemoryAdditionalText("active-buildgates.json", "{ \"nullability-enforcement\": \"nullability-enforcement.json\", }"));

        Diagnostic diagnostic = Assert.Single(diagnostics.Where(item => item.Id == BuildGateAnalyzer.ConfigurationConflictId));
        Assert.Contains("Could not parse", diagnostic.GetMessage(), StringComparison.Ordinal);
        Assert.Contains("active-buildgates.json", diagnostic.GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Reports_MissingBuildGateConfigurationReferencedByManifest()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { }",
            new InMemoryAdditionalText("active-buildgates.json", "{ \"nullability-enforcement\": \"missing.json\" }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConfigurationConflictId);
    }

    [Fact]
    public async Task Merges_ParentAndCurrentActiveConfigurations()
    {
        string configurationDirectory = Path.GetFullPath(Path.Combine("buildgates-tests", "child"));
        string parentDirectory = Directory.GetParent(configurationDirectory)!.FullName;
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            public static class ParentApi { public static void Block() { } }
            public static class CurrentApi { public static void Block() { } }
            public class Example { void Run() { ParentApi.Block(); CurrentApi.Block(); } }
            """,
            new GlobalAnalyzerConfigOptionsProvider(configurationDirectory + Path.DirectorySeparatorChar),
            new InMemoryAdditionalText(Path.Combine(parentDirectory, "active-buildgates.json"), "{ \"parent\": \"parent.json\" }"),
            new InMemoryAdditionalText(Path.Combine(parentDirectory, "parent.json"), "{ \"forbiddenMethods\": [{ \"containingType\": \"ParentApi\", \"method\": \"Block\", \"message\": \"Parent rule.\" }] }"),
            new InMemoryAdditionalText(Path.Combine(configurationDirectory, "active-buildgates.json"), "{ \"current\": \"current.json\" }"),
            new InMemoryAdditionalText(Path.Combine(configurationDirectory, "current.json"), "{ \"forbiddenMethods\": [{ \"containingType\": \"CurrentApi\", \"method\": \"Block\", \"message\": \"Current rule.\" }] }"));

        Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Id == BuildGateAnalyzer.ForbiddenMethodId));
    }

    [Fact]
    public async Task Reports_ConflictBetweenParentAndCurrentConfigurations()
    {
        string configurationDirectory = Path.GetFullPath(Path.Combine("buildgates-tests", "child"));
        string parentDirectory = Directory.GetParent(configurationDirectory)!.FullName;
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { }",
            new GlobalAnalyzerConfigOptionsProvider(configurationDirectory),
            new InMemoryAdditionalText(Path.Combine(parentDirectory, "active-buildgates.json"), "{ \"parent\": \"parent.json\" }"),
            new InMemoryAdditionalText(Path.Combine(parentDirectory, "parent.json"), "{ \"memberPrefix\": \"m_\" }"),
            new InMemoryAdditionalText(Path.Combine(configurationDirectory, "active-buildgates.json"), "{ \"current\": \"current.json\" }"),
            new InMemoryAdditionalText(Path.Combine(configurationDirectory, "current.json"), "{ \"memberPrefix\": \"_\" }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ConfigurationConflictId);
    }

    [Fact]
    public async Task Reports_ControlFlowBodyWithoutBlockByDefault()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { void Run() { if (true) Run(); } }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ControlFlowBlockId);
    }

    [Fact]
    public async Task Allows_ControlFlowBodyWithoutBlockWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { void Run() { if (true) Run(); } }",
            "{ \"requireBlocksForControlFlow\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ControlFlowBlockId);
    }

    [Fact]
    public async Task Reports_PublicClassWhoseFileNameDoesNotMatch()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Different.cs", "public class Expected { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Reports_MultipleUnrelatedPublicClassesInOneFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("First.cs", "public class First { } public class Second { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_PublicClassesDifferingOnlyByGenericArityInOneFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Value.cs", "public class Value<T> { } public class Value<T, TOther> { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_PublicEnumToShareAFileWithItsPublicClass()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Main.cs", "public class Main { } public enum MainMode { Default }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_CompletePublicClassHierarchyInTheBaseClassFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Base.cs", "public class Base { } public class Derived : Base { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_CompletePublicInterfaceHierarchyInTheInterfaceFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("IChoice.cs", "public interface IChoice { } public class First : IChoice { } public class Second : IChoice { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_CompletePublicInterfaceHierarchyInADescriptivelyNamedFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("EntityAccessFailures.cs", "public interface IFailureDisclosure { } public class HideExistence : IFailureDisclosure { } public class RevealForbidden : IFailureDisclosure { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_InterfaceAndSameNamedImplementationToShareAFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Xyz.cs", "public interface IXyz { } public class Xyz : IXyz { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_InterfaceImplementationAndFactoryInterfaceToShareAFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("IXyz.cs", "public interface IXyz { } public interface IXyzFactory { } public class Xyz : IXyz { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Reports_UnrelatedInterfaceAlongsideSameNamedImplementation()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("XyzContracts.cs", "public interface IXyz { } public interface IOther { } public class Xyz : IXyz { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Reports_NameBasedInterfaceCompanionsInADescriptiveFile()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("XyzContracts.cs", "public interface IXyz { } public class Xyz : IXyz { } public class Other { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_AttributeClassesToShareTheMainClassFileByDefault()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("Main.cs", "public class Main { } public sealed class MainOptionAttribute : System.Attribute { } public sealed class MainOtherAttribute : System.Attribute { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Reports_AttributeClassesSharingTheMainClassFileWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            "{ \"allowAttributeClassesToShareFile\": false }",
            ("Main.cs", "public class Main { } public sealed class MainOptionAttribute : System.Attribute { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Allows_PublicClassFilePolicyToBeDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            "{ \"onePublicClassPerFile\": false }",
            ("Different.cs", "public class Expected { } public class Other { }"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.PublicClassFileId);
    }

    [Fact]
    public async Task Reports_AllBooleanLiteralComparisonsByDefault()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { bool Check(bool value) => value == true || value != true || false == value || value != false; }");

        Assert.Equal(4, diagnostics.Count(diagnostic => diagnostic.Id == BuildGateAnalyzer.BooleanLiteralComparisonId));
        Assert.Contains("User.Identity is { IsAuthenticated: true } identity", diagnostics.First(diagnostic => diagnostic.Id == BuildGateAnalyzer.BooleanLiteralComparisonId).GetMessage(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Allows_BooleanLiteralComparisonsWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { bool Check(bool value) => value == true; }",
            "{ \"banComparingBoolValueToLiteral\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.BooleanLiteralComparisonId);
    }

    [Fact]
    public async Task Reports_LockKeywordByDefault()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { private readonly object m_gate = new(); void Run() { lock (m_gate) { } } }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.LockKeywordId);
    }

    [Fact]
    public async Task Allows_LockWithDetailedLocalThreadsJustification()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            public class Example
            {
                private readonly object m_gate = new();
                void Run()
                {
                    // untrust-allow-local-threads-lock This lock only protects an in-process cache mutation; no distributed invariant, ownership decision, or cross-node state depends on it.
                    lock (m_gate) { }
                }
            }
            """);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.LockKeywordId);
    }

    [Fact]
    public async Task Allows_LockKeywordWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { private readonly object m_gate = new(); void Run() { lock (m_gate) { } } }",
            "{ \"forbidLockKeyword\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.LockKeywordId);
    }

    [Fact]
    public async Task Reports_UnsafeHttpRequestBodyAccesses()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            namespace Microsoft.AspNetCore.Http
            {
                public interface IFormCollection { }
                public class HttpRequest
                {
                    public void ReadFormAsync() { }
                    public object Form { get; }
                    public object Body { get; }
                    public object BodyReader { get; }
                }
            }
            public class Example
            {
                void Read(Microsoft.AspNetCore.Http.HttpRequest request, Microsoft.AspNetCore.Http.IFormCollection form)
                {
                    request.ReadFormAsync();
                    object first = request.Form;
                    object second = request.Body;
                    object third = request.BodyReader;
                }
            }
            """);

        Assert.Equal(5, diagnostics.Count(diagnostic => diagnostic.Id == BuildGateAnalyzer.HttpRequestBodyAccessId));
    }

    [Fact]
    public async Task Allows_HttpRequestBodyAccessWithDetailedScopedJustification()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            namespace Microsoft.AspNetCore.Http
            {
                public class HttpRequest { public object Body { get; } }
            }
            public class Example
            {
                void Read(Microsoft.AspNetCore.Http.HttpRequest request)
                {
                    // untrust-use-banned-method: HttpRequest.Body This adapter is the single reviewed compatibility boundary for a legacy streaming protocol; it validates the content length, content type, tenant ownership, and cancellation before any body bytes are consumed.
                    object body = request.Body;
                }
            }
            """);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.HttpRequestBodyAccessId);
    }

    [Fact]
    public async Task Allows_UnsafeHttpRequestBodyAccessWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            namespace Microsoft.AspNetCore.Http
            {
                public class HttpRequest { public object Body { get; } }
            }
            public class Example { void Read(Microsoft.AspNetCore.Http.HttpRequest request) { object body = request.Body; } }
            """,
            "{ \"forbidHttpRequestBodyAccess\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.HttpRequestBodyAccessId);
    }

    [Fact]
    public async Task Allows_VarWhenTypeIsObviousFromTheInitializer()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            """
            public class User { }
            public class Box<T> { }
            public class Example
            {
                void Run(object value)
                {
                    var user = new User();
                    var users = new Box<User>();
                    var count = 0;
                    var name = "Yariv";
                    var enabled = true;
                    var castUser = (User)value;
                }
            }
            """);

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Reports_VarWhenTypeComesFromAMethodCall()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class User { } public class Example { User Create() => new User(); void Run() { var user = Create(); } }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Allows_VarForStaticParseValueReturningItsDeclaringType()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public sealed class Parsed : System.IDisposable { public static Parsed ParseValue(ref int reader) => new Parsed(); public void Dispose() { } } public class Example { void Read(ref int reader) { using var document = Parsed.ParseValue(ref reader); } }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Allows_OutVarForStaticTryParseReturningItsDeclaringType()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public sealed class Parsed { public static bool TryParse(string raw, out Parsed result) { result = new Parsed(); return true; } } public class Example { bool Read(string raw) { return Parsed.TryParse(raw, out var result); } }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Reports_ForeachVarBecauseTheElementTypeIsNotExplicit()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class Example { void Run(int[] values) { foreach (var value in values) { } } }");

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Allows_NonObviousVarWhenRuleIsDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            "public class User { } public class Example { User Create() => new User(); void Run() { var user = Create(); } }",
            "{ \"requireObviousVarType\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.VarTypeObviousnessId);
    }

    [Fact]
    public async Task Reports_UnvalidatedControllerRouteArgumentsAndDtoMembers()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(ControllerRouteSource("string raw", "string Raw"));

        Assert.Equal(2, diagnostics.Count(diagnostic => diagnostic.Id == BuildGateAnalyzer.ControllerValidatedArgumentsId));
    }

    [Fact]
    public async Task Allows_ValidatedControllerRouteArgumentsAndDtoMembers()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(ControllerRouteSource("ValidatedInput raw", "ValidatedInput Raw"));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ControllerValidatedArgumentsId);
    }

    [Fact]
    public async Task Allows_UnvalidatedControllerRouteArgumentsWhenDisabled()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeAsync(
            ControllerRouteSource("string raw", "string Raw"),
            "{ \"requireValidatedControllerRouteArguments\": false }");

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ControllerValidatedArgumentsId);
    }

    [Fact]
    public async Task Reports_WhenControllerRoutesDoNotEnableDenyByDefaultAuthorizationInProgram()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("ExampleController.cs", AuthorizationRouteSource("[Microsoft.AspNetCore.Authorization.AllowAnonymous]")),
            ("Program.cs", "public sealed class Program { }"));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.DenyByDefaultRouteAuthorizationId);
    }

    [Fact]
    public async Task Allows_WhenProgramEnablesDenyByDefaultAuthorization()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("ExampleController.cs", AuthorizationRouteSource("[Microsoft.AspNetCore.Authorization.AllowAnonymous]")),
            ("Program.cs", ProgramWithDenyByDefaultAuthorizationSource()));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.DenyByDefaultRouteAuthorizationId);
    }

    [Fact]
    public async Task Reports_ControllerRouteWithoutExplicitAuthorizationAttribute()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("ExampleController.cs", AuthorizationRouteSource(string.Empty)),
            ("Program.cs", ProgramWithDenyByDefaultAuthorizationSource()));

        Assert.Contains(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ExplicitRouteAuthorizationId);
    }

    [Fact]
    public async Task Allows_ControllerRouteWithAuthorizeAttribute()
    {
        ImmutableArray<Diagnostic> diagnostics = await AnalyzeFilesAsync(
            null,
            ("ExampleController.cs", AuthorizationRouteSource("[Microsoft.AspNetCore.Authorization.Authorize]")),
            ("Program.cs", ProgramWithDenyByDefaultAuthorizationSource()));

        Assert.DoesNotContain(diagnostics, diagnostic => diagnostic.Id == BuildGateAnalyzer.ExplicitRouteAuthorizationId);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(string source, string? policy = null)
    {
        ImmutableArray<AdditionalText> additionalFiles = policy is null
            ? ImmutableArray<AdditionalText>.Empty
            : ImmutableArray.Create<AdditionalText>(new InMemoryAdditionalText("buildgates.json", policy));
        return await AnalyzeAsync(source, additionalFiles);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        string source,
        params AdditionalText[] additionalFiles)
    {
        return await AnalyzeAsync(source, additionalFiles.ToImmutableArray());
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        string source,
        AnalyzerConfigOptionsProvider analyzerConfigOptionsProvider,
        params AdditionalText[] additionalFiles)
    {
        return await AnalyzeAsync(source, additionalFiles.ToImmutableArray(), analyzerConfigOptionsProvider);
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        string source,
        ImmutableArray<AdditionalText> additionalFiles)
    {
        return await AnalyzeAsync(source, additionalFiles, new GlobalAnalyzerConfigOptionsProvider(null));
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeAsync(
        string source,
        ImmutableArray<AdditionalText> additionalFiles,
        AnalyzerConfigOptionsProvider analyzerConfigOptionsProvider)
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

        var options = new AnalyzerOptions(additionalFiles, analyzerConfigOptionsProvider);
        CompilationWithAnalyzers analyzed = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new BuildGateAnalyzer()),
            options);
        return await analyzed.GetAnalyzerDiagnosticsAsync();
    }

    private static async Task<ImmutableArray<Diagnostic>> AnalyzeFilesAsync(
        string? policy,
        params (string Path, string Source)[] sourceFiles)
    {
        ImmutableArray<AdditionalText> additionalFiles = policy is null
            ? ImmutableArray<AdditionalText>.Empty
            : ImmutableArray.Create<AdditionalText>(new InMemoryAdditionalText("buildgates.json", policy));
        CSharpCompilation compilation = CSharpCompilation.Create(
            "AnalyzerTest",
            sourceFiles.Select(file => CSharpSyntaxTree.ParseText(file.Source, path: file.Path)),
            new[]
            {
                MetadataReference.CreateFromFile(typeof(object).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Console).Assembly.Location),
                MetadataReference.CreateFromFile(typeof(System.Runtime.GCSettings).Assembly.Location),
            },
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));

        var options = new AnalyzerOptions(additionalFiles, new GlobalAnalyzerConfigOptionsProvider(null));
        CompilationWithAnalyzers analyzed = compilation.WithAnalyzers(
            ImmutableArray.Create<DiagnosticAnalyzer>(new BuildGateAnalyzer()),
            options);
        return await analyzed.GetAnalyzerDiagnosticsAsync();
    }

    private static string ControllerRouteSource(string parameter, string dtoMember) =>
        $$"""
        namespace Microsoft.AspNetCore.Mvc
        {
            public class ControllerBase { }
            public sealed class HttpGetAttribute : Routing.HttpMethodAttribute { }
        }
        namespace Microsoft.AspNetCore.Mvc.Routing
        {
            public abstract class HttpMethodAttribute : System.Attribute { }
        }
        namespace Microsoft.AspNetCore.Authorization
        {
            public sealed class AllowAnonymousAttribute : System.Attribute { }
        }
        namespace Owasp.Untrust.VV.Core
        {
            public abstract class ValidatedValue<TSelf, TValue, TDisclosure> { }
        }
        public sealed class ValidatedInput : Owasp.Untrust.VV.Core.ValidatedValue<ValidatedInput, string, object> { }
        public sealed class RequestDto
        {
            public {{dtoMember}} { get; }
        }
        public sealed class ExampleController : Microsoft.AspNetCore.Mvc.ControllerBase
        {
            [Microsoft.AspNetCore.Mvc.HttpGet]
            [Microsoft.AspNetCore.Authorization.AllowAnonymous]
            public void Read({{parameter}}, RequestDto dto) { }
        }
        """;

    private static string AuthorizationRouteSource(string authorizationAttribute) =>
        $$"""
        namespace Microsoft.AspNetCore.Mvc
        {
            public class ControllerBase { }
            public sealed class HttpGetAttribute : Routing.HttpMethodAttribute { }
        }
        namespace Microsoft.AspNetCore.Mvc.Routing
        {
            public abstract class HttpMethodAttribute : System.Attribute { }
        }
        namespace Microsoft.AspNetCore.Authorization
        {
            public sealed class AuthorizeAttribute : System.Attribute { }
            public sealed class AllowAnonymousAttribute : System.Attribute { }
        }
        public sealed class ExampleController : Microsoft.AspNetCore.Mvc.ControllerBase
        {
            [Microsoft.AspNetCore.Mvc.HttpGet]
            {{authorizationAttribute}}
            public void Read() { }
        }
        """;

    private static string ProgramWithDenyByDefaultAuthorizationSource() =>
        """
        using Owasp.Untrust.NoOwnershipNeeded;

        namespace Microsoft.AspNetCore.Builder
        {
            public sealed class WebApplicationBuilder { }
        }
        namespace Owasp.Untrust.NoOwnershipNeeded
        {
            public static class DenyByDefaultRouteAuthorization
            {
                public static void EnableDenyByDefaultRouteAuthorization(this Microsoft.AspNetCore.Builder.WebApplicationBuilder builder) { }
            }
        }
        public sealed class Program
        {
            public void Configure(Microsoft.AspNetCore.Builder.WebApplicationBuilder builder)
            {
                builder.EnableDenyByDefaultRouteAuthorization();
            }
        }
        """;

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

    private sealed class GlobalAnalyzerConfigOptionsProvider : AnalyzerConfigOptionsProvider
    {
        private static readonly AnalyzerConfigOptions Empty = new DictionaryAnalyzerConfigOptions(ImmutableDictionary<string, string>.Empty);

        public GlobalAnalyzerConfigOptionsProvider(string? configurationDirectory)
        {
            GlobalOptions = configurationDirectory is null
                ? Empty
                : new DictionaryAnalyzerConfigOptions(ImmutableDictionary<string, string>.Empty.Add("build_property.BuildGatesConfigurationDirectory", configurationDirectory));
        }

        public override AnalyzerConfigOptions GlobalOptions { get; }

        public override AnalyzerConfigOptions GetOptions(SyntaxTree tree) => Empty;

        public override AnalyzerConfigOptions GetOptions(AdditionalText textFile) => Empty;
    }

    private sealed class DictionaryAnalyzerConfigOptions : AnalyzerConfigOptions
    {
        private readonly ImmutableDictionary<string, string> values;

        public DictionaryAnalyzerConfigOptions(ImmutableDictionary<string, string> values)
        {
            this.values = values;
        }

        public override bool TryGetValue(string key, out string value) => values.TryGetValue(key, out value!);
    }
}
