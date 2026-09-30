# BuildGates for C#

Owasp.Untrust.BuildGates is a Roslyn analyzer package. Referencing it makes normal C# compilation enforce the configured build gates; a diagnostic has Error severity, so dotnet build fails on a violation.

## Included gates

- UBG001: every material null literal needs a reviewed no-value explanation.
- UBG002: every member field must start with m_ (or the configured prefix).
- UBG003: configured methods are forbidden and report the policy's replacement guidance.
- UBG004: static virtual interface members require a reviewed security justification.
- UBG005: methods beginning with `Is` must return `bool` and cannot declare `out` parameters; use TryXxx naming semantics for an operation that produces output, for example `TryExtract...`, `TryConvert...`, or `TryParse...`.
  When an `out` value is null for a `false` result, declare the TryParse-style
  `[MaybeNullWhen(false)]` contract.
- UBG006: a null-capable `out` parameter on a `Try...` method must declare
  `[MaybeNullWhen(false)]`; a non-nullable value-type `out` parameter must not
  declare it.
- UBG007: a method whose first argument is nullable needs a reviewed no-value
  boundary explanation. Prefer moving the null check to the caller so it does
  not call the method for null input.
- UBG008: conflicting parent/current configuration is rejected.
- UBG009: control-flow bodies must use curly-brace blocks, including one-statement bodies.
- UBG010: a public top-level class must be the sole public class in a matching file,
  except for a complete grouped class hierarchy.
- UBG011: Boolean values must not be compared with `true` or `false` literals.
- UBG012: `lock` is forbidden because it cannot coordinate a distributed system.
- UBG013: direct HTTP request-body/form access is forbidden outside a reviewed boundary.
- UBG014: `var` requires an obvious right-hand-side type.
- UBG015: controller route inputs must use VV validated values.
- UBG016: controller routes require `Program.cs` to enable deny-by-default authorization.
- UBG017: every controller route requires a method-level `[Authorize(...)]` or `[AllowAnonymous]` attribute.
- UBG004: static virtual interface members require a reviewed security justification.

The analyzer is semantic for method calls: aliases, using static, and inherited methods resolve to the actual invoked symbol rather than a text match.

## Consume the package

Reference the analyzer centrally, usually in Directory.Build.props:

~~~xml
<ItemGroup>
  <PackageReference Include="Owasp.Untrust.BuildGates" Version="0.1.0" PrivateAssets="all" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)active-buildgates.json" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)nullability-enforcement.json" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)forbidden-methods.json" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)explicitness-enforcement.json" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)code-style.json" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)untrust-libs-enforcement.json" />
</ItemGroup>
~~~

Configure the analyzer with an `active-buildgates.json` manifest and the referenced
category files. Copy the `*.example.json` files to the consuming repository, then tailor
their policy. The policy is deliberately owned by the consuming application; it is
versioned and reviewed alongside its source.

~~~json
{
  "nullability-enforcement": "nullability-enforcement.json",
  "forbidden-methods": "forbidden-methods.json",
  "explicitness-enforcement": "explicitness-enforcement.json",
  "code-style": "code-style.json",
  "untrust-libs-enforcement": "untrust-libs-enforcement.json"
}
~~~

The analyzer checks for `active-buildgates.json` in the parent configuration folder first,
then the current configuration folder. Include the parent folder's JSON files as
`AdditionalFiles` when it has a manifest. The two manifests and their referenced fragments
are merged in that order. A setting or rule that disagrees with an earlier configuration is
an error; a child configuration cannot silently override a parent policy. Set
`BuildGatesConfigurationDirectory` to the folder containing the current manifest (and add it
to `CompilerVisibleProperty`) when that folder is above the individual project directory.

Every referenced JSON file must be included as an MSBuild `AdditionalFiles` item beside
the manifest. `explicitness-enforcement.json` owns static-virtual-interface policy;
`code-style.json` owns naming and block-style conventions. A fragment owns only its category's properties,
preventing unrelated policy sections from competing for the same top-level fields. The
analyzer still accepts one legacy `buildgates.json` file when no active manifest is supplied.

Set includeSubclasses to true on a forbidden-method rule when calls declared on derived types should also be covered.

Set `memberPrefix` to an empty string when a consuming repository deliberately
enables other gates but does not adopt a field-prefix convention.

`constFieldsExmptMemberPrefix` defaults to `true`, so C# `const` and `static
readonly` fields do not need the member prefix. `konstantsInUpperCase` defaults
to `true`; it requires upper-case names for `const` fields and `static readonly`
fields initialized directly from a literal or a literal-derived `Hardcoded`
value, such as `Hardcoded("message")`.

`requireBlocksForControlFlow` defaults to `true`. Set it to `false` only for a
deliberate compatibility exception; otherwise `if`, `for`, `foreach`, `while`,
`do`, `using`, `lock`, and `fixed` bodies must use curly braces.

`onePublicClassPerFile` defaults to `true`: a source file must be named for its
single public top-level class. `allowGroupingOfCompleteClassHierarchies` also
defaults to `true`; it permits a descriptively named file to contain a public
base class and every source-defined derived class in the same compilation.
An interface may likewise head the grouping when the file contains every
source-defined implementing class.
An interface may also share a file with its same-named implementation
(`IXyz` and `Xyz : IXyz`) and its corresponding factory interface
(`IXyzFactory`) when the file is named `Xyz.cs` or `IXyz.cs`; these name-based
companion types do not need to be the complete implementation hierarchy.
`allowAttributeClassesToShareFile` also defaults to `true`; it permits a file
named for one public non-attribute class to also declare public classes derived
from `System.Attribute`.
Public classes that differ only by generic arity, such as `Value<T>` and
`Value<T, TOther>`, count as one class for this rule.
An enum is not a class for this rule and may share a file with its public class.

`banComparingBoolValueToLiteral` defaults to `true`; write `condition` or
`!condition` rather than comparing it with `true` or `false`. For nullable
identity checks, replace `User.Identity?.IsAuthenticated == true` with
`User.Identity is { IsAuthenticated: true } identity`.

`forbidLockKeyword` defaults to `true`. A lock coordinates only local threads;
use a distributed coordination mechanism when nodes must agree. The narrow
escape hatch is an immediately preceding comment beginning
`untrust-allow-local-threads-lock` followed by at least 100 characters that
explain why the local lock remains effective in the distributed system.

`forbidHttpRequestBodyAccess` defaults to `true`. It rejects
`HttpRequest.ReadFormAsync()`, `HttpRequest.Form`, `HttpRequest.Body`,
`HttpRequest.BodyReader`, and `IFormCollection`. The only escape hatch is an
immediately preceding comment such as
`// untrust-use-banned-method: HttpRequest.Body <100+-character justification>`.
The target name must exactly match the banned access and the justification must
contain at least 100 characters.

`requireObviousVarType` defaults to `true`. `var` is allowed for an explicit
creation such as `new User()` or `new List<User>()`, a literal such as `0`,
`"Yariv"`, or `true`, and an explicit cast such as `(User)obj`. Use an explicit
declared type for method/property results, target-typed `new()`, `null`, and
other expressions whose result type is not immediately visible. Static `Parse`
and `ParseValue` calls are also allowed when they return their declaring type,
for example `using var document = JsonDocument.ParseValue(ref reader);`. An
`out var` is likewise allowed for a static self-returning `TryParse`, for
example `T.TryParse(raw, provider, out var result)` when the out type is `T`.

`requireValidatedControllerRouteArguments` defaults to `true`. Every parameter
of a controller action bearing an `HttpGet`, `HttpPost`, or other HTTP-method
route attribute must derive from VV's `ValidatedValue` or `CrossValidatedValue`
base class. A DTO parameter is allowed only when each of its public instance
fields and properties is such a validated value.

`requireDenyByDefaultRouteAuthorization` and
`requireExplicitControllerRouteAuthorization` both default to `true`. When a
project has controller routes, `Program.cs` must call
`builder.EnableDenyByDefaultRouteAuthorization()` from
`Owasp.Untrust.NoOwnershipNeeded`. Each controller route must then explicitly
declare `[Authorize(...)]` or `[AllowAnonymous]` on the route method.

## Narrow null exceptions

A null literal requires a no-value explanation of at least 15 characters. Place a
`//` or one-line `/* ... */` comment directly
before it, or put a `//` comment after it on the same line:

~~~csharp
// untrust-null-represents-no-value: The external protocol explicitly uses null for an absent optional value.
return null;

ValidationIssue? issue = null; // untrust-null-represents-no-value: no issue found after all validation rules passed
~~~

For recurring, reviewed null semantics, configure an exact type allow-list. Each
context flag defaults to `false` when omitted:

~~~json
{
  "nullabilityExemptions": [
    {
      "typeAssignedTo": "System.IFormatProvider",
      "asDefaultArg": true,
      "justification": "The standard provider convention selects the ambient provider."
    },
    {
      "typeAssignedTo": "Example.ValidationIssue",
      "asReturned": true,
      "justification": "No validation issue represents a successful validation result."
    },
    {
      "methodNamePrefix": "Find",
      "asReturned": true,
      "justification": "Find operations return null when no matching value exists."
    }
  ]
}
~~~

This allow-list is context-specific: allowing an `IFormatProvider` default does
not allow returning one, and unlisted assignment contexts remain rejected.
Every allow-list entry requires a non-empty `justification` recording why its
recurring null exception is safe and remains appropriate for review.
`methodNamePrefix` matches ordinal, case-sensitive method names and only permits
explicit null returns from methods declared with a nullable return type. It can
be combined with `typeAssignedTo` to require both selectors.

Set `asOutValue` to `true` only for a reviewed method family whose `out` value
uses null as a documented result state. For example, an existing `Is...` family
can suppress the null diagnostic while UBG005 still directs its migration to a
`Try...` API.

The legacy `untrust-allow-null:` marker remains supported for compatibility and
continues to require `minimumNullJustificationCharacters` (40 by default).

Keep exceptions narrow and explain the invariant that makes the exception safe. The analyzer does not silently suppress a broad region or a whole file.

The reviewed no-value comment can justify a nullable first argument only when
null is an intentional boundary contract:

~~~csharp
// untrust-null-represents-no-value: The protocol deliberately uses an omitted query as its documented default request.
void Search(string? query) { }
~~~

Otherwise, check for null at the caller and avoid calling the method at all.

For a nullable first argument, first preserve the contract of an implemented
interface or override. Otherwise make the parameter non-nullable and establish
non-nullness at callers; do not retain null merely because the current method
can handle it. Use the shared `nullabilityExemptions` policy only as the
last resort for a reviewed boundary contract. It supports exact `methodName` or
`methodNamePrefix`, and optionally `typeAssignedTo` (exact or `*` wildcard):

~~~json
{
  "nullabilityExemptions": [
    {
      "methodName": "Equals",
      "typeAssignedTo": "object",
      "asNullableFirstArgument": true,
      "justification": "The .NET equality contract intentionally accepts a nullable peer for comparison."
    },
    {
      "methodNamePrefix": "Require",
      "asNullableFirstArgument": true,
      "justification": "Require helpers deliberately accept nullable input to reject it at one validation boundary."
    }
  ]
}
~~~

## Build and test

~~~powershell
dotnet test BuildGates.sln
dotnet pack src/Owasp.Untrust.BuildGates/Owasp.Untrust.BuildGates.csproj
~~~

"# buildgates_cs" 
