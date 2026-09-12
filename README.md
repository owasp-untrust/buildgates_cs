# BuildGates for C#

Owasp.Untrust.BuildGates is a Roslyn analyzer package. Referencing it makes normal C# compilation enforce the configured build gates; a diagnostic has Error severity, so dotnet build fails on a violation.

## Included gates

- UBG001: every null literal needs an immediately preceding reviewed comment.
- UBG002: every member field must start with m_ (or the configured prefix).
- UBG003: configured methods are forbidden and report the policy's replacement guidance.

The analyzer is semantic for method calls: aliases, using static, and inherited methods resolve to the actual invoked symbol rather than a text match.

## Consume the package

Reference the analyzer centrally, usually in Directory.Build.props:

~~~xml
<ItemGroup>
  <PackageReference Include="Owasp.Untrust.BuildGates" Version="0.1.0" PrivateAssets="all" />
  <AdditionalFiles Include="$(MSBuildThisFileDirectory)buildgates.json" />
</ItemGroup>
~~~

Copy buildgates.example.json to the consuming repository as buildgates.json, then tailor its policy. The policy is deliberately owned by the consuming application; it is versioned and reviewed alongside its source.

~~~json
{
  "memberPrefix": "m_",
  "minimumNullJustificationCharacters": 40,
  "forbiddenMethods": [
    {
      "containingType": "System.Console",
      "method": "WriteLine",
      "message": "Use the application's structured logger instead."
    }
  ]
}
~~~

Set includeSubclasses to true on a forbidden-method rule when calls declared on derived types should also be covered.

## Narrow null exceptions

A null literal requires the comment directly on the prior line, and its explanation must meet minimumNullJustificationCharacters:

~~~csharp
// untrust-allow-null: The external protocol explicitly uses a null sentinel for an absent optional value.
return null;
~~~

Keep exceptions narrow and explain the invariant that makes the exception safe. The analyzer does not silently suppress a broad region or a whole file.

## Build and test

~~~powershell
dotnet test BuildGates.sln
dotnet pack src/Owasp.Untrust.BuildGates/Owasp.Untrust.BuildGates.csproj
~~~

"# buildgates_cs" 
