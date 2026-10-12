namespace Owasp.Untrust.BuildGates;

public static class BuildGateDiagnosticIds
{
    public const string NullLiteral = "UBG001";
    public const string MemberPrefix = "UBG002";
    public const string ForbiddenMethod = "UBG003";
    public const string StaticVirtualInterfaceMember = "UBG004";
    public const string IsMethodContract = "UBG005";
    public const string TryMethodOutContract = "UBG006";
    public const string NullableFirstArgument = "UBG007";
    public const string ConfigurationConflict = "UBG008";
    public const string ControlFlowBlock = "UBG009";
    public const string PublicClassFile = "UBG010";
    public const string BooleanLiteralComparison = "UBG011";
    public const string LockKeyword = "UBG012";
    public const string HttpRequestBodyAccess = "UBG013";
    public const string VarTypeObviousness = "UBG014";
    public const string ConstantFieldCapitalization = "UBG018";
}
