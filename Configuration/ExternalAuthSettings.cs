namespace IdentityAppV2.Configuration;

public class ExternalAuthSettings
{
    public OktaSettings Okta { get; set; } = new();
    public SamlSettings Saml { get; set; } = new();
}

public class OktaSettings
{
    public string Domain { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string AuthorizationEndpoint { get; set; } = string.Empty;
    public string TokenEndpoint { get; set; } = string.Empty;
    public string UserInfoEndpoint { get; set; } = string.Empty;
}

public class SamlSettings
{
    public string EntityId { get; set; } = string.Empty;
    public string MetadataUrl { get; set; } = string.Empty;
    public string SingleSignOnServiceUrl { get; set; } = string.Empty;
    public string SingleLogoutServiceUrl { get; set; } = string.Empty;
    public string X509Certificate { get; set; } = string.Empty;
    public string AssertionConsumerServiceUrl { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
} 