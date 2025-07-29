using System.Security.Claims;
using System.Text;
using System.Xml;
using IdentityAppV2.Configuration;
using IdentityAppV2.Models;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.Saml2;
using Microsoft.IdentityModel.Tokens.Saml2;

namespace IdentityAppV2.Services;

public class SamlAuthService : ISamlAuthService
{
    private readonly SamlSettings _samlSettings;
    private readonly ILogger<SamlAuthService> _logger;
    private readonly IConfiguration _configuration;

    public SamlAuthService(
        IOptions<ExternalAuthSettings> externalAuthSettings,
        ILogger<SamlAuthService> logger,
        IConfiguration configuration)
    {
        _samlSettings = externalAuthSettings.Value.Saml;
        _logger = logger;
        _configuration = configuration;
    }

    public async Task<string> GenerateSamlRequestAsync(string returnUrl)
    {
        try
        {
            // Generate SAML AuthnRequest
            var requestId = "_" + Guid.NewGuid().ToString();
            var issueInstant = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");
            
            var samlRequest = $@"
                <samlp:AuthnRequest 
                    xmlns:samlp=""urn:oasis:names:tc:SAML:2.0:protocol""
                    xmlns:saml=""urn:oasis:names:tc:SAML:2.0:assertion""
                    ID=""{requestId}""
                    Version=""2.0""
                    IssueInstant=""{issueInstant}""
                    Destination=""{_samlSettings.SingleSignOnServiceUrl}""
                    AssertionConsumerServiceURL=""{_samlSettings.AssertionConsumerServiceUrl}""
                    ProtocolBinding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"">
                    <saml:Issuer>{_samlSettings.EntityId}</saml:Issuer>
                    <samlp:NameIDPolicy 
                        Format=""urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress""
                        AllowCreate=""true""/>
                </samlp:AuthnRequest>";

            // Base64 encode the request
            var samlRequestBytes = Encoding.UTF8.GetBytes(samlRequest);
            using var output = new MemoryStream();
            using var deflateStream = new System.IO.Compression.DeflateStream(output, System.IO.Compression.CompressionMode.Compress);
            deflateStream.Write(samlRequestBytes, 0, samlRequestBytes.Length);
            deflateStream.Close();
            var base64Request = Convert.ToBase64String(output.ToArray());
            
            // Build the redirect URL
            var ssoUrl = _samlSettings.SingleSignOnServiceUrl +
                        $"?SAMLRequest={Uri.EscapeDataString(base64Request)}";
            
            if (!string.IsNullOrEmpty(returnUrl))
            {
                ssoUrl += $"&RelayState={Uri.EscapeDataString(returnUrl)}";
            }

            _logger.LogInformation("Generated SAML request for SSO URL: {SsoUrl}", ssoUrl);
            return await Task.FromResult(ssoUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating SAML request");
            throw new InvalidOperationException("Failed to generate SAML request", ex);
        }
    }

    public async Task<ExternalUserInfo> ProcessSamlResponseAsync(ClaimsPrincipal claimsPrincipal)
    {
        try
        {
            if (!ValidateSamlResponse(claimsPrincipal))
            {
                throw new InvalidOperationException("Invalid SAML response");
            }

            var userInfo = new ExternalUserInfo
            {
                Provider = "SAML",
                Claims = new Dictionary<string, object>()
            };

            // Extract standard claims with various possible claim types
            userInfo.Email = GetClaimValue(claimsPrincipal, ClaimTypes.Email) 
                          ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
                          ?? GetClaimValue(claimsPrincipal, "email")
                          ?? GetClaimValue(claimsPrincipal, "emailaddress")
                          ?? string.Empty;

            userInfo.FirstName = GetClaimValue(claimsPrincipal, ClaimTypes.GivenName)
                              ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname")
                              ?? GetClaimValue(claimsPrincipal, "given_name")
                              ?? GetClaimValue(claimsPrincipal, "firstName");

            userInfo.LastName = GetClaimValue(claimsPrincipal, ClaimTypes.Surname)
                             ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname")
                             ?? GetClaimValue(claimsPrincipal, "family_name")
                             ?? GetClaimValue(claimsPrincipal, "lastName");

            userInfo.ExternalId = GetClaimValue(claimsPrincipal, ClaimTypes.NameIdentifier)
                               ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
                               ?? GetClaimValue(claimsPrincipal, "sub")
                               ?? GetClaimValue(claimsPrincipal, "nameidentifier")
                               ?? userInfo.Email;

            // Extract all claims for storage
            foreach (var claim in claimsPrincipal.Claims)
            {
                userInfo.Claims[claim.Type] = claim.Value;
            }

            _logger.LogInformation("Successfully processed SAML response for user: {Email}", userInfo.Email);
            return await Task.FromResult(userInfo);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML response");
            throw new InvalidOperationException("Failed to process SAML response", ex);
        }
    }

    public async Task<string> InitiateSamlLogoutAsync(string userId)
    {
        try
        {
            // Generate SAML logout URL
            var logoutUrl = _samlSettings.SingleLogoutServiceUrl;
            
            if (string.IsNullOrEmpty(logoutUrl))
            {
                _logger.LogWarning("SAML Single Logout URL not configured");
                return string.Empty;
            }

            _logger.LogInformation("Initiated SAML logout for user: {UserId}", userId);
            return await Task.FromResult(logoutUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error initiating SAML logout for user: {UserId}", userId);
            throw new InvalidOperationException("Failed to initiate SAML logout", ex);
        }
    }

    public bool ValidateSamlResponse(ClaimsPrincipal claimsPrincipal)
    {
        try
        {
            if (claimsPrincipal?.Identity == null || !claimsPrincipal.Identity.IsAuthenticated)
            {
                _logger.LogWarning("SAML response validation failed: Principal not authenticated");
                return false;
            }

            // Check for required claims with multiple possible claim types
            var email = GetClaimValue(claimsPrincipal, ClaimTypes.Email) 
                     ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
                     ?? GetClaimValue(claimsPrincipal, "email")
                     ?? GetClaimValue(claimsPrincipal, "emailaddress");

            var nameId = GetClaimValue(claimsPrincipal, ClaimTypes.NameIdentifier)
                      ?? GetClaimValue(claimsPrincipal, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")
                      ?? GetClaimValue(claimsPrincipal, "sub")
                      ?? GetClaimValue(claimsPrincipal, "nameidentifier");

            if (string.IsNullOrEmpty(email) && string.IsNullOrEmpty(nameId))
            {
                _logger.LogWarning("SAML response validation failed: Missing required claims (email or nameidentifier)");
                return false;
            }

            // Validate issuer if configured
            if (!string.IsNullOrEmpty(_samlSettings.Issuer))
            {
                var issuer = GetClaimValue(claimsPrincipal, ClaimTypes.System)
                          ?? GetClaimValue(claimsPrincipal, "iss")
                          ?? GetClaimValue(claimsPrincipal, "issuer");
                
                if (!string.IsNullOrEmpty(issuer) && !issuer.Equals(_samlSettings.Issuer, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning("SAML response validation failed: Invalid issuer. Expected: {ExpectedIssuer}, Actual: {ActualIssuer}", 
                        _samlSettings.Issuer, issuer);
                    return false;
                }
            }

            // Additional validation for authentication time
            var authInstant = GetClaimValue(claimsPrincipal, "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant")
                           ?? GetClaimValue(claimsPrincipal, "auth_time");
            
            if (!string.IsNullOrEmpty(authInstant) && DateTime.TryParse(authInstant, out var authTime))
            {
                // Check if authentication is not too old (e.g., within last hour)
                if (authTime.AddHours(1) < DateTime.UtcNow)
                {
                    _logger.LogWarning("SAML response validation failed: Authentication too old");
                    return false;
                }
            }

            _logger.LogInformation("SAML response validation successful");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating SAML response");
            return false;
        }
    }

    private string? GetClaimValue(ClaimsPrincipal principal, string claimType)
    {
        return principal.Claims.FirstOrDefault(c => c.Type == claimType)?.Value;
    }
} 