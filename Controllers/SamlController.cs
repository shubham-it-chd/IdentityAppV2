using IdentityAppV2.DTOs;
using IdentityAppV2.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.Xml;

namespace IdentityAppV2.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SamlController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ISamlAuthService _samlAuthService;
    private readonly ILogger<SamlController> _logger;

    public SamlController(
        IAuthService authService,
        ISamlAuthService samlAuthService,
        ILogger<SamlController> logger)
    {
        _authService = authService;
        _samlAuthService = samlAuthService;
        _logger = logger;
    }

    /// <summary>
    /// Initiate SAML authentication
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult> InitiateSamlLogin([FromBody] ExternalLoginRequest request)
    {
        try
        {
            if (request.Provider.ToLower() != "saml")
            {
                return BadRequest(new ErrorResponse 
                { 
                    Error = "invalid_provider", 
                    ErrorDescription = "Only SAML provider is supported by this endpoint" 
                });
            }

            // Generate SAML request URL
            var samlUrl = await _samlAuthService.GenerateSamlRequestAsync(request.ReturnUrl ?? string.Empty);
            
            _logger.LogInformation("SAML login initiated for return URL: {ReturnUrl}", request.ReturnUrl);
            
            // Return the SAML request URL for the client to redirect to
            return Ok(new { redirectUrl = samlUrl });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error initiating SAML login");
            return StatusCode(500, new ErrorResponse 
            { 
                Error = "server_error", 
                ErrorDescription = "Failed to initiate SAML authentication" 
            });
        }
    }

    /// <summary>
    /// Handle SAML assertion consumer service (ACS) - where IdP posts the SAML response
    /// </summary>
    [HttpPost("acs")]
    [AllowAnonymous]
    public async Task<ActionResult<TokenResponse>> AssertionConsumerService([FromForm] string SAMLResponse, [FromForm] string? RelayState)
    {
        try
        {
            if (string.IsNullOrEmpty(SAMLResponse))
            {
                _logger.LogWarning("SAML ACS called without SAMLResponse");
                return BadRequest(new ErrorResponse 
                { 
                    Error = "invalid_request", 
                    ErrorDescription = "Missing SAMLResponse" 
                });
            }

            // Decode and parse the SAML response
            var samlResponseBytes = Convert.FromBase64String(SAMLResponse);
            var samlResponseXml = System.Text.Encoding.UTF8.GetString(samlResponseBytes);
            
            // Parse the SAML response to extract claims
            var claimsPrincipal = await ParseSamlResponseAsync(samlResponseXml);
            
            if (claimsPrincipal == null)
            {
                _logger.LogWarning("Failed to parse SAML response");
                return Unauthorized(new ErrorResponse 
                { 
                    Error = "authentication_failed", 
                    ErrorDescription = "Failed to parse SAML response" 
                });
            }

            // Process the SAML response and generate our JWT tokens
            var tokenResponse = await _authService.ProcessSamlCallbackAsync(claimsPrincipal);
            
            _logger.LogInformation("SAML authentication completed successfully");
            return Ok(tokenResponse);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("SAML authentication failed: {Message}", ex.Message);
            return Unauthorized(new ErrorResponse 
            { 
                Error = "authentication_failed", 
                ErrorDescription = ex.Message 
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML assertion");
            return StatusCode(500, new ErrorResponse 
            { 
                Error = "server_error", 
                ErrorDescription = "Failed to process SAML assertion" 
            });
        }
    }

    private async Task<ClaimsPrincipal?> ParseSamlResponseAsync(string samlResponseXml)
    {
        try
        {
            var doc = new System.Xml.XmlDocument();
            doc.LoadXml(samlResponseXml);

            var claims = new List<Claim>();
            var namespaceManager = new System.Xml.XmlNamespaceManager(doc.NameTable);
            namespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            namespaceManager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol");

            // Extract NameID
            var nameIdNode = doc.SelectSingleNode("//saml:NameID", namespaceManager);
            if (nameIdNode != null)
            {
                claims.Add(new Claim(ClaimTypes.NameIdentifier, nameIdNode.InnerText));
                claims.Add(new Claim(ClaimTypes.Email, nameIdNode.InnerText)); // Assuming NameID is email
            }

            // Extract attribute statements
            var attributeNodes = doc.SelectNodes("//saml:Attribute", namespaceManager);
            if (attributeNodes != null)
            {
                foreach (XmlNode attributeNode in attributeNodes)
                {
                    var attributeName = attributeNode.Attributes?["Name"]?.Value;
                    var attributeValueNode = attributeNode.SelectSingleNode("saml:AttributeValue", namespaceManager);
                    
                    if (!string.IsNullOrEmpty(attributeName) && attributeValueNode != null)
                    {
                        var claimType = MapAttributeToClaimType(attributeName);
                        claims.Add(new Claim(claimType, attributeValueNode.InnerText));
                    }
                }
            }

            if (claims.Any())
            {
                var identity = new ClaimsIdentity(claims, "SAML");
                return new ClaimsPrincipal(identity);
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error parsing SAML response XML");
            return null;
        }
    }

    private string MapAttributeToClaimType(string attributeName)
    {
        return attributeName.ToLower() switch
        {
            "email" or "emailaddress" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" => ClaimTypes.Email,
            "firstname" or "givenname" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname" => ClaimTypes.GivenName,
            "lastname" or "surname" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname" => ClaimTypes.Surname,
            "name" or "displayname" or "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name" => ClaimTypes.Name,
            _ => attributeName
        };
    }

    /// <summary>
    /// Initiate SAML logout
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<ActionResult> InitiateSamlLogout()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ErrorResponse 
                { 
                    Error = "invalid_token", 
                    ErrorDescription = "Invalid access token" 
                });
            }

            // Revoke our JWT token first
            var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
            await _authService.RevokeTokenAsync(token);

            // Get SAML logout URL
            var logoutUrl = await _samlAuthService.InitiateSamlLogoutAsync(userId);
            
            if (string.IsNullOrEmpty(logoutUrl))
            {
                // If no SAML logout URL is available, just return success
                return Ok(new { message = "Logged out successfully" });
            }

            _logger.LogInformation("SAML logout initiated for user: {UserId}", userId);
            
            // Return logout URL for client to redirect to
            return Ok(new { logoutUrl, message = "SAML logout initiated" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error initiating SAML logout");
            return StatusCode(500, new ErrorResponse 
            { 
                Error = "server_error", 
                ErrorDescription = "Failed to initiate SAML logout" 
            });
        }
    }

    /// <summary>
    /// Handle SAML single logout service (SLS)
    /// </summary>
    [HttpPost("sls")]
    [AllowAnonymous]
    public async Task<ActionResult> SingleLogoutService()
    {
        try
        {
            // For native ASP.NET Core SAML, we just return success
            // In a real implementation, you might want to implement SLO properly
            _logger.LogInformation("SAML single logout completed");
            return Ok(new { message = "Logout successful" });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing SAML single logout");
            return StatusCode(500, new ErrorResponse 
            { 
                Error = "server_error", 
                ErrorDescription = "Failed to process SAML logout" 
            });
        }
    }

    /// <summary>
    /// Get SAML metadata (for IdP configuration)
    /// </summary>
    [HttpGet("metadata")]
    [AllowAnonymous]
    public IActionResult GetMetadata()
    {
        try
        {
            // Generate SAML metadata XML for this service provider
            var entityId = Request.Scheme + "://" + Request.Host + "/saml";
            var acsUrl = Request.Scheme + "://" + Request.Host + "/api/saml/acs";
            
            var metadata = $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<md:EntityDescriptor xmlns:md=""urn:oasis:names:tc:SAML:2.0:metadata""
                     entityID=""{entityId}"">
  <md:SPSSODescriptor protocolSupportEnumeration=""urn:oasis:names:tc:SAML:2.0:protocol"">
    <md:AssertionConsumerService Binding=""urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST""
                                 Location=""{acsUrl}""
                                 index=""0"" isDefault=""true""/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>";

            return Content(metadata, "application/xml");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error generating SAML metadata");
            return StatusCode(500, new ErrorResponse 
            { 
                Error = "server_error", 
                ErrorDescription = "Failed to generate SAML metadata" 
            });
        }
    }
} 