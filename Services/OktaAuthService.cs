using System.Text;
using System.Text.Json;
using IdentityAppV2.Configuration;
using Microsoft.Extensions.Options;

namespace IdentityAppV2.Services;

public class OktaAuthService : IExternalAuthService
{
    private readonly HttpClient _httpClient;
    private readonly OktaSettings _oktaSettings;
    private readonly ILogger<OktaAuthService> _logger;

    public OktaAuthService(
        HttpClient httpClient,
        IOptions<ExternalAuthSettings> externalAuthSettings,
        ILogger<OktaAuthService> logger)
    {
        _httpClient = httpClient;
        _oktaSettings = externalAuthSettings.Value.Okta;
        _logger = logger;
    }

    public async Task<string> GenerateAuthorizationUrlAsync(string provider, string state)
    {
        if (provider.ToLower() != "okta")
        {
            throw new ArgumentException("Unsupported provider");
        }

        var queryParams = new Dictionary<string, string>
        {
            { "client_id", _oktaSettings.ClientId },
            { "response_type", "code" },
            { "scope", "openid profile email" },
            { "redirect_uri", "https://localhost:7001/api/auth/callback" },
            { "state", state }
        };

        var queryString = string.Join("&", queryParams.Select(kvp => $"{kvp.Key}={Uri.EscapeDataString(kvp.Value)}"));
        return $"{_oktaSettings.AuthorizationEndpoint}?{queryString}";
    }

    public async Task<ExternalUserInfo> ProcessSamlResponseAsync(System.Security.Claims.ClaimsPrincipal claimsPrincipal)
    {
        // This method is not used for OAuth, only for SAML
        throw new NotImplementedException("SAML processing is handled by SamlAuthService");
    }

    public async Task<ExternalUserInfo> ExchangeCodeForUserInfoAsync(string code)
    {
        try
        {
            // Exchange authorization code for access token
            var tokenRequest = new FormUrlEncodedContent(new[]
            {
                new KeyValuePair<string, string>("grant_type", "authorization_code"),
                new KeyValuePair<string, string>("client_id", _oktaSettings.ClientId),
                new KeyValuePair<string, string>("client_secret", _oktaSettings.ClientSecret),
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("redirect_uri", "https://localhost:7001/api/auth/callback")
            });

            var tokenResponse = await _httpClient.PostAsync(_oktaSettings.TokenEndpoint, tokenRequest);
            tokenResponse.EnsureSuccessStatusCode();

            var tokenContent = await tokenResponse.Content.ReadAsStringAsync();
            var tokenData = JsonSerializer.Deserialize<JsonElement>(tokenContent);

            var accessToken = tokenData.GetProperty("access_token").GetString()!;

            // Get user info using access token
            var userInfoRequest = new HttpRequestMessage(HttpMethod.Get, _oktaSettings.UserInfoEndpoint);
            userInfoRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);

            var userInfoResponse = await _httpClient.SendAsync(userInfoRequest);
            userInfoResponse.EnsureSuccessStatusCode();

            var userInfoContent = await userInfoResponse.Content.ReadAsStringAsync();
            var userInfo = JsonSerializer.Deserialize<JsonElement>(userInfoContent);

            return new ExternalUserInfo
            {
                Email = userInfo.GetProperty("email").GetString()!,
                FirstName = userInfo.GetProperty("given_name").GetString(),
                LastName = userInfo.GetProperty("family_name").GetString(),
                ExternalId = userInfo.GetProperty("sub").GetString()!,
                Provider = "Okta",
                Claims = ExtractClaims(userInfo)
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error exchanging code for user info");
            throw new InvalidOperationException("Failed to exchange authorization code for user info", ex);
        }
    }

    private Dictionary<string, object> ExtractClaims(JsonElement userInfo)
    {
        var claims = new Dictionary<string, object>();
        
        foreach (var property in userInfo.EnumerateObject())
        {
            claims[property.Name] = property.Value.ValueKind switch
            {
                JsonValueKind.String => property.Value.GetString()!,
                JsonValueKind.Number => property.Value.GetInt32(),
                JsonValueKind.True => true,
                JsonValueKind.False => false,
                _ => property.Value.ToString()
            };
        }

        return claims;
    }
} 