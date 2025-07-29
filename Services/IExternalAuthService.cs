using IdentityAppV2.Models;

namespace IdentityAppV2.Services;

public interface IExternalAuthService
{
    Task<string> GenerateAuthorizationUrlAsync(string provider, string state);
    Task<ExternalUserInfo> ExchangeCodeForUserInfoAsync(string code);
    Task<ExternalUserInfo> ProcessSamlResponseAsync(System.Security.Claims.ClaimsPrincipal claimsPrincipal);
}

public class ExternalUserInfo
{
    public string Email { get; set; } = string.Empty;
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public string ExternalId { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;
    public Dictionary<string, object> Claims { get; set; } = new();
} 