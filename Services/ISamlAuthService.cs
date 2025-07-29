using IdentityAppV2.Models;
using System.Security.Claims;

namespace IdentityAppV2.Services;

public interface ISamlAuthService
{
    Task<string> GenerateSamlRequestAsync(string returnUrl);
    Task<ExternalUserInfo> ProcessSamlResponseAsync(ClaimsPrincipal claimsPrincipal);
    Task<string> InitiateSamlLogoutAsync(string userId);
    bool ValidateSamlResponse(ClaimsPrincipal claimsPrincipal);
} 