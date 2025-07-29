using IdentityAppV2.DTOs;
using IdentityAppV2.Models;

namespace IdentityAppV2.Services;

public interface IAuthService
{
    Task<TokenResponse> LoginAsync(LoginRequest request);
    Task<string> InitiateExternalLoginAsync(ExternalLoginRequest request);
    Task<TokenResponse> ProcessExternalCallbackAsync(string code, string state);
    Task<TokenResponse> ProcessSamlCallbackAsync(System.Security.Claims.ClaimsPrincipal claimsPrincipal);
    Task<TokenResponse> RefreshTokenAsync(string refreshToken);
    Task<bool> RevokeTokenAsync(string token);
    Task<UserInfoResponse> GetUserInfoAsync(string userId);
    Task<bool> ValidateTokenAsync(string token);
    Task CleanupExpiredTokensAsync();
} 