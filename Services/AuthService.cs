using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AutoMapper;
using IdentityAppV2.Configuration;
using IdentityAppV2.Data;
using IdentityAppV2.DTOs;
using IdentityAppV2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAppV2.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ApplicationDbContext _context;
    private readonly IMapper _mapper;
    private readonly JwtSettings _jwtSettings;
    private readonly ILogger<AuthService> _logger;
    private readonly IExternalAuthService _externalAuthService;
    private readonly ISamlAuthService _samlAuthService;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        ApplicationDbContext context,
        IMapper mapper,
        IOptions<JwtSettings> jwtSettings,
        ILogger<AuthService> logger,
        IExternalAuthService externalAuthService,
        ISamlAuthService samlAuthService)
    {
        _userManager = userManager;
        _context = context;
        _mapper = mapper;
        _jwtSettings = jwtSettings.Value;
        _logger = logger;
        _externalAuthService = externalAuthService;
        _samlAuthService = samlAuthService;
    }

    public async Task<TokenResponse> LoginAsync(LoginRequest request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null || !await _userManager.CheckPasswordAsync(user, request.Password))
        {
            throw new UnauthorizedAccessException("Invalid email or password");
        }

        if (!user.IsActive)
        {
            throw new UnauthorizedAccessException("Account is deactivated");
        }

        // Update last login
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return await GenerateTokenResponseAsync(user, request.ApplicationId);
    }

    public async Task<string> InitiateExternalLoginAsync(ExternalLoginRequest request)
    {
        var state = GenerateState();
        var redirectUrl = await _externalAuthService.GenerateAuthorizationUrlAsync(request.Provider, state);
        
        // Store state for validation
        // In a real implementation, you might want to store this in a distributed cache
        return redirectUrl;
    }

    public async Task<TokenResponse> ProcessExternalCallbackAsync(string code, string state)
    {
        // Validate state (in real implementation, retrieve from cache)
        var userInfo = await _externalAuthService.ExchangeCodeForUserInfoAsync(code);
        
        var user = await GetOrCreateExternalUserAsync(userInfo);
        
        // Update last login
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return await GenerateTokenResponseAsync(user, null);
    }

    public async Task<TokenResponse> ProcessSamlCallbackAsync(System.Security.Claims.ClaimsPrincipal claimsPrincipal)
    {
        // Validate SAML response
        if (!_samlAuthService.ValidateSamlResponse(claimsPrincipal))
        {
            throw new UnauthorizedAccessException("Invalid SAML response");
        }

        var userInfo = await _samlAuthService.ProcessSamlResponseAsync(claimsPrincipal);
        var user = await GetOrCreateExternalUserAsync(userInfo);
        
        // Update last login
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return await GenerateTokenResponseAsync(user, null);
    }

    public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
    {
        var tokenMap = await _context.UserTokenMaps
            .Include(t => t.User)
            .Include(t => t.Application)
            .FirstOrDefaultAsync(t => t.RefreshToken == refreshToken && !t.IsRevoked);

        if (tokenMap == null || tokenMap.ExpiresAt < DateTime.UtcNow)
        {
            throw new UnauthorizedAccessException("Invalid or expired refresh token");
        }

        return await GenerateTokenResponseAsync(tokenMap.User, tokenMap.ApplicationId);
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        var tokenMap = await _context.UserTokenMaps
            .FirstOrDefaultAsync(t => t.AccessToken == token || t.RefreshToken == token);

        if (tokenMap != null)
        {
            tokenMap.IsRevoked = true;
            tokenMap.RevokedAt = DateTime.UtcNow;
            await _context.SaveChangesAsync();
            return true;
        }

        return false;
    }

    public async Task<UserInfoResponse> GetUserInfoAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new ArgumentException("User not found");
        }

        var userInfo = _mapper.Map<UserInfoResponse>(user);
        
        // Get additional claims
        var claims = await _userManager.GetClaimsAsync(user);
        userInfo.Claims = claims.ToDictionary(c => c.Type, c => (object)c.Value);

        return userInfo;
    }

    public async Task<bool> ValidateTokenAsync(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);

            tokenHandler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidateAudience = true,
                ValidAudience = _jwtSettings.Audience,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out SecurityToken validatedToken);

            return true;
        }
        catch
        {
            return false;
        }
    }

    public async Task CleanupExpiredTokensAsync()
    {
        var expiredTokens = await _context.UserTokenMaps
            .Where(t => t.ExpiresAt < DateTime.UtcNow || t.IsRevoked)
            .ToListAsync();

        _context.UserTokenMaps.RemoveRange(expiredTokens);
        await _context.SaveChangesAsync();

        _logger.LogInformation("Cleaned up {Count} expired tokens", expiredTokens.Count);
    }

    private async Task<TokenResponse> GenerateTokenResponseAsync(ApplicationUser user, int? applicationId)
    {
        var claims = await GetUserClaimsAsync(user);
        var accessToken = GenerateJwtToken(claims);
        var refreshToken = GenerateRefreshToken();
        var expiresAt = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes);

        // Store token in database
        var tokenMap = new UserTokenMap
        {
            UserId = user.Id,
            ApplicationId = applicationId ?? 1, // Default application
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = expiresAt,
            Claims = System.Text.Json.JsonSerializer.Serialize(claims)
        };

        _context.UserTokenMaps.Add(tokenMap);
        await _context.SaveChangesAsync();

        return new TokenResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresIn = _jwtSettings.AccessTokenExpirationMinutes * 60,
            ExpiresAt = expiresAt,
            Claims = claims
        };
    }

    private async Task<Dictionary<string, object>> GetUserClaimsAsync(ApplicationUser user)
    {
        var claims = new Dictionary<string, object>
        {
            { ClaimTypes.NameIdentifier, user.Id },
            { ClaimTypes.Email, user.Email! },
            { ClaimTypes.Name, user.FullName },
            { "sub", user.Id },
            { "email", user.Email! },
            { "name", user.FullName },
            { "email_verified", user.EmailConfirmed },
            { "created_at", user.CreatedAt }
        };

        // Add custom claims
        var userClaims = await _userManager.GetClaimsAsync(user);
        foreach (var claim in userClaims)
        {
            claims[claim.Type] = claim.Value;
        }

        return claims;
    }

    private string GenerateJwtToken(Dictionary<string, object> claims)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_jwtSettings.SecretKey);

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims.Select(c => new Claim(c.Key, c.Value.ToString()!))),
            Expires = DateTime.UtcNow.AddMinutes(_jwtSettings.AccessTokenExpirationMinutes),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private string GenerateState()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    private async Task<ApplicationUser> GetOrCreateExternalUserAsync(ExternalUserInfo userInfo)
    {
        var user = await _userManager.FindByEmailAsync(userInfo.Email);
        
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = userInfo.Email,
                Email = userInfo.Email,
                FirstName = userInfo.FirstName,
                LastName = userInfo.LastName,
                ExternalId = userInfo.ExternalId,
                ExternalProvider = userInfo.Provider,
                EmailConfirmed = true,
                IsActive = true
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                throw new InvalidOperationException($"Failed to create user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
            }
        }

        return user;
    }
} 