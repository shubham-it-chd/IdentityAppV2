using IdentityAppV2.DTOs;
using IdentityAppV2.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace IdentityAppV2.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;

    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }

    /// <summary>
    /// Login with email and password
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult<TokenResponse>> Login([FromBody] LoginRequest request)
    {
        try
        {
            var response = await _authService.LoginAsync(request);
            _logger.LogInformation("User logged in successfully: {Email}", request.Email);
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Login failed for email: {Email}, Reason: {Reason}", request.Email, ex.Message);
            return Unauthorized(new ErrorResponse { Error = "invalid_credentials", ErrorDescription = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during login for email: {Email}", request.Email);
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Initiate external authentication (OAuth)
    /// </summary>
    [HttpPost("external-login")]
    public async Task<ActionResult<string>> ExternalLogin([FromBody] ExternalLoginRequest request)
    {
        try
        {
            var redirectUrl = await _authService.InitiateExternalLoginAsync(request);
            return Ok(new { redirectUrl });
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning("External login failed: {Provider}, Reason: {Reason}", request.Provider, ex.Message);
            return BadRequest(new ErrorResponse { Error = "invalid_provider", ErrorDescription = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during external login for provider: {Provider}", request.Provider);
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Handle OAuth callback
    /// </summary>
    [HttpGet("callback")]
    public async Task<ActionResult<TokenResponse>> Callback([FromQuery] string code, [FromQuery] string state)
    {
        try
        {
            var response = await _authService.ProcessExternalCallbackAsync(code, state);
            _logger.LogInformation("External authentication completed successfully");
            return Ok(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error processing external authentication callback");
            return BadRequest(new ErrorResponse { Error = "invalid_callback", ErrorDescription = "Failed to process authentication callback" });
        }
    }

    /// <summary>
    /// Refresh access token using refresh token
    /// </summary>
    [HttpPost("refresh")]
    public async Task<ActionResult<TokenResponse>> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var response = await _authService.RefreshTokenAsync(request.RefreshToken);
            _logger.LogInformation("Token refreshed successfully");
            return Ok(response);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogWarning("Token refresh failed: {Reason}", ex.Message);
            return Unauthorized(new ErrorResponse { Error = "invalid_refresh_token", ErrorDescription = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token refresh");
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Revoke access token or refresh token
    /// </summary>
    [HttpPost("revoke")]
    [Authorize]
    public async Task<ActionResult> RevokeToken([FromBody] RevokeTokenRequest request)
    {
        try
        {
            var success = await _authService.RevokeTokenAsync(request.Token);
            if (success)
            {
                _logger.LogInformation("Token revoked successfully");
                return Ok(new { message = "Token revoked successfully" });
            }
            else
            {
                return NotFound(new ErrorResponse { Error = "token_not_found", ErrorDescription = "Token not found or already revoked" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token revocation");
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Get current user information
    /// </summary>
    [HttpGet("userinfo")]
    [Authorize]
    public async Task<ActionResult<UserInfoResponse>> GetUserInfo()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ErrorResponse { Error = "invalid_token", ErrorDescription = "Invalid access token" });
            }

            var userInfo = await _authService.GetUserInfoAsync(userId);
            return Ok(userInfo);
        }
        catch (ArgumentException ex)
        {
            _logger.LogWarning("User info request failed: {Reason}", ex.Message);
            return NotFound(new ErrorResponse { Error = "user_not_found", ErrorDescription = ex.Message });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during user info request");
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Validate access token
    /// </summary>
    [HttpPost("validate")]
    public async Task<ActionResult> ValidateToken([FromBody] RevokeTokenRequest request)
    {
        try
        {
            var isValid = await _authService.ValidateTokenAsync(request.Token);
            return Ok(new { valid = isValid });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during token validation");
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }

    /// <summary>
    /// Logout (revoke current token)
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<ActionResult> Logout()
    {
        try
        {
            var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
            var success = await _authService.RevokeTokenAsync(token);
            
            if (success)
            {
                _logger.LogInformation("User logged out successfully");
                return Ok(new { message = "Logged out successfully" });
            }
            else
            {
                return NotFound(new ErrorResponse { Error = "token_not_found", ErrorDescription = "Token not found or already revoked" });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during logout");
            return StatusCode(500, new ErrorResponse { Error = "server_error", ErrorDescription = "An unexpected error occurred" });
        }
    }
} 