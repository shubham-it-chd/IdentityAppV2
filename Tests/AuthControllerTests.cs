// using IdentityAppV2.Controllers;
// using IdentityAppV2.DTOs;
// using IdentityAppV2.Services;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.Extensions.Logging;
// using Moq;

// namespace IdentityAppV2.Tests;

// public class AuthControllerTests
// {
//     private readonly Mock<IAuthService> _mockAuthService;
//     private readonly Mock<ILogger<AuthController>> _mockLogger;
//     private readonly AuthController _controller;

//     public AuthControllerTests()
//     {
//         _mockAuthService = new Mock<IAuthService>();
//         _mockLogger = new Mock<ILogger<AuthController>>();
//         _controller = new AuthController(_mockAuthService.Object, _mockLogger.Object);
//     }

//     [Fact]
//     public async Task Login_ValidCredentials_ReturnsOkResult()
//     {
//         // Arrange
//         var loginRequest = new LoginRequest
//         {
//             Email = "test@example.com",
//             Password = "Test123!"
//         };

//         var expectedResponse = new TokenResponse
//         {
//             AccessToken = "test-access-token",
//             RefreshToken = "test-refresh-token",
//             ExpiresIn = 3600,
//             ExpiresAt = DateTime.UtcNow.AddHours(1)
//         };

//         _mockAuthService.Setup(x => x.LoginAsync(loginRequest))
//             .ReturnsAsync(expectedResponse);

//         // Act
//         var result = await _controller.Login(loginRequest);

//         // Assert
//         var okResult = Assert.IsType<OkObjectResult>(result.Result);
//         var tokenResponse = Assert.IsType<TokenResponse>(okResult.Value);
//         Assert.Equal(expectedResponse.AccessToken, tokenResponse.AccessToken);
//         Assert.Equal(expectedResponse.RefreshToken, tokenResponse.RefreshToken);
//     }

//     [Fact]
//     public async Task Login_InvalidCredentials_ReturnsUnauthorized()
//     {
//         // Arrange
//         var loginRequest = new LoginRequest
//         {
//             Email = "test@example.com",
//             Password = "WrongPassword"
//         };

//         _mockAuthService.Setup(x => x.LoginAsync(loginRequest))
//             .ThrowsAsync(new UnauthorizedAccessException("Invalid credentials"));

//         // Act
//         var result = await _controller.Login(loginRequest);

//         // Assert
//         var unauthorizedResult = Assert.IsType<UnauthorizedObjectResult>(result.Result);
//         var errorResponse = Assert.IsType<ErrorResponse>(unauthorizedResult.Value);
//         Assert.Equal("invalid_credentials", errorResponse.Error);
//     }

//     [Fact]
//     public async Task RefreshToken_ValidToken_ReturnsOkResult()
//     {
//         // Arrange
//         var refreshRequest = new RefreshTokenRequest
//         {
//             RefreshToken = "valid-refresh-token"
//         };

//         var expectedResponse = new TokenResponse
//         {
//             AccessToken = "new-access-token",
//             RefreshToken = "new-refresh-token",
//             ExpiresIn = 3600,
//             ExpiresAt = DateTime.UtcNow.AddHours(1)
//         };

//         _mockAuthService.Setup(x => x.RefreshTokenAsync(refreshRequest.RefreshToken))
//             .ReturnsAsync(expectedResponse);

//         // Act
//         var result = await _controller.RefreshToken(refreshRequest);

//         // Assert
//         var okResult = Assert.IsType<OkObjectResult>(result.Result);
//         var tokenResponse = Assert.IsType<TokenResponse>(okResult.Value);
//         Assert.Equal(expectedResponse.AccessToken, tokenResponse.AccessToken);
//     }

//     [Fact]
//     public async Task ValidateToken_ValidToken_ReturnsOkResult()
//     {
//         // Arrange
//         var validateRequest = new RevokeTokenRequest
//         {
//             Token = "valid-token"
//         };

//         _mockAuthService.Setup(x => x.ValidateTokenAsync(validateRequest.Token))
//             .ReturnsAsync(true);

//         // Act
//         var result = await _controller.ValidateToken(validateRequest);

//         // Assert
//         var okResult = Assert.IsType<OkObjectResult>(result.Result);
//         var response = Assert.IsType<dynamic>(okResult.Value);
//         Assert.True(response.valid);
//     }
// } 