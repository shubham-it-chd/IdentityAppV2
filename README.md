# Identity App V2

A modern ASP.NET Core Identity application built with OpenIdDict and best practices for authentication and authorization.

## Features

- **ASP.NET Core Identity** with custom user model
- **OpenIdDict** for OAuth 2.0 and OpenID Connect
- **JWT Token Management** with refresh tokens
- **External Authentication** (Okta OAuth 2.0 and native ASP.NET Core SAML integration)
<!-- - **Rate Limiting** for API protection -->
- **Comprehensive Logging** with Serilog
- **Health Checks** for monitoring
- **AutoMapper** for clean DTO mapping
- **Swagger/OpenAPI** documentation
- **CORS** support
- **Background Token Cleanup**

## Architecture

This application follows the architecture defined in the documentation:

- **Controllers**: Handle HTTP requests and responses
- **Services**: Business logic implementation
- **Data Layer**: Entity Framework Core with custom DbContext
- **Models**: Domain entities and DTOs
- **Configuration**: Settings and options classes

## Prerequisites

- .NET 8.0 SDK
- SQL Server (LocalDB for development)
- Visual Studio 2022 or VS Code

## Setup Instructions

### 1. Clone and Navigate
```bash
cd IdentityAppV2
```

### 2. Update Configuration
Edit `appsettings.json` and `appsettings.Development.json`:

- Update connection string for your database
- Configure JWT settings with a strong secret key
- Set up Okta credentials (if using OAuth external auth)
- Configure SAML settings (if using SAML external auth)

### 3. Install Dependencies
```bash
dotnet restore
```

### 4. Run Database Migrations
```bash
dotnet ef database update
```

### 5. Run the Application
```bash
dotnet run
```

The application will be available at:
- **API**: https://localhost:7001
- **Swagger UI**: https://localhost:7001 (root)

## Default Credentials

The application creates a default admin user:
- **Email**: admin@example.com
- **Password**: Admin123!

## API Endpoints

### Authentication

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "admin@example.com",
  "password": "Admin123!",
  "applicationId": 1
}
```

#### External Login (OAuth)
```http
POST /api/auth/external-login
Content-Type: application/json

{
  "provider": "okta",
  "returnUrl": "https://localhost:7002/callback"
}
```

#### SAML Login
```http
POST /api/saml/login
Content-Type: application/json

{
  "provider": "saml",
  "returnUrl": "https://localhost:7002/callback"
}
```

#### SAML Logout
```http
POST /api/saml/logout
Authorization: Bearer your-access-token
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refreshToken": "your-refresh-token"
}
```

#### Get User Info
```http
GET /api/auth/userinfo
Authorization: Bearer your-access-token
```

#### Validate Token
```http
POST /api/auth/validate
Content-Type: application/json

{
  "token": "your-access-token"
}
```

#### Revoke Token
```http
POST /api/auth/revoke
Authorization: Bearer your-access-token
Content-Type: application/json

{
  "token": "token-to-revoke"
}
```

#### Logout
```http
POST /api/auth/logout
Authorization: Bearer your-access-token
```

### Health Check
```http
GET /health
```

## Database Schema

### Core Tables
- **AspNetUsers** (ApplicationUser) - User accounts
- **AspNetRoles** - User roles
- **AspNetUserRoles** - User-role relationships
- **Applications** - OAuth client applications
- **UserTokenMaps** - JWT tokens and refresh tokens
- **UserClaims** - Additional user claims

### OpenIddict Tables
- **OpenIddictApplications** - OAuth applications
- **OpenIddictAuthorizations** - Authorization records
- **OpenIddictScopes** - OAuth scopes
- **OpenIddictTokens** - OAuth tokens

## Configuration

### JWT Settings
```json
{
  "JwtSettings": {
    "Issuer": "https://localhost:7001",
    "Audience": "https://localhost:7001",
    "SecretKey": "your-super-secret-key-with-at-least-256-bits",
    "AccessTokenExpirationMinutes": 60,
    "RefreshTokenExpirationDays": 7
  }
}
```

### External Auth (Okta OAuth & SAML)
```json
{
  "ExternalAuth": {
    "Okta": {
      "Domain": "your-okta-domain.okta.com",
      "ClientId": "your-okta-client-id",
      "ClientSecret": "your-okta-client-secret",
      "AuthorizationEndpoint": "https://your-okta-domain.okta.com/oauth2/v1/authorize",
      "TokenEndpoint": "https://your-okta-domain.okta.com/oauth2/v1/token",
      "UserInfoEndpoint": "https://your-okta-domain.okta.com/oauth2/v1/userinfo"
    },
    "Saml": {
      "EntityId": "https://localhost:7001/saml",
      "MetadataUrl": "https://your-okta-domain.okta.com/app/your-app-id/sso/saml/metadata",
      "SingleSignOnServiceUrl": "https://your-okta-domain.okta.com/app/your-app-id/sso/saml",
      "SingleLogoutServiceUrl": "https://your-okta-domain.okta.com/app/your-app-id/slo/saml",
      "X509Certificate": "base64-encoded-certificate-from-okta",
      "AssertionConsumerServiceUrl": "https://localhost:7001/api/saml/acs",
      "Issuer": "http://www.okta.com/your-issuer-id"
    }
  }
}
```

## Security Features

- **Password Requirements**: Minimum 8 characters with complexity
- **JWT Token Security**: Signed tokens with expiration
- **Refresh Token Rotation**: Secure token refresh mechanism
<!-- - **Rate Limiting**: API protection against abuse -->
- **CORS Configuration**: Cross-origin request handling
- **Input Validation**: Comprehensive request validation
- **Error Handling**: Secure error responses

## Logging

The application uses Serilog for structured logging:
- Console output for development
- File logging with daily rotation
- Structured logging with correlation IDs

## Monitoring

- **Health Checks**: Database connectivity and application health
- **Token Cleanup**: Automatic cleanup of expired tokens every 12 hours
- **Performance Monitoring**: Built-in ASP.NET Core metrics

## Development

### Adding New External Providers

1. Create a new service implementing `IExternalAuthService`
2. Register the service in `Program.cs`
3. Update the `AuthService` to handle the new provider

### Customizing User Claims

1. Modify the `GetUserClaimsAsync` method in `AuthService`
2. Add custom claims to the `ApplicationUser` model
3. Update the AutoMapper profile if needed

### Database Migrations

```bash
# Create a new migration
dotnet ef migrations add MigrationName

# Update database
dotnet ef database update
```

## Production Deployment

### Security Checklist
- [ ] Change default JWT secret key
- [ ] Configure HTTPS certificates
- [ ] Set up proper CORS policies
- [ ] Enable email confirmation
- [ ] Configure production database
- [ ] Set up monitoring and alerting
- [ ] Configure backup strategies

### Environment Variables
```bash
# Database
ConnectionStrings__DefaultConnection="Server=...;Database=...;..."

# JWT
JwtSettings__SecretKey="your-production-secret-key"

# External Auth
ExternalAuth__Okta__ClientSecret="your-okta-client-secret"
```

## SAML Configuration with Okta

### Setting up SAML with Okta

1. **Create SAML App in Okta**:
   - Go to Okta Admin Console
   - Navigate to Applications > Create App Integration
   - Choose SAML 2.0

2. **Configure SAML Settings**:
   - **Single sign on URL**: `https://localhost:7001/api/saml/acs`
   - **Audience URI (SP Entity ID)**: `https://localhost:7001/saml`
   - **Name ID format**: EmailAddress
   - **Application username**: Email
   - **Attribute Statements**: Map user attributes (firstName, lastName, email)

3. **Get Configuration from Okta**:
   - Copy the SSO URL from the "View Setup Instructions"
   - Download or copy the X.509 Certificate
   - Note the Issuer URL

4. **Update appsettings.json**:
   - Set `EntityId` to your SP Entity ID
   - Set `SingleSignOnServiceUrl` to Okta's SSO URL
   - Set `X509Certificate` to the base64-encoded certificate (optional for validation)
   - Set `Issuer` to Okta's issuer URL

5. **Get Service Provider Metadata**:
   - Access `https://localhost:7001/api/saml/metadata` to get your SP metadata
   - Use this to configure the app in Okta if needed

## Troubleshooting

### Common Issues

1. **Database Connection**: Ensure SQL Server is running and connection string is correct
2. **JWT Token Issues**: Verify secret key length (minimum 256 bits)
3. **External Auth**: Check Okta OAuth configuration and network connectivity
4. **SAML Issues**: Verify SAML certificate and URLs are correct
5. **CORS Errors**: Verify CORS policy configuration

### Logs
Check application logs for detailed error information:
- Development: Console output
- Production: File logs in `Logs/` directory

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License. 

Import-PfxCertificate -FilePath "C:\path\to\your\certificate.pfx" -CertStoreLocation Cert:\LocalMachine\My -Password (ConvertTo-SecureString "your-certificate-password" -AsPlainText -Force)

Import-PfxCertificate -FilePath "C:\path\to\your\certificate.pfx" -CertStoreLocation Cert:\CurrentUser\My -Password (ConvertTo-SecureString "your-certificate-password" -AsPlainText -Force)
