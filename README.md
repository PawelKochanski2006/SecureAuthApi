# SecureAuthApi

A secure authentication API built with ASP.NET Core 9.0 that supports both local user authentication and LDAP/Active Directory integration with JWT token management.

## Features

- **JWT Authentication**: Secure token-based authentication with access and refresh tokens
- **LDAP Integration**: Authenticate users against LDAP/Active Directory servers
- **User Management**: ASP.NET Core Identity for local user management
- **Hybrid Authentication**: Support both local and LDAP users
- **Token Management**: Refresh token rotation with revocation support
- **Secure Storage**: AES-256 encryption for sensitive data (LDAP credentials)
- **MySQL Database**: Entity Framework Core with MySQL via Pomelo provider
- **Structured Logging**: Serilog integration for comprehensive logging

## Prerequisites

- .NET 9.0 SDK or later
- MySQL Server 5.7+ or MariaDB 10.2+
- (Optional) LDAP/Active Directory server for LDAP authentication

## Setup

### 1. Clone and Build

```pwsh
git clone <repository-url>
cd SecureAuthApi
dotnet restore
dotnet build
```

### 2. Configure Database

Update the connection string in `appsettings.json` or set environment variable:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "server=localhost;port=3306;database=secureauthdb;user=root;password=your_password"
  }
}
```

### 3. Configure Security Keys

#### Generate AES Encryption Key (PowerShell)

```pwsh
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

#### Generate JWT Secret Key

Generate a secure random string of at least 32 characters.

#### Update appsettings.json

```json
{
  "Jwt": {
    "SecretKey": "YOUR_SECURE_JWT_SECRET_KEY_HERE",
    "Issuer": "SecureAuthApi",
    "Audience": "SecureAuthApiClients",
    "AccessTokenExpirationMinutes": "15",
    "RefreshTokenExpirationDays": "7"
  },
  "Encryption": {
    "AesKey": "YOUR_BASE64_ENCODED_32_BYTE_KEY_HERE"
  }
}
```

**Important**: For production, use environment variables instead of storing keys in appsettings.json:

```pwsh
# Set environment variables
$env:Jwt__SecretKey = "your-secret-key"
$env:Encryption__AesKey = "your-base64-key"
```

### 4. Create Database and Run Migrations

```pwsh
# Create initial migration (if not exists)
dotnet ef migrations add InitialCreate

# Apply migrations to database
dotnet ef database update
```

### 5. Run the Application

```pwsh
# Development (HTTP)
dotnet run --launch-profile http

# Development (HTTPS)
dotnet run --launch-profile https

# Production
dotnet run --environment Production
```

The API will be available at:
- HTTP: http://localhost:5133
- HTTPS: https://localhost:7079

## API Endpoints

### Authentication Endpoints

#### POST /api/auth/login
Login with username/email and password.

**Request:**
```json
{
  "username": "john.doe",
  "password": "SecurePass123!",
  "rememberMe": false
}
```

**Response:**
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIs...",
  "refreshToken": "base64-encoded-token",
  "expiresAt": "2025-10-27T12:00:00Z",
  "username": "john.doe",
  "displayName": "John Doe",
  "isLdapUser": true
}
```

#### POST /api/auth/refresh
Refresh an expired access token.

**Request:**
```json
{
  "accessToken": "expired-access-token",
  "refreshToken": "valid-refresh-token"
}
```

**Response:** Same as login response with new tokens.

#### POST /api/auth/revoke
Revoke a specific refresh token (requires authentication).

**Request:**
```json
{
  "refreshToken": "token-to-revoke"
}
```

#### POST /api/auth/logout
Revoke all refresh tokens for the current user (requires authentication).

### LDAP Configuration Endpoints (Requires Authentication)

#### GET /api/ldap/config
Get all LDAP configurations.

#### POST /api/ldap/config
Create a new LDAP configuration.

**Request:**
```json
{
  "serverUrl": "ldap.example.com",
  "port": 389,
  "baseDn": "DC=example,DC=com",
  "bindDn": "CN=Service Account,OU=Users,DC=example,DC=com",
  "bindPassword": "password",
  "searchFilter": "(&(objectClass=user)(sAMAccountName={0}))",
  "useSsl": false,
  "validateCertificate": true,
  "isEnabled": true
}
```

#### PUT /api/ldap/config/{id}
Update an existing LDAP configuration.

#### DELETE /api/ldap/config/{id}
Delete an LDAP configuration.

#### POST /api/ldap/test
Test LDAP connection without saving configuration.

## Configuration Options

### JWT Settings

- **SecretKey**: Secret key for signing JWT tokens (min 32 characters)
- **Issuer**: Token issuer identifier
- **Audience**: Token audience identifier
- **AccessTokenExpirationMinutes**: Access token lifetime (default: 15 minutes)
- **RefreshTokenExpirationDays**: Refresh token lifetime (default: 7 days)

### LDAP Settings

LDAP configurations are stored in the database and can be managed via API endpoints. Each configuration includes:

- **ServerUrl**: LDAP server hostname
- **Port**: LDAP server port (389 for LDAP, 636 for LDAPS)
- **BaseDn**: Base distinguished name for searches
- **BindDn**: Service account DN for binding
- **BindPassword**: Service account password (encrypted in database)
- **SearchFilter**: LDAP search filter (use {0} as username placeholder)
- **UseSsl**: Enable SSL/TLS connection
- **ValidateCertificate**: Validate server certificate
- **IsEnabled**: Enable/disable configuration

### Identity Password Requirements

Default password requirements (can be modified in Program.cs):

- Minimum 8 characters
- Requires digit
- Requires lowercase letter
- Requires uppercase letter
- Requires non-alphanumeric character

## Development

### Project Structure

```
SecureAuthApi/
├── Data/                    # DbContext and database configuration
├── DTOs/                    # Data transfer objects
├── Interfaces/              # Service interfaces
├── Models/                  # Domain entities
├── Repositories/            # Data access layer
├── Services/                # Business logic
├── Program.cs               # Application entry point
└── appsettings.json         # Configuration
```

### Testing

Currently, no tests are implemented. To add tests:

1. Create a test project: `dotnet new xunit -n SecureAuthApi.Tests`
2. Add reference: `dotnet add reference ../SecureAuthApi/SecureAuthApi.csproj`
3. Run tests: `dotnet test`

### Database Migrations

```pwsh
# Add new migration
dotnet ef migrations add <MigrationName>

# Update database
dotnet ef database update

# Rollback migration
dotnet ef database update <PreviousMigrationName>

# Remove last migration (if not applied)
dotnet ef migrations remove
```

## Security Considerations

1. **Never commit secrets**: Use environment variables or secret management services for production
2. **HTTPS in production**: Always use HTTPS in production environments
3. **Strong passwords**: Enforce strong password policies for local users
4. **Token rotation**: Refresh tokens are automatically rotated on use
5. **LDAP credentials**: Bind passwords are encrypted using AES-256 before storage
6. **Certificate validation**: Enable SSL certificate validation for LDAP in production

## Troubleshooting

### Database Connection Issues

- Verify MySQL is running
- Check connection string credentials
- Ensure database exists or migrations are applied

### LDAP Connection Issues

- Test LDAP connectivity using `/api/ldap/test` endpoint
- Verify BaseDn and BindDn format
- Check network connectivity to LDAP server
- For SSL issues, verify certificate chain

### JWT Token Issues

- Ensure secret key is at least 32 characters
- Verify issuer and audience match configuration
- Check token expiration times

## License

[Specify your license here]

## Contributing

[Specify contribution guidelines here]
