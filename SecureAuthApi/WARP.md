# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project Overview

SecureAuthApi is an ASP.NET Core 9.0 Web API for authentication with LDAP integration and JWT token management. The application uses Entity Framework Core with MySQL (via Pomelo provider) and implements ASP.NET Core Identity for user management.

## Architecture

### Core Components

- **Authentication System**: JWT-based authentication with refresh token support
- **LDAP Integration**: LDAP authentication using Novell.Directory.Ldap.NETStandard
- **User Management**: ASP.NET Core Identity with custom ApplicationUser model
- **Data Encryption**: AES-256 encryption service for sensitive data (LDAP credentials)
- **Database**: Entity Framework Core with MySQL database

### Project Structure

- **Data/**: DbContext and database configuration
  - `ApplicationDbContext`: Main EF Core context extending IdentityDbContext
- **Models/**: Domain entities
  - `ApplicationUser`: Custom identity user with LDAP properties (SAMAccountName, DisplayName, IsLdapUser)
  - `RefreshToken`: Refresh token entity with revocation support
  - `LdapConfiguration`: LDAP server configuration with encrypted credentials
- **DTOs/**: Data transfer objects for API requests/responses
  - Login/authentication DTOs
  - LDAP configuration DTOs
- **Services/**: Business logic implementations
  - `EncryptionService`: AES-256 encryption/decryption for sensitive data
- **Interfaces/**: Service contracts
  - `IEncryptionService`: Encryption operations interface
  - `IRefreshTokenRepository`: Refresh token repository interface
- **Repositories/**: Empty directory (repository implementations to be added)

### Key Database Relationships

- `ApplicationUser` has many `RefreshTokens` (one-to-many, cascade delete)
- Unique constraints on `ApplicationUser.SAMAccountName` and `RefreshToken.Token`
- Indexes on refresh token expiration and revocation status for efficient queries

### Security Features

- **AES-256 Encryption**: LDAP bind passwords are encrypted before storage
- **Encryption Key Configuration**: Must be set via `Encryption:AesKey` config (Base64 encoded 32-byte key)
- **JWT Authentication**: Using Microsoft.AspNetCore.Authentication.JwtBearer
- **Refresh Token Rotation**: Token-based authentication with revocation support

## Commands

### Build and Run

```pwsh
# Build the project
dotnet build

# Run the application (Development)
dotnet run --launch-profile http   # HTTP on localhost:5133
dotnet run --launch-profile https  # HTTPS on localhost:7079

# Run in production mode
dotnet run --environment Production
```

### Database Management

```pwsh
# Add a new migration
dotnet ef migrations add <MigrationName>

# Apply migrations to database
dotnet ef database update

# Revert to a specific migration
dotnet ef database update <MigrationName>

# Remove last migration (if not applied)
dotnet ef migrations remove

# Generate SQL script for migrations
dotnet ef migrations script
```

### Package Management

```pwsh
# Restore dependencies
dotnet restore

# Add a new package
dotnet add package <PackageName>

# Update all packages
dotnet restore --force-evaluate
```

### Testing

Note: No test project currently exists in the solution. When tests are added:

```pwsh
# Run all tests
dotnet test

# Run tests with detailed output
dotnet test --verbosity normal

# Run specific test
dotnet test --filter "FullyQualifiedName~<TestName>"
```

## Configuration Requirements

### Required Environment Variables / Configuration

- **Encryption:AesKey**: Base64 encoded 256-bit (32 bytes) AES encryption key
  - Used by `EncryptionService` to encrypt/decrypt LDAP credentials
  - Must be set in environment variables or appsettings.json
  - Can generate using: `[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))`

### Database Connection

- Connection string should be configured in appsettings.json or environment variables
- Using Pomelo.EntityFrameworkCore.MySql provider for MySQL database

## Development Notes

### API Style

- This project uses Minimal APIs (no controllers)
- Endpoints are defined in Program.cs using `app.MapGet()`, `app.MapPost()`, etc.
- Currently only has a sample weather forecast endpoint

### Entity Framework Core

- Using Code First approach with migrations
- Database context: `ApplicationDbContext`
- All entities use navigation properties for relationships
- Timestamps (CreatedAt, UpdatedAt) are used for auditing

### Logging

- Serilog.AspNetCore is configured for structured logging
- Default log level: Information
- ASP.NET Core logging level: Warning

### Authentication Flow

1. User authenticates via LDAP or local credentials
2. System generates JWT access token and refresh token
3. Refresh tokens are stored in database with expiration and revocation tracking
4. Users can refresh access tokens using valid refresh tokens
5. Tokens can be revoked individually or all tokens for a user

### LDAP Configuration

- LDAP configurations are stored in the database
- Bind passwords are encrypted using EncryptionService before storage
- Supports SSL/TLS connections with certificate validation options
- Search filter defaults to Active Directory user lookup: `(&(objectClass=user)(sAMAccountName={0}))`

## Dependencies

Key NuGet packages:
- Microsoft.AspNetCore.Authentication.JwtBearer (9.0.10)
- Microsoft.AspNetCore.Identity.EntityFrameworkCore (9.0.10)
- Pomelo.EntityFrameworkCore.MySql (9.0.0)
- Novell.Directory.Ldap.NETStandard (4.0.0)
- Serilog.AspNetCore (9.0.0)
