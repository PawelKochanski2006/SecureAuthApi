using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureAuthApi.DTOs;
using SecureAuthApi.Interfaces;
using SecureAuthApi.Models;

namespace SecureAuthApi.Services;

public class AuthenticationService : IAuthenticationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IJwtTokenService _jwtTokenService;
    private readonly IRefreshTokenRepository _refreshTokenRepository;
    private readonly ILdapService _ldapService;
    private readonly IConfiguration _configuration;
    private readonly ILogger<AuthenticationService> _logger;

    public AuthenticationService(
        UserManager<ApplicationUser> userManager,
        IJwtTokenService jwtTokenService,
        IRefreshTokenRepository refreshTokenRepository,
        ILdapService ldapService,
        IConfiguration configuration,
        ILogger<AuthenticationService> logger)
    {
        _userManager = userManager;
        _jwtTokenService = jwtTokenService;
        _refreshTokenRepository = refreshTokenRepository;
        _ldapService = ldapService;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task<LoginResponse?> AuthenticateAsync(LoginRequest request)
    {
        // Try to find user by username or email
        var user = await _userManager.FindByNameAsync(request.Username) 
                   ?? await _userManager.FindByEmailAsync(request.Username);

        // If user doesn't exist or is an LDAP user, try LDAP authentication
        if (user == null || user.IsLdapUser)
        {
            var ldapUser = await _ldapService.AuthenticateAsync(request.Username, request.Password);
            
            if (ldapUser != null)
            {
                // Create or update user from LDAP
                user = await GetOrCreateLdapUserAsync(ldapUser);
            }
            else if (user == null)
            {
                _logger.LogWarning("Authentication failed for user {Username}", request.Username);
                return null;
            }
        }
        
        // For local users, verify password
        if (!user.IsLdapUser)
        {
            var passwordValid = await _userManager.CheckPasswordAsync(user, request.Password);
            if (!passwordValid)
            {
                _logger.LogWarning("Invalid password for user {Username}", request.Username);
                return null;
            }
        }

        // Update last login time
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        // Generate tokens
        var rolesForToken = await _userManager.GetRolesAsync(user);
        var accessToken = _jwtTokenService.GenerateAccessToken(user, rolesForToken);
        var refreshToken = _jwtTokenService.GenerateRefreshToken();

        // Calculate refresh token expiration
        var refreshTokenExpirationDays = int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");
        var expiresAt = DateTime.UtcNow.AddDays(refreshTokenExpirationDays);

        // Store refresh token
        await _refreshTokenRepository.CreateAsync(new RefreshToken
        {
            Token = refreshToken,
            UserId = user.Id,
            ExpiresAt = expiresAt
        });

        _logger.LogInformation("User {Username} authenticated successfully", user.UserName);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            ExpiresAt = expiresAt,
            Username = user.UserName ?? string.Empty,
            DisplayName = user.DisplayName,
            IsLdapUser = user.IsLdapUser
        };
    }

    public async Task<LoginResponse?> RefreshTokenAsync(RefreshTokenRequest request)
    {
        var principal = _jwtTokenService.GetPrincipalFromExpiredToken(request.AccessToken);
        if (principal == null)
        {
            _logger.LogWarning("Invalid access token provided for refresh");
            return null;
        }

        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (string.IsNullOrEmpty(userId))
        {
            _logger.LogWarning("No user ID found in token claims");
            return null;
        }

        var storedRefreshToken = await _refreshTokenRepository.GetByTokenAsync(request.RefreshToken);
        
        if (storedRefreshToken == null || storedRefreshToken.UserId != userId)
        {
            _logger.LogWarning("Invalid refresh token or user mismatch");
            return null;
        }

        if (storedRefreshToken.ExpiresAt < DateTime.UtcNow)
        {
            _logger.LogWarning("Refresh token has expired");
            await _refreshTokenRepository.RevokeAsync(request.RefreshToken);
            return null;
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            _logger.LogWarning("User not found for ID {UserId}", userId);
            return null;
        }

        // Revoke old refresh token
        await _refreshTokenRepository.RevokeAsync(request.RefreshToken);

        // Generate new tokens
        var rolesForToken = await _userManager.GetRolesAsync(user);
        var accessToken = _jwtTokenService.GenerateAccessToken(user, rolesForToken);
        var newRefreshToken = _jwtTokenService.GenerateRefreshToken();

        var refreshTokenExpirationDays = int.Parse(_configuration["Jwt:RefreshTokenExpirationDays"] ?? "7");
        var expiresAt = DateTime.UtcNow.AddDays(refreshTokenExpirationDays);

        // Store new refresh token
        await _refreshTokenRepository.CreateAsync(new RefreshToken
        {
            Token = newRefreshToken,
            UserId = user.Id,
            ExpiresAt = expiresAt
        });

        _logger.LogInformation("Tokens refreshed for user {Username}", user.UserName);

        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = newRefreshToken,
            ExpiresAt = expiresAt,
            Username = user.UserName ?? string.Empty,
            DisplayName = user.DisplayName,
            IsLdapUser = user.IsLdapUser
        };
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        await _refreshTokenRepository.RevokeAsync(token);
        return true;
    }

    public async Task<bool> RevokeAllUserTokensAsync(string userId)
    {
        await _refreshTokenRepository.RevokeAllForUserAsync(userId);
        return true;
    }

    private async Task<ApplicationUser> GetOrCreateLdapUserAsync(LdapUserInfo ldapUserInfo)
    {
        // Try to find existing user by UserName (mapped from sAMAccountName)
        var user = await _userManager.FindByNameAsync(ldapUserInfo.SAMAccountName);

        if (user == null)
        {
            // Create new user
            user = new ApplicationUser
            {
                UserName = ldapUserInfo.SAMAccountName,
                Email = ldapUserInfo.Email,
                DisplayName = ldapUserInfo.DisplayName,
                FirstName = ldapUserInfo.FirstName,
                LastName = ldapUserInfo.LastName,
                IsLdapUser = true,
                EmailConfirmed = true // LDAP users are considered verified
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                _logger.LogError("Failed to create LDAP user {Username}: {Errors}", 
                    ldapUserInfo.SAMAccountName, 
                    string.Join(", ", result.Errors.Select(e => e.Description)));
                throw new InvalidOperationException("Failed to create LDAP user");
            }

            _logger.LogInformation("Created new LDAP user {Username}", user.UserName);
        }
        else
        {
            // Update existing user information from LDAP
            user.Email = ldapUserInfo.Email;
            user.DisplayName = ldapUserInfo.DisplayName;
            user.FirstName = ldapUserInfo.FirstName;
            user.LastName = ldapUserInfo.LastName;
            
            await _userManager.UpdateAsync(user);
            _logger.LogInformation("Updated LDAP user {Username}", user.UserName);
        }

        return user;
    }
}
