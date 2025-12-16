using SecureAuthApi.DTOs;

namespace SecureAuthApi.Interfaces;

public interface IAuthenticationService
{
    Task<LoginResponse?> AuthenticateAsync(LoginRequest request);
    Task<LoginResponse?> RefreshTokenAsync(RefreshTokenRequest request);
    Task<bool> RevokeTokenAsync(string token);
    Task<bool> RevokeAllUserTokensAsync(string userId);
}
