using SecureAuthApi.Models;

namespace SecureAuthApi.Interfaces;

public interface IRefreshTokenRepository
{
    Task<RefreshToken?> GetByTokenAsync(string token);
    Task<RefreshToken> CreateAsync(RefreshToken refreshToken);
    Task RevokeAsync(string token);
    Task RevokeAllForUserAsync(string userId);
    Task DeleteExpiredTokensAsync();
}
