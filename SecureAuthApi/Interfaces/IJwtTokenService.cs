using System.Security.Claims;
using SecureAuthApi.Models;

namespace SecureAuthApi.Interfaces;

public interface IJwtTokenService
{
    string GenerateAccessToken(ApplicationUser user, IEnumerable<string> roles);
    string GenerateRefreshToken();
    ClaimsPrincipal? GetPrincipalFromExpiredToken(string token);
}
