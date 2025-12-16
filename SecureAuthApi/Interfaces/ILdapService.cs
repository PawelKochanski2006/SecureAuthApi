using SecureAuthApi.Models;

namespace SecureAuthApi.Interfaces;

public interface ILdapService
{
    Task<LdapUserInfo?> AuthenticateAsync(string username, string password);
    Task<bool> TestConnectionAsync(LdapConfiguration config);
}
