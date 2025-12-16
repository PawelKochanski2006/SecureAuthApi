namespace SecureAuthApi.Models;

public class LdapUserInfo
{
    public string SAMAccountName { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public string DistinguishedName { get; set; } = string.Empty;
}
