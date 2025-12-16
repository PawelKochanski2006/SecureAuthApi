namespace SecureAuthApi.Models;

public class LdapConfiguration
{
    public int Id { get; set; }
    public string ServerUrl { get; set; } = string.Empty;
    public int Port { get; set; } = 389;
    public string BaseDn { get; set; } = string.Empty;
    public string BindDn { get; set; } = string.Empty;
    public string EncryptedBindPassword { get; set; } = string.Empty;
    public string SearchFilter { get; set; } = "(&(objectClass=user)(sAMAccountName={0}))";
    public bool UseSsl { get; set; }
    public bool ValidateCertificate { get; set; } = true;
    public bool IsEnabled { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt { get; set; }
}
