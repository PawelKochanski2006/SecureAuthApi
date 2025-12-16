namespace SecureAuthApi.DTOs;

public class LdapConfigResponse
{
    public int Id { get; set; }
    public string ServerUrl { get; set; } = string.Empty;
    public int Port { get; set; }
    public string BaseDn { get; set; } = string.Empty;
    public string BindDn { get; set; } = string.Empty;
    public string BindPassword { get; set; } = "********"; // Masked for security
    public string SearchFilter { get; set; } = string.Empty;
    public bool UseSsl { get; set; }
    public bool ValidateCertificate { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? UpdatedAt { get; set; }
}
