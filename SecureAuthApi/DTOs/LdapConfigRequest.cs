using System.ComponentModel.DataAnnotations;

namespace SecureAuthApi.DTOs;

public class LdapConfigRequest
{
    [Required(ErrorMessage = "Server URL is required")]
    [StringLength(512, ErrorMessage = "Server URL cannot exceed 512 characters")]
    public string ServerUrl { get; set; } = string.Empty;

    [Required(ErrorMessage = "Port is required")]
    [Range(1, 65535, ErrorMessage = "Port must be between 1 and 65535")]
    public int Port { get; set; } = 389;

    [Required(ErrorMessage = "Base DN is required")]
    [StringLength(512, ErrorMessage = "Base DN cannot exceed 512 characters")]
    public string BaseDn { get; set; } = string.Empty;

    [Required(ErrorMessage = "Bind DN is required")]
    [StringLength(512, ErrorMessage = "Bind DN cannot exceed 512 characters")]
    public string BindDn { get; set; } = string.Empty;

    [Required(ErrorMessage = "Bind password is required")]
    [StringLength(256, ErrorMessage = "Bind password cannot exceed 256 characters")]
    public string BindPassword { get; set; } = string.Empty;

    [Required(ErrorMessage = "Search filter is required")]
    [StringLength(512, ErrorMessage = "Search filter cannot exceed 512 characters")]
    public string SearchFilter { get; set; } = "(&(objectClass=user)(sAMAccountName={0}))";

    public bool UseSsl { get; set; }
    public bool ValidateCertificate { get; set; } = true;
    public bool IsEnabled { get; set; } = true;
}
