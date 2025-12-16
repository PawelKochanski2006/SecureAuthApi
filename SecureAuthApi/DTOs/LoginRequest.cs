using System.ComponentModel.DataAnnotations;

namespace SecureAuthApi.DTOs;

public class LoginRequest
{
    [Required(ErrorMessage = "Username is required")]
    [StringLength(256, ErrorMessage = "Username cannot exceed 256 characters")]
    public string Username { get; set; } = string.Empty;

    [Required(ErrorMessage = "Password is required")]
    [StringLength(128, MinimumLength = 1, ErrorMessage = "Password must be between 1 and 128 characters")]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}
