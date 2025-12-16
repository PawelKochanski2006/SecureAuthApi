using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureAuthApi.Data;
using SecureAuthApi.DTOs;
using SecureAuthApi.Interfaces;
using SecureAuthApi.Models;

namespace SecureAuthApi.Controllers;

[ApiController]
[Route("api/ldap")]
[Authorize(Roles = "Admin")]
public class LdapConfigController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly IEncryptionService _encryptionService;
    private readonly ILdapService _ldapService;

    public LdapConfigController(
        ApplicationDbContext context,
        IEncryptionService encryptionService,
        ILdapService ldapService)
    {
        _context = context;
        _encryptionService = encryptionService;
        _ldapService = ldapService;
    }

    [HttpGet("config")]
    public async Task<IActionResult> GetConfigs()
    {
        var configs = await _context.LdapConfigurations
            .Select(c => new LdapConfigResponse
            {
                Id = c.Id,
                ServerUrl = c.ServerUrl,
                Port = c.Port,
                BaseDn = c.BaseDn,
                BindDn = c.BindDn,
                SearchFilter = c.SearchFilter,
                UseSsl = c.UseSsl,
                ValidateCertificate = c.ValidateCertificate,
                IsEnabled = c.IsEnabled,
                CreatedAt = c.CreatedAt,
                UpdatedAt = c.UpdatedAt
            })
            .ToListAsync();

        return Ok(configs);
    }

    [HttpPost("config")]
    public async Task<IActionResult> CreateConfig([FromBody] LdapConfigRequest request)
    {
        var encryptedPassword = _encryptionService.Encrypt(request.BindPassword);
        var config = new LdapConfiguration
        {
            ServerUrl = request.ServerUrl,
            Port = request.Port,
            BaseDn = request.BaseDn,
            BindDn = request.BindDn,
            EncryptedBindPassword = encryptedPassword,
            SearchFilter = request.SearchFilter,
            UseSsl = request.UseSsl,
            ValidateCertificate = request.ValidateCertificate,
            IsEnabled = request.IsEnabled
        };

        var connectionTest = await _ldapService.TestConnectionAsync(config);
        if (!connectionTest)
        {
            return BadRequest(new { message = "Failed to connect to LDAP server with provided configuration" });
        }

        _context.LdapConfigurations.Add(config);
        await _context.SaveChangesAsync();

        var response = new LdapConfigResponse
        {
            Id = config.Id,
            ServerUrl = config.ServerUrl,
            Port = config.Port,
            BaseDn = config.BaseDn,
            BindDn = config.BindDn,
            SearchFilter = config.SearchFilter,
            UseSsl = config.UseSsl,
            ValidateCertificate = config.ValidateCertificate,
            IsEnabled = config.IsEnabled,
            CreatedAt = config.CreatedAt,
            UpdatedAt = config.UpdatedAt
        };

        return Created($"/api/ldap/config/{config.Id}", response);
    }

    [HttpPut("config/{id:int}")]
    public async Task<IActionResult> UpdateConfig(int id, [FromBody] LdapConfigRequest request)
    {
        var config = await _context.LdapConfigurations.FindAsync(id);
        if (config == null) return NotFound();

        config.ServerUrl = request.ServerUrl;
        config.Port = request.Port;
        config.BaseDn = request.BaseDn;
        config.BindDn = request.BindDn;
        config.EncryptedBindPassword = _encryptionService.Encrypt(request.BindPassword);
        config.SearchFilter = request.SearchFilter;
        config.UseSsl = request.UseSsl;
        config.ValidateCertificate = request.ValidateCertificate;
        config.IsEnabled = request.IsEnabled;
        config.UpdatedAt = DateTime.UtcNow;

        var connectionTest = await _ldapService.TestConnectionAsync(config);
        if (!connectionTest)
        {
            return BadRequest(new { message = "Failed to connect to LDAP server with provided configuration" });
        }

        await _context.SaveChangesAsync();

        var response = new LdapConfigResponse
        {
            Id = config.Id,
            ServerUrl = config.ServerUrl,
            Port = config.Port,
            BaseDn = config.BaseDn,
            BindDn = config.BindDn,
            SearchFilter = config.SearchFilter,
            UseSsl = config.UseSsl,
            ValidateCertificate = config.ValidateCertificate,
            IsEnabled = config.IsEnabled,
            CreatedAt = config.CreatedAt,
            UpdatedAt = config.UpdatedAt
        };

        return Ok(response);
    }

    [HttpDelete("config/{id:int}")]
    public async Task<IActionResult> DeleteConfig(int id)
    {
        var config = await _context.LdapConfigurations.FindAsync(id);
        if (config == null) return NotFound();

        _context.LdapConfigurations.Remove(config);
        await _context.SaveChangesAsync();
        return Ok(new { message = "LDAP configuration deleted successfully" });
    }

    [HttpPost("test")]
    public async Task<IActionResult> Test([FromBody] LdapConfigRequest request)
    {
        var config = new LdapConfiguration
        {
            ServerUrl = request.ServerUrl,
            Port = request.Port,
            BaseDn = request.BaseDn,
            BindDn = request.BindDn,
            EncryptedBindPassword = _encryptionService.Encrypt(request.BindPassword),
            SearchFilter = request.SearchFilter,
            UseSsl = request.UseSsl,
            ValidateCertificate = request.ValidateCertificate
        };

        var result = await _ldapService.TestConnectionAsync(config);
        return Ok(new { success = result, message = result ? "Connection successful" : "Connection failed" });
    }
}
