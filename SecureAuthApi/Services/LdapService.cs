using Microsoft.EntityFrameworkCore;
using Novell.Directory.Ldap;
using SecureAuthApi.Data;
using SecureAuthApi.Interfaces;
using SecureAuthApi.Models;

namespace SecureAuthApi.Services;

public class LdapService : ILdapService
{
    private readonly ApplicationDbContext _context;
    private readonly IEncryptionService _encryptionService;
    private readonly ILogger<LdapService> _logger;

    public LdapService(
        ApplicationDbContext context,
        IEncryptionService encryptionService,
        ILogger<LdapService> logger)
    {
        _context = context;
        _encryptionService = encryptionService;
        _logger = logger;
    }

    /// <summary>
    /// The function `AuthenticateAsync` asynchronously authenticates a user against an LDAP server by
    /// searching for the user, verifying the password, and returning user information if successful.
    /// </summary>
    /// <param name="username">The code snippet you provided is an asynchronous method for
    /// authenticating a user against an LDAP server. The method takes a username and password as input
    /// parameters for authentication. The username is used to search for the user in the LDAP
    /// directory, and the password is used to verify the user's credentials.</param>
    /// <param name="password">The `password` parameter in the `AuthenticateAsync` method is the user's
    /// password that is used for LDAP authentication. This password is provided by the user attempting
    /// to log in and is used to verify their identity against the LDAP server.</param>
    /// <returns>
    /// The method `AuthenticateAsync` returns a `Task` that may contain a `LdapUserInfo` object if the
    /// LDAP authentication is successful, or `null` if there are any errors or if the user is not found
    /// in the LDAP directory.
    /// </returns>
    public async Task<LdapUserInfo?> AuthenticateAsync(string username, string password)
    {
        var config = await GetActiveLdapConfigurationAsync();
        if (config == null)
        {
            _logger.LogWarning("No active LDAP configuration found");
            return null;
        }

        try
        {
            using var connection = new LdapConnection();
            
            if (config.UseSsl)
            {
                connection.SecureSocketLayer = true;
            }

            // Connect to LDAP server
            await connection.ConnectAsync(config.ServerUrl, config.Port);

            // Bind with service account to search for user
            var bindPassword = _encryptionService.Decrypt(config.EncryptedBindPassword);
            await connection.BindAsync(config.BindDn, bindPassword);

            // Search for user
            var searchFilter = BuildSearchFilter(config.SearchFilter, username);
            var searchResults = await connection.SearchAsync(
                config.BaseDn,
                LdapConnection.ScopeSub,
                searchFilter,
                new[] { "sAMAccountName", "displayName", "mail", "givenName", "sn" },
                false
            );

            LdapEntry? userEntry = null;
            await foreach (var entry in searchResults)
            {
                userEntry = entry;
                break;
            }
            
            if (userEntry == null)
            {
                _logger.LogWarning("User {Username} not found in LDAP", username);
                return null;
            }
            
            var userDn = userEntry.Dn;

            // Try to bind as the user to verify password
            try
            {
                using var userConnection = new LdapConnection();
                
                if (config.UseSsl)
                {
                    userConnection.SecureSocketLayer = true;
                }

                await userConnection.ConnectAsync(config.ServerUrl, config.Port);
                await userConnection.BindAsync(userDn, password);
                
                // If bind succeeds, password is correct
                _logger.LogInformation("LDAP authentication successful for user {Username}", username);
                
                // Extract user information
                return new LdapUserInfo
                {
                    SAMAccountName = GetLdapAttribute(userEntry, "sAMAccountName"),
                    DisplayName = GetLdapAttribute(userEntry, "displayName"),
                    Email = GetLdapAttribute(userEntry, "mail"),
                    FirstName = GetLdapAttribute(userEntry, "givenName"),
                    LastName = GetLdapAttribute(userEntry, "sn"),
                    DistinguishedName = userDn
                };
            }
            catch (LdapException ex) when (ex.ResultCode == LdapException.InvalidCredentials)
            {
                _logger.LogWarning("Invalid credentials for LDAP user {Username}", username);
                return null;
            }
        }
        catch (LdapException ex)
        {
            _logger.LogError(ex, "LDAP authentication error for user {Username}: {Message}", username, ex.Message);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error during LDAP authentication for user {Username}", username);
            return null;
        }
    }

    /// <summary>
    /// The TestConnectionAsync method establishes an LDAP connection using the provided configuration
    /// and returns true if successful, logging any errors encountered.
    /// </summary>
    /// <param name="LdapConfiguration">LdapConfiguration is a class or object that contains the
    /// configuration settings for connecting to an LDAP server. It likely includes properties such as
    /// ServerUrl, Port, UseSsl, BindDn, BaseDn, and EncryptedBindPassword. These settings are used to
    /// establish a connection to the LDAP</param>
    /// <returns>
    /// The `TestConnectionAsync` method returns a `Task<bool>`, where `true` is returned if the LDAP
    /// connection test is successful, and `false` is returned if the test fails.
    /// </returns>
    public async Task<bool> TestConnectionAsync(LdapConfiguration config)
    {
        try
        {
            using var connection = new LdapConnection();
            
            if (config.UseSsl)
            {
                connection.SecureSocketLayer = true;
            }

            await connection.ConnectAsync(config.ServerUrl, config.Port);
            
            var bindPassword = _encryptionService.Decrypt(config.EncryptedBindPassword);
            await connection.BindAsync(config.BindDn, bindPassword);
            
            // Test search
            var searchResults = await connection.SearchAsync(
                config.BaseDn,
                LdapConnection.ScopeBase,
                "(objectClass=*)",
                null,
                false
            );

            _logger.LogInformation("LDAP connection test successful for {ServerUrl}", config.ServerUrl);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "LDAP connection test failed for {ServerUrl}: {Message}", config.ServerUrl, ex.Message);
            return false;
        }
    }

    /// <summary>
    /// This C# function asynchronously retrieves the most recently created enabled LDAP configuration
    /// from a database context.
    /// </summary>
    /// <returns>
    /// The method `GetActiveLdapConfigurationAsync` returns a `Task` that will eventually contain a
    /// nullable `LdapConfiguration` object.
    /// </returns>
    private async Task<LdapConfiguration?> GetActiveLdapConfigurationAsync()
    {
        return await _context.LdapConfigurations
            .Where(c => c.IsEnabled)
            .OrderByDescending(c => c.CreatedAt)
            .FirstOrDefaultAsync();
    }

    /// <summary>
    /// The function `GetLdapAttribute` retrieves the value of a specified LDAP attribute from a given
    /// `LdapEntry` object.
    /// </summary>
    /// <param name="LdapEntry">`LdapEntry` is a class representing an entry in an LDAP (Lightweight
    /// Directory Access Protocol) directory. It typically contains information about an object in the
    /// directory, such as its attributes and values.</param>
    /// <param name="attributeName">The `attributeName` parameter is a string that represents the name
    /// of the LDAP attribute you want to retrieve from the `LdapEntry` object.</param>
    /// <returns>
    /// The method `GetLdapAttribute` returns the value of the LDAP attribute specified by the
    /// `attributeName` parameter from the `LdapEntry` object `entry`. If the attribute is found, its
    /// string value is returned. If the attribute is not found or an exception occurs during the
    /// retrieval process, an empty string is returned.
    /// </returns>
    private static string GetLdapAttribute(LdapEntry entry, string attributeName)
    {
        try
        {
            var attribute = entry.GetAttributeSet()[attributeName];
            return attribute?.StringValue ?? string.Empty;
        }
        catch
        {
            return string.Empty;
        }
    }

    /// <summary>
    /// The function `BuildSearchFilter` constructs a search filter in C# by adding a username condition
    /// to a base filter, ensuring the filter includes the sAMAccountName attribute.
    /// </summary>
    /// <param name="baseFilter">The `BuildSearchFilter` method you provided is used to construct an
    /// LDAP search filter by adding a condition for the `sAMAccountName` attribute based on the
    /// provided `username`. The method first checks if the `baseFilter` already contains a filter for
    /// `sAMAccountName`, and if</param>
    /// <param name="username">The `BuildSearchFilter` method you provided is used to construct an LDAP
    /// search filter by adding a condition for the `sAMAccountName` attribute based on the provided
    /// `baseFilter` and `username`.</param>
    /// <returns>
    /// The `BuildSearchFilter` method returns a modified search filter string that includes the
    /// `sAMAccountName` filter with the provided `username` added to it. If the base filter already
    /// contains the `sAMAccountName` filter, it simply replaces the placeholder with the `username`. If
    /// the base filter does not contain the `sAMAccountName` filter, it adds the `sAM
    /// </returns>
    private string BuildSearchFilter(string baseFilter, string username)
    {
        const string placeholder = "{0}";
        const string samAccountFilter = $"(sAMAccountName={placeholder})";

        // Je�li filtr ju� zawiera (sAMAccountName={0}), nie modyfikuj
        if (baseFilter.Contains(samAccountFilter, StringComparison.OrdinalIgnoreCase))
        {
            return string.Format(baseFilter, username);
        }

        // Opcjonalnie: usu� zewn�trzne nawiasy, je�li istniej�, by unikn�� podw�jnych (&(...))
        string cleanFilter = baseFilter.Trim();
        if (cleanFilter.StartsWith("(") && cleanFilter.EndsWith(")"))
        {
            cleanFilter = cleanFilter.Substring(1, cleanFilter.Length - 2);
        }

        // Zawsze dodajemy (sAMAccountName={0}) na pocz�tek
        string finalFilter = $"(&{samAccountFilter}({cleanFilter}))";
        return string.Format(finalFilter, username);
    }
}
