using System.Security.Cryptography;
using System.Text;
using SecureAuthApi.Interfaces;

namespace SecureAuthApi.Services;

public class EncryptionService : IEncryptionService
{
    private readonly byte[] _key;
    private readonly ILogger<EncryptionService> _logger;

    public EncryptionService(IConfiguration configuration, ILogger<EncryptionService> logger)
    {
        _logger = logger;
        
        // Key should be stored in environment variable or secure key vault
        // Format: Base64 encoded 256-bit (32 bytes) key
        var keyString = configuration["Encryption:AesKey"] 
            ?? throw new InvalidOperationException("AES encryption key not configured. Set Encryption:AesKey in environment variables or configuration.");
        
        try
        {
            _key = Convert.FromBase64String(keyString);
            
            if (_key.Length != 32)
            {
                throw new InvalidOperationException("AES key must be 256 bits (32 bytes). Current key length: " + _key.Length);
            }
        }
        catch (FormatException ex)
        {
            _logger.LogCritical(ex, "Invalid AES key format. Key must be Base64 encoded.");
            throw new InvalidOperationException("Invalid AES key format. Key must be Base64 encoded.", ex);
        }
    }

    public string Encrypt(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            throw new ArgumentException("Plain text cannot be null or empty.", nameof(plainText));
        }

        try
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.GenerateIV();

            var iv = aes.IV;
            
            using var encryptor = aes.CreateEncryptor(aes.Key, iv);
            using var msEncrypt = new MemoryStream();
            using var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write);
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
            }

            var encrypted = msEncrypt.ToArray();
            
            // Combine IV and encrypted data
            var result = new byte[iv.Length + encrypted.Length];
            Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
            Buffer.BlockCopy(encrypted, 0, result, iv.Length, encrypted.Length);

            return Convert.ToBase64String(result);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Encryption failed");
            throw new InvalidOperationException("Encryption operation failed.", ex);
        }
    }

    public string Decrypt(string cipherText)
    {
        if (string.IsNullOrEmpty(cipherText))
        {
            throw new ArgumentException("Cipher text cannot be null or empty.", nameof(cipherText));
        }

        try
        {
            var fullCipher = Convert.FromBase64String(cipherText);

            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            // Extract IV (first 16 bytes)
            var iv = new byte[aes.IV.Length];
            var cipher = new byte[fullCipher.Length - iv.Length];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

            aes.IV = iv;

            using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
            using var msDecrypt = new MemoryStream(cipher);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var srDecrypt = new StreamReader(csDecrypt);
            
            return srDecrypt.ReadToEnd();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Decryption failed");
            throw new InvalidOperationException("Decryption operation failed.", ex);
        }
    }
}
