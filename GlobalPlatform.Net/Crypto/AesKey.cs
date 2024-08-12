using System;

namespace GlobalPlatform.Net.Crypto;

/// <summary>
/// Represents an AES key, which is a type of symmetric key.
/// </summary>
public class AesKey : SymmetricKey
{
    /// <summary>
    /// Constructs an AES key from a byte array.
    /// </summary>
    /// <param name="value">The byte array representing the key.</param>
    /// <param name="keyId">The ID of the key (default is 0).</param>
    /// <param name="keyVersion">The version of the key (default is 0).</param>
    /// <exception cref="ArgumentException">Thrown when the key length is invalid.</exception>
    public AesKey(byte[] value, int keyId = 0, int keyVersion = 0) : base(value, keyId, keyVersion)
    {
        // Use a switch statement to determine the key length and set the key size
        KeySize = value.Length switch
        {
            16 => KeySize.Aes128,
            24 => KeySize.Aes192,
            32 => KeySize.Aes256,
            _ => throw new ArgumentException("Invalid key length")
        };
    }

    /// <summary>
    /// Constructs an AES key from a hex string.
    /// </summary>
    /// <param name="hexValue">The hex string representing the key.</param>
    /// <param name="keyId">The ID of the key (default is 0).</param>
    /// <param name="keyVersion">The version of the key (default is 0).</param>
    /// <exception cref="ArgumentException">Thrown when the key length is invalid.</exception>
    public AesKey(string hexValue, int keyId = 0, int keyVersion = 0) : base(hexValue, keyId, keyVersion)
    {
        // Use a switch statement to determine the key length and set the key size
        KeySize = hexValue.Length switch
        {
            32 => KeySize.Aes128,
            48 => KeySize.Aes192,
            64 => KeySize.Aes256,
            _ => throw new ArgumentException("Invalid key length")
        };
    }
}