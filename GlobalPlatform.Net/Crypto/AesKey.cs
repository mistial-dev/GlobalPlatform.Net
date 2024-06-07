using System;

namespace GlobalPlatform.Net.Crypto;

public class AesKey : SymmetricKey
{
    /// <summary>
    /// Constructs an AES key from a byte array
    /// </summary>
    /// <param name="value"></param>
    /// <param name="keyId"></param>
    /// <param name="keyVersion"></param>
    /// <exception cref="ArgumentException"></exception>
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
    /// Constructs an AES key from a hex string
    /// </summary>
    /// <param name="hexValue"></param>
    /// <param name="keyId"></param>
    /// <param name="keyVersion"></param>
    /// <exception cref="ArgumentException"></exception>
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