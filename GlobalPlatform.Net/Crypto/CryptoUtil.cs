using System;
using System.Linq;
using System.Security.Cryptography;

namespace GlobalPlatform.Net.Crypto;

public static class CryptoUtil
{
    #region Constant Fields

    /// <summary>
    ///     Operate at encryption mode
    /// </summary>
    public const int MODE_ENCRYPT = 0x00;

    /// <summary>
    ///     Operate at decryption mode
    /// </summary>
    public const int MODE_DECRYPT = 0x01;

    /// <summary>
    ///     Binary zeroes
    /// </summary>
    public static readonly byte[] BINARY_ZEROS_8_BYTE_BLOCK = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    public const byte ALG_DES = 0x80;

    #endregion

    #region Static Methods

    /// <summary>
    ///     Applies full triple DES MAC as defined in [ISO 9797-1] as MAC Algorithm 1 with output transformation 1,
    ///     without truncation, and withtriple DES taking the place of the block cipher.
    ///     See Global Platform 2.1.1 Card Spec Section B.1.2.1
    /// </summary>
    /// <param name="key">3DES key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to MAC</param>
    /// <returns>Full triple DES MAC</returns>
    public static byte[] FullTripleDESMAC(SymmetricKey key, byte[] iv, byte[] data)
    {
        var enc = TripleDESCBC(new DesKey(key.BuildTripleDesKey()), iv, data, MODE_ENCRYPT);
        var result = new byte[8];
        Array.Copy(enc, enc.Length - 8, result, 0, 8);
        return result;
    }

    /// <summary>
    ///     Applies Retail MAC as defined in [ISO 9797-1] as MAC Algorithm 1 with output
    ///     transformation 3, without truncation, and withDES taking the place of the block cipher.
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to MAC</param>
    /// <returns>Retial MAC</returns>
    public static byte[] SingleDESFullTripleDESMAC(SymmetricKey key, byte[] iv, byte[] data)
    {
        byte[] intermeidateResult;
        var result = new byte[8];
        if (data.Length > 8)
        {
            intermeidateResult = DESCBC(
                new DesKey(key.BuildDesKey()), iv, SubArray(data, 0, data.Length - 8), MODE_ENCRYPT);
            Array.Copy(intermeidateResult, intermeidateResult.Length - 8, result, 0, 8);
            intermeidateResult = TripleDESCBC(
                new DesKey(key.BuildTripleDesKey()), result, SubArray(data, data.Length - 8, 8), MODE_ENCRYPT);
        }
        else
        {
            intermeidateResult = TripleDESCBC(
                new DesKey(key.BuildTripleDesKey()), iv, SubArray(data, data.Length - 8, 8), MODE_ENCRYPT);
        }

        Array.Copy(intermeidateResult, intermeidateResult.Length - 8, result, 0, 8);
        return result;
    }

    /// <summary>
    ///     Applies DES Padding according to following rules:
    ///     * Append an '80' to the right of the data block.
    ///     * If the resultant data block length is a multiple of 8, no further padding is required.
    ///     * Append binary zeroes to the right of the data block until the data block length is a multiple of 8
    ///     See Global Platform 2.1.1 Card Spec Section B.4
    /// </summary>
    /// <param name="data">Data to Pad</param>
    /// <returns>DES Padded data</returns>
    public static byte[] DESPad(byte[] data)
    {
        byte[] paddedData;
        var padLength = 8 - data.Length % 8;
        paddedData = new byte[data.Length + padLength];
        Array.Copy(data, paddedData, data.Length);
        paddedData[data.Length] = 0x80;
        if (paddedData.Length - data.Length > 1)
            Array.Clear(paddedData, data.Length + 1, padLength - 1);
        return paddedData;
    }
    
    /// <summary>
    ///     Applies AES Padding according to following rules:
    ///     * Append an '80' to the right of the data block.
    ///     * If the resultant data block length is a multiple of 16, no further padding is required.
    ///     * Append binary zeroes to the right of the data block until the data block length is a multiple of 16
    ///     See Global Platform 2.3.1 Card Spec Section B.2.3
    /// </summary>
    /// <param name="data">Data to Pad</param>
    /// <returns>AES Padded data</returns>
    public static byte[] AESPad(byte[] data)
    {
        // Determine the length of the padding
        var paddingLength = (16 - (data.Length + 1) % 16) % 16;

        // Zeroize the byte array
        var padded = Enumerable.Repeat((byte) 0x00, data.Length + 1 + paddingLength).ToArray();

        // Copy the data to the byte array
        Array.Copy(data, padded, data.Length);
        padded[data.Length] = 0x80;

        return padded;
    }

    /// <summary>
    ///     Encrypts or decrypts <see cref="data" /> with 3DES/ECB/NoPadding
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to encrypt or decrypt</param>
    /// <param name="operationMode">Operation mode: either <see cref="MODE_ENCRYPT" /> or <see cref="MODE_DECRYPT" /> </param>
    /// <returns></returns>
    public static byte[] TripleDESECB(DesKey key, byte[] data, int operationMode)
    {
        byte[] result = null;
        var tdes = new TripleDESCryptoServiceProvider();
        if (operationMode == MODE_DECRYPT)
        {
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;
            var decryptor = tdes.CreateDecryptor(key.Value, null);
            result = decryptor.TransformFinalBlock(data, 0, data.Length);
        }
        else if (operationMode == MODE_ENCRYPT)
        {
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;
            var encryptor = tdes.CreateEncryptor(key.Value, null);
            result = encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        return result;
    }

    /// <summary>
    ///     Encrypts or decrypts <see cref="data" /> with 3DES/CBC/NoPadding
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to encrypt or decrypt</param>
    /// <param name="mode">Operation mode: either <see cref="MODE_ENCRYPT" /> or <see cref="MODE_DECRYPT" /> </param>
    /// <returns></returns>
    public static byte[] TripleDESCBC(DesKey key, byte[] iv, byte[] data, int operationMode)
    {
        byte[] result = null;
        var tdes = new TripleDESCryptoServiceProvider();
        if (operationMode == MODE_DECRYPT)
        {
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            var decryptor = tdes.CreateDecryptor(key.Value, iv);
            result = decryptor.TransformFinalBlock(data, 0, data.Length);
        }
        else if (operationMode == MODE_ENCRYPT)
        {
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            var encryptor = tdes.CreateEncryptor(key.Value, iv);
            result = encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        return result;
    }

    /// <summary>
    ///     Encrypts or decrypts <see cref="data" /> with DES/ECB/NoPadding
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to encrypt or decrypt</param>
    /// <param name="operationMode">Operation mode: either <see cref="MODE_ENCRYPT" /> or <see cref="MODE_DECRYPT" /> </param>
    /// <returns></returns>
    public static byte[] DESECB(DesKey key, byte[] data, int operationMode)
    {
        byte[] result = null;
        var tdes = new DESCryptoServiceProvider();
        if (operationMode == MODE_DECRYPT)
        {
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;
            var decryptor = tdes.CreateDecryptor(key.Value, null);
            result = decryptor.TransformFinalBlock(data, 0, data.Length);
        }
        else if (operationMode == MODE_ENCRYPT)
        {
            tdes.Mode = CipherMode.ECB;
            tdes.Padding = PaddingMode.None;
            var encryptor = tdes.CreateEncryptor(key.Value, null);
            result = encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        return result;
    }

    /// <summary>
    ///     Encrypts or decrypts <see cref="data" /> with DES/CBC/NoPadding
    /// </summary>
    /// <param name="key">Key</param>
    /// <param name="iv">Initial Vector</param>
    /// <param name="data">Data to encrypt or decrypt</param>
    /// <param name="mode">Operation mode: either <see cref="MODE_ENCRYPT" /> or <see cref="MODE_DECRYPT" /> </param>
    /// <returns></returns>
    public static byte[] DESCBC(DesKey key, byte[] iv, byte[] data, int operationMode)
    {
        byte[] result = null;
        var tdes = new DESCryptoServiceProvider();
        if (operationMode == MODE_DECRYPT)
        {
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            var decryptor = tdes.CreateDecryptor(key.Value, iv);
            result = decryptor.TransformFinalBlock(data, 0, data.Length);
        }
        else if (operationMode == MODE_ENCRYPT)
        {
            tdes.Mode = CipherMode.CBC;
            tdes.Padding = PaddingMode.None;
            var encryptor = tdes.CreateEncryptor(key.Value, iv);
            result = encryptor.TransformFinalBlock(data, 0, data.Length);
        }

        return result;
    }


    /// <summary>
    ///     Extracts a subarray from <see cref="source" /> array.
    /// </summary>
    /// <param name="source">Source array</param>
    /// <param name="index">Index</param>
    /// <param name="length">Length</param>
    /// <returns>Subarray from index (inclusive) up to <see cref="length" /> bytes.</returns>
    public static byte[] SubArray(byte[] source, int index, int length)
    {
        var result = new byte[length];
        Array.Copy(source, index, result, 0, length);
        return result;
    }

    #endregion
}