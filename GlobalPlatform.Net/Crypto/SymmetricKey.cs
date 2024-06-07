using System;
using JetBrains.Annotations;

namespace GlobalPlatform.Net.Crypto;

public abstract class SymmetricKey : ISymmetricKey
{
    #region Constant Fields

    public const int KEY_TYPE_ENC = 0x01;
    public const int KEY_TYPE_MAC = 0x02;
    public const int KEY_TYPE_KEK = 0x03;
    public const int KEY_TYPE_RMAC = 0x04;
    public const int KEY_TYPE_DEK = 0x05;

    #endregion

    #region Private Fields

    #endregion

    #region Public Properties

    /// <summary>
    /// Key value getter as a byte array
    /// </summary>
    [PublicAPI]
    public byte[] Value { get; }

    /// <summary>
    /// Key value getter as a hex string
    /// </summary>
    [PublicAPI]
    public string HexValue => Convert.ToHexString(Value);

    /// <summary>
    ///     Key version
    /// </summary>
    public int KeyVersion { get; }

    /// <summary>
    ///     Key Id
    /// </summary>
    public int KeyId { get; }

    #endregion

    #region Constructors

    /// <summary>
    ///     Constructs a key from byte array
    /// </summary>
    /// <param name="value">Key value</param>
    /// <param name="keyId">Key Id</param>
    /// <param name="keyVersion">Key Version</param>
    [PublicAPI]
    protected SymmetricKey(byte[] value, int keyId = 0, int keyVersion = 0)
    {
        Value = value;
        KeyId = keyId;
        KeyVersion = keyVersion;
    }

    /// <summary>
    ///     Constructs a key from hex string represntation
    /// </summary>
    /// <param name="hexValue">Key value</param>
    /// <param name="keyId">Key Id</param>
    /// <param name="keyVersion">Key Version</param>
    [PublicAPI]
    protected SymmetricKey(string hexValue, int keyId = 0, int keyVersion = 0)
    {
        // Convert the hex string to a byte array
        Value = Convert.FromHexString(hexValue);
        KeyId = keyId;
        KeyVersion = keyVersion;
    }

    #endregion

    #region Public Methods

    /// <summary>
    ///     Builds 3DES key from this key value
    /// </summary>
    /// <returns></returns>
    public byte[] BuildTripleDesKey()
    {
        var tdesKey = new byte[24];
        Array.Copy(Value, 0, tdesKey, 0, 16);
        Array.Copy(Value, 0, tdesKey, 16, 8);
        return tdesKey;
    }

    /// <summary>
    ///     Builds DES key from this key value
    /// </summary>
    /// <returns></returns>
    public byte[] BuildDesKey()
    {
        var desKey = new byte[8];
        Array.Copy(Value, 0, desKey, 0, 8);
        return desKey;
    }

    #endregion
}