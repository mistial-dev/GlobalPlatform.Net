using System;

namespace GlobalPlatform.Net.Crypto;

/// <summary>
///     A set of keys associated with a card or a secure channel
/// </summary>
public class KeySet
{
    #region Constructors

    /// <summary>
    ///     Constructs key set and sets key id and key version
    /// </summary>
    /// <param name="keyId">Key Id</param>
    /// <param name="keyVersion">Key version</param>
    public KeySet(int keyId = 0, int keyVersion = 0)
    {
        KeyVersion = keyVersion;
        KeyId = keyId;
    }

    #endregion


    #region Public Methods

    /// <summary>
    ///     Retrives key of the specified type.
    /// </summary>
    /// <param name="keyType">
    ///     Key type:
    ///     * <see cref="SymmetricKey.KEY_TYPE_ENC" />
    ///     * <see cref="SymmetricKey.KEY_TYPE_MAC" />
    ///     * <see cref="SymmetricKey.KEY_TYPE_RMAC" />
    ///     * <see cref="SymmetricKey.KEY_TYPE_KEK" />
    /// </param>
    /// <returns>Retrieved key</returns>
    /// <exception cref="ArgumentException">If key type is invalid</exception>
    public SymmetricKey RetrieveKey(int keyType)
    {
        var key = keyType switch
        {
            SymmetricKey.KEY_TYPE_ENC => EncKey,
            SymmetricKey.KEY_TYPE_MAC => MacKey,
            SymmetricKey.KEY_TYPE_RMAC => RmacKey,
            SymmetricKey.KEY_TYPE_KEK => KekKey,
            SymmetricKey.KEY_TYPE_DEK => KekKey,
            _ => throw new ArgumentException("Invalid key type")
        };

        return key;
    }

    #endregion

    #region Static Fields

    #endregion

    #region Private Fields

    #endregion

    #region Public Properties

    /// <summary>
    ///     Key Version Number  within an on-card entity may be used to
    ///     differentiate instances or versions of the same key.
    /// </summary>
    public int KeyVersion { get; }

    /// <summary>
    ///     ENC Key
    /// </summary>
    public SymmetricKey EncKey { get; set; }

    /// <summary>
    ///     C-MAC Key
    /// </summary>
    public SymmetricKey MacKey { get; set; }

    /// <summary>
    ///     R-MAC Key
    /// </summary>
    public SymmetricKey RmacKey { get; set; }

    /// <summary>
    ///     KEK Key
    /// </summary>
    public SymmetricKey KekKey { get; set; }
    
    /// <summary>
    /// DEK Key is an alias for KEK Key (SCP03)
    /// </summary>
    public SymmetricKey DekKey
    {
        get { return KekKey; }
        set { KekKey = value;}
    }

    /// <summary>
    ///     Key Identifier which identifies each key within an on-card entity.
    /// </summary>
    public int KeyId { get; }

    /// <summary>
    /// Key Algorithm (default is DES)
    /// </summary>
    public KeyAlgorithm Algorithm { get; set; } = KeyAlgorithm.DES;

    #endregion
}