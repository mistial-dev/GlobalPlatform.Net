namespace globalplatform.net;

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
    ///     * <see cref="Key.KEY_TYPE_ENC" />
    ///     * <see cref="Key.KEY_TYPE_MAC" />
    ///     * <see cref="Key.KEY_TYPE_RMAC" />
    ///     * <see cref="Key.KEY_TYPE_KEK" />
    /// </param>
    /// <returns>Retrieved key</returns>
    public Key RetrieveKey(int keyType)
    {
        Key key = null;
        switch (keyType)
        {
            case Key.KEY_TYPE_ENC:
                key = EncKey;
                break;
            case Key.KEY_TYPE_MAC:
                key = MacKey;
                break;
            case Key.KEY_TYPE_RMAC:
                key = RmacKey;
                break;
            case Key.KEY_TYPE_KEK:
                key = KekKey;
                break;
        }

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
    public Key EncKey { get; set; }

    /// <summary>
    ///     C-MAC Key
    /// </summary>
    public Key MacKey { get; set; }

    /// <summary>
    ///     R-MAC Key
    /// </summary>
    public Key RmacKey { get; set; }

    /// <summary>
    ///     KEK Key
    /// </summary>
    public Key KekKey { get; set; }

    /// <summary>
    ///     Key Identifier which identifies each key within an on-card entity.
    /// </summary>
    public int KeyId { get; }

    #endregion
}