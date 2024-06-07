namespace GlobalPlatform.Net;

public class SecurityLevel
{
    #region Constant Fields

    /// <summary>
    ///     NO SECURITY LEVEL
    /// </summary>
    public const int NO_SECURITY_LEVEL = 0x00;

    /// <summary>
    ///     C-MAC
    /// </summary>
    public const int C_MAC = 0x01;

    /// <summary>
    ///     C-DECRYPTION
    /// </summary>
    public const int C_DECRYPTION = 0x2;

    /// <summary>
    ///     R-MAC
    /// </summary>
    public const int R_MAC = 0x10;

    #endregion

    /// <summary>
    ///     R-DECRYPTION
    /// </summary>
    public const int R_ENCRYPTION = 0x20;
}