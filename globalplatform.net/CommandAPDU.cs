using System;

namespace globalplatform.net;

/// <summary>
///     Represents a command APDU.
/// </summary>
/// ToDo: Support Extended APDU
public class CommandAPDU
{
    #region Pubic Methods

    /// <summary>
    ///     Converts CommandAPDU to corresponding byte array.
    /// </summary>
    /// <returns>Byte array corresponding to this CommandAPDU</returns>
    public byte[] ToByteArray()
    {
        var resultSize = Data.Length + 5;
        if (LE != -1)
            resultSize += 1;
        var result = new byte[resultSize];
        result[OFFSET_CLA] = (byte) CLA;
        result[OFFSET_INS] = (byte) INS;
        result[OFFSET_P1] = (byte) P1;
        result[OFFSET_P2] = (byte) P2;
        result[OFFSET_LC] = (byte) LC;
        Array.Copy(Data, 0, result, OFFSET_CDATA, Data.Length);
        if (LE != -1)
            result[result.Length - 1] = (byte) LE;
        return result;
    }

    #endregion

    #region Constant Fields

    /// <summary>
    ///     CLA offset in APDU
    /// </summary>
    public const byte OFFSET_CLA = 0x0;

    /// <summary>
    ///     INS offset in APDU
    /// </summary>
    public const byte OFFSET_INS = 0x1;

    /// <summary>
    ///     P1 offset in APDU
    /// </summary>
    public const byte OFFSET_P1 = 0x2;

    /// <summary>
    ///     P2 offset in APDU
    /// </summary>
    public const byte OFFSET_P2 = 0x3;

    /// <summary>
    ///     LC offset in APDU
    /// </summary>
    public const byte OFFSET_LC = 0x4;

    /// <summary>
    ///     DATA offset in APDU
    /// </summary>
    public const byte OFFSET_CDATA = 0x5;

    #endregion

    #region Private Fields

    #endregion

    #region Public Properties

    /// <summary>
    ///     CLA
    /// </summary>
    public int CLA { get; }

    /// <summary>
    ///     INS
    /// </summary>
    public int INS { get; }

    /// <summary>
    ///     P1
    /// </summary>
    public int P1 { get; }

    /// <summary>
    ///     P2
    /// </summary>
    public int P2 { get; }

    /// <summary>
    ///     LC
    /// </summary>
    public int LC { get; }

    /// <summary>
    ///     LE
    /// </summary>
    public int LE { get; }

    /// <summary>
    ///     APDU data
    /// </summary>
    public byte[] Data { get; }

    #endregion

    #region Constructors

    /// <summary>
    ///     Constructs CommandAPDU from cla, ins, p1, p2, data and le. LC is
    ///     taken from data.Length
    /// </summary>
    /// <param name="cla">CLA</param>
    /// <param name="ins">INS</param>
    /// <param name="p1">P1</param>
    /// <param name="p2">P2</param>
    /// <param name="le">LE; -1 means no LE</param>
    /// <param name="data">Data</param>
    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data, int le)
    {
        CLA = cla;
        INS = ins;
        P1 = p1;
        P2 = p2;
        if (data != null)
        {
            LC = data.Length;
            Data = new byte[data.Length];
            Array.Copy(data, Data, Data.Length);
        }
        else
        {
            LC = 0;
            Data = new byte[LC];
        }

        LE = le;
    }

    /// <summary>
    ///     Constructs CommandAPDU from cla, ins, p1, p2 and data. It sets -1 for
    ///     LE that means no LE.
    /// </summary>
    /// <param name="cla">CLA</param>
    /// <param name="ins">INS</param>
    /// <param name="p1">P1</param>
    /// <param name="p2">P2</param>
    /// <param name="data">Data</param>
    public CommandAPDU(int cla, int ins, int p1, int p2, byte[] data) : this(cla, ins, p1, p2, data, -1)
    {
    }

    /// <summary>
    ///     Constructs CommandAPDU from raw APDU.
    /// </summary>
    /// <param name="apdu">Raw APDU</param>
    /// <exception cref="Exception">
    ///     * If apdu.Length is less than 5
    ///     * If LC is not equal to (apdu.Length - 5) or (apdu.Length - 5 - 1)
    /// </exception>
    public CommandAPDU(byte[] apdu)
    {
        if (apdu.Length < 5)
            throw new Exception("Wrong APDU length.");

        CLA = apdu[OFFSET_CLA];
        INS = apdu[OFFSET_INS];
        P1 = apdu[OFFSET_P1];
        P2 = apdu[OFFSET_P2];
        LC = apdu[OFFSET_LC];
        if (LC == apdu.Length - 5)
            LE = -1;
        else if (LC == apdu.Length - 5 - 1)
            LE = apdu[apdu.Length - 1];
        else
            throw new Exception("Wrong LC value.");
        Data = new byte[LC];
        Array.Copy(apdu, OFFSET_CDATA, Data, 0, Data.Length);
    }

    #endregion
}