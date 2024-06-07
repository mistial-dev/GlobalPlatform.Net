using System;

namespace GlobalPlatform.Net;

/// <summary>
///     Represents response APDU
/// </summary>
public class ResponseAPDU
{
    #region Methods

    /// <summary>
    ///     Converts ResponseAPDU to a byte array.
    /// </summary>
    /// <returns>Byte array corresponding to ResponseAPDU</returns>
    public byte[] ToByteArray()
    {
        var result = new byte[Data.Length + 2];
        result[result.Length - 2] = (byte) SW1;
        result[result.Length - 1] = (byte) SW2;
        if (Data.Length > 0)
            Array.Copy(Data, 0, result, 2, Data.Length);
        return result;
    }

    #endregion

    #region Private Fields

    #endregion

    #region Public Properties

    /// <summary>
    ///     SW1
    /// </summary>
    public int SW1 { get; }

    /// <summary>
    ///     SW2
    /// </summary>
    public int SW2 { get; }

    /// <summary>
    ///     Response data
    /// </summary>
    public byte[] Data { get; }

    #endregion

    #region Constructors

    /// <summary>
    ///     Constructs a ResponseAPDU from sw1, sw2 and response data.
    /// </summary>
    /// <param name="sw1">sw1</param>
    /// <param name="sw2">sw2</param>
    /// <param name="data">response data</param>
    public ResponseAPDU(int sw1, int sw2, byte[] data)
    {
        SW1 = sw1;
        SW2 = sw2;
        if (data != null)
        {
            Data = new byte[data.Length];
            Array.Copy(data, Data, Data.Length);
        }
        else
        {
            Data = new byte[0];
        }
    }

    /// <summary>
    ///     Constructs a ResponseAPDU from raw response.
    /// </summary>
    /// <param name="response">Raw respose</param>
    /// <exception cref="Exception">If raw response contains less than 2 bytes.</exception>
    public ResponseAPDU(byte[] response)
    {
        if (response.Length < 2)
            throw new Exception("Response APDU must be 2 bytes or more.");
        SW1 = response[^2];
        SW2 = response[^1];
        Data = new byte[response.Length - 2];
        if (Data.Length > 0)
            Array.Copy(response, 0, Data, 0, Data.Length);
    }

    /// <summary>
    /// Constructs a ResponseAPDU from raw response in hex format.
    /// </summary>
    /// <param name="response"></param>
    public ResponseAPDU(string response) : this (Convert.FromHexString(response))
    {
    }

    #endregion
}