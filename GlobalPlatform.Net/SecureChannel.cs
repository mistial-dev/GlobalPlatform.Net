using System;
using System.IO;
using System.Linq;
using GlobalPlatform.Net.Crypto;

namespace GlobalPlatform.Net;

public class SecureChannel
{
    #region Private Methods

    private void ConfigureImplementation(int scpImplementationOption)
    {
        switch (scpImplementationOption)
        {
            case Session.IMPL_OPTION_I_1B:
            case Session.IMPL_OPTION_I_1A:
            case Session.IMPL_OPTION_I_15:
            case Session.IMPL_OPTION_I_14:
                mICVEncryption = true;
                break;
            default:
                mICVEncryption = false;
                break;
        }

        switch (scpImplementationOption)
        {
            case Session.IMPL_OPTION_I_0A:
            case Session.IMPL_OPTION_I_0B:
            case Session.IMPL_OPTION_I_1A:
            case Session.IMPL_OPTION_I_1B:
                mApplyToModifiedAPDU = false;
                break;
            default:
                mApplyToModifiedAPDU = true;
                break;
        }
    }

    #endregion

    #region Private Fields

    private int mSecurityLevel;
    private readonly int mSCPIdentifier;
    private byte[] mICV;
    private byte[] mRICV;
    private bool mApplyToModifiedAPDU;
    private bool mICVEncryption;
    private MemoryStream mRMACStream;
    private bool mSecurityLevelSet;
    private bool mFirstCommandInChain;

    #endregion

    #region Public Properties

    /// <summary>
    ///     Security level of established secure channel
    /// </summary>
    public int SecurityLevel
    {
        get => mSecurityLevel;
        set
        {
            if (!mSecurityLevelSet)
            {
                mSecurityLevel = value;
                if ((mSecurityLevel & Net.SecurityLevel.R_MAC) != 0)
                    Array.Copy(mICV, mRICV, 8);
                mSecurityLevelSet = true;
            }
            else
            {
                throw new Exception(
                    "Security level can be set just once and automatically by CreateExternalAuthCommand() method " +
                    "after a successful EXTERNAL AUTHENTICATE command.");
            }
        }
    }

    /// <summary>
    ///     Secure channel session key set
    /// </summary>
    public KeySet SessionKeys { get; }
    
    public LogicalChannel LogicalChannel { get; set; }

    #endregion

    /// <summary>
    ///     Constructs a secure channel
    /// </summary>
    /// <param name="sessionKeys">Session Keys</param>
    /// <param name="securityLevel">Security Level</param>
    /// <param name="scpIdentifier">
    ///     Secure Channel Identifer: either <see cref="Session.SCP_01" /> or
    ///     <see cref="Session.SCP_02" />.
    /// </param>
    /// <param name="scpImplementationOption">Secure Channel Implementation Option: See GlobalPlatform.IMPL_OPTION_* </param>
    /// <param name="icv">Initial Chaining Vector</param>
    /// <param name="ricv">Response Initial Chaingin Vector</param>
    public SecureChannel(KeySet sessionKeys, int securityLevel, int scpIdentifier, int scpImplementationOption,
        byte[] icv, byte[] ricv)
    {
        SessionKeys = sessionKeys;
        mSecurityLevel = securityLevel;
        mSCPIdentifier = scpIdentifier;
        mICV = icv;
        mRICV = ricv;
        mFirstCommandInChain = true;

        ConfigureImplementation(scpImplementationOption);
    }

    public CommandAPDU wrap(CommandAPDU command)
    {
        // Apply R-MAC
        if ((mSecurityLevel & Net.SecurityLevel.R_MAC) != 0)
        {
            if (mRMACStream != null)
                throw new Exception(
                    "There exists an unwrapped response while R-MAC security level set. Secure channel can only work correctly if " +
                    "for each wrapped command the corresponding response be unwrapped immediately.");
            mRMACStream = new MemoryStream();

            //Clear 3 LSB of CLA
            mRMACStream.WriteByte((byte) (command.CLA & ~0x07));
            mRMACStream.WriteByte((byte) command.INS);
            mRMACStream.WriteByte((byte) command.P1);
            mRMACStream.WriteByte((byte) command.P2);
            if (command.LC > 0)
            {
                mRMACStream.WriteByte((byte) command.LC);
                mRMACStream.Write(command.Data, 0, command.Data.Length);
            }
        }

        if ((mSecurityLevel & (Net.SecurityLevel.C_MAC | Net.SecurityLevel.C_DECRYPTION)) == 0)
            return command;

        var secureCLA = command.CLA;
        byte[] wrappedData = null;
        var wrappedDataSize = command.LC;

        var commandStream = new MemoryStream();

        var maxCommandSize = 255;
        if ((mSecurityLevel & Net.SecurityLevel.C_MAC) != 0)
            maxCommandSize -= 8;
        if ((mSecurityLevel & Net.SecurityLevel.C_DECRYPTION) != 0)
            maxCommandSize -= 8;
        if (command.LC > maxCommandSize)
            throw new Exception(
                "APDU command too large. Max command length = 255 - 8(for C-MAC if present) - 8(for C-DECRYTPION padding if present).");

        if ((mSecurityLevel & Net.SecurityLevel.C_MAC) != 0)
        {
            if (mFirstCommandInChain)
            {
                mFirstCommandInChain = false;
            }
            else if (mICVEncryption)
            {
                if (mSCPIdentifier == Session.SCP_01)
                {
                    mICV = CryptoUtil.TripleDESECB(
                        new DesKey(SessionKeys.MacKey.BuildTripleDesKey()), mICV, CryptoUtil.ModeEncrypt);
                }
                else
                {
                    mICV = CryptoUtil.DESECB(new DesKey(SessionKeys.MacKey.BuildDesKey()), mICV, CryptoUtil.ModeEncrypt);
                }
            } // If ICV Encryption

            if (mApplyToModifiedAPDU)
            {
                secureCLA = command.CLA | 0x04;
                wrappedDataSize += 8;
            }

            commandStream.WriteByte((byte) secureCLA);
            commandStream.WriteByte((byte) command.INS);
            commandStream.WriteByte((byte) command.P1);
            commandStream.WriteByte((byte) command.P2);
            commandStream.WriteByte((byte) wrappedDataSize);
            commandStream.Write(command.Data, 0, command.Data.Length);
            if (mSCPIdentifier == Session.SCP_01)
            {
                mICV = CryptoUtil.FullTripleDESMAC(
                    SessionKeys.MacKey, mICV, CryptoUtil.DESPad(commandStream.ToArray()));
            }
            else
            {
                mICV = CryptoUtil.SingleDESFullTripleDESMAC(
                    SessionKeys.MacKey, mICV, CryptoUtil.DESPad(commandStream.ToArray()));
            }

            if (!mApplyToModifiedAPDU)
            {
                secureCLA = command.CLA | 0x04;
                wrappedDataSize += 8;
            }

            wrappedData = command.Data;
            commandStream = new MemoryStream();
        } // If C-MAC

        if ((mSecurityLevel & Net.SecurityLevel.C_DECRYPTION) != 0 && command.LC > 0)
        {
            if (mSCPIdentifier == Session.SCP_01)
            {
                if ((command.LC + 1) % 8 != 0)
                {
                    commandStream.WriteByte((byte) command.LC);
                    commandStream.Write(command.Data, 0, command.Data.Length);
                    var paddedData = CryptoUtil.DESPad(commandStream.ToArray());
                    commandStream = new MemoryStream();
                    commandStream.Write(paddedData, 0, paddedData.Length);
                }
                else
                {
                    commandStream.WriteByte((byte) command.LC);
                    commandStream.Write(command.Data, 0, command.Data.Length);
                }
            } // If SCP '01'
            else
            {
                var paddedData = CryptoUtil.DESPad(command.Data);
                commandStream.Write(paddedData, 0, paddedData.Length);
            }

            wrappedDataSize += (int) (commandStream.Length - command.Data.Length);
            wrappedData = CryptoUtil.TripleDESCBC(
                new DesKey(SessionKeys.EncKey.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock,
                commandStream.ToArray(), CryptoUtil.ModeEncrypt);
            commandStream = new MemoryStream();
        } // If C-DECRYPTION

        commandStream.WriteByte((byte) secureCLA);
        commandStream.WriteByte((byte) command.INS);
        commandStream.WriteByte((byte) command.P1);
        commandStream.WriteByte((byte) command.P2);
        if (wrappedDataSize > 0)
        {
            commandStream.WriteByte((byte) wrappedDataSize);
            commandStream.Write(wrappedData, 0, wrappedData.Length);
        }

        if ((mSecurityLevel & Net.SecurityLevel.C_MAC) != 0)
            commandStream.Write(mICV, 0, mICV.Length);
        if (command.LE > 0)
            commandStream.WriteByte((byte) command.LE);

        return new CommandAPDU(commandStream.ToArray());
    }

    public ResponseAPDU unwrap(ResponseAPDU response)
    {
        if ((mSecurityLevel & Net.SecurityLevel.R_MAC) != 0)
        {
            if (response.Data.Length < 8)
                throw new Exception("Response data length must be at least 8 bytes.");

            if (mRMACStream == null)
                throw new Exception(
                    "No corresponding wrapped command found while R-MAC security level set. Secure channel can only work correctly if " +
                    "for each wrapped command the corresponding response be unwrapped immediately.");
            var realResponseLength = response.Data.Length - 8;
            mRMACStream.WriteByte((byte) realResponseLength);
            mRMACStream.Write(response.Data, 0, realResponseLength);
            mRMACStream.WriteByte((byte) response.SW1);
            mRMACStream.WriteByte((byte) response.SW2);

            mRICV = CryptoUtil.SingleDESFullTripleDESMAC(
                SessionKeys.RmacKey, mRICV, CryptoUtil.DESPad(mRMACStream.ToArray()));

            var realMac = new byte[8];
            Array.Copy(response.Data, realResponseLength, realMac, 0, 8);
            if (realMac.SequenceEqual(mRICV))
                throw new Exception("Invalid R-MAC.");
            mRMACStream = null;
            response = new ResponseAPDU(
                response.SW1, response.SW2, CryptoUtil.SubArray(response.Data, 0, realResponseLength));
        }

        return response;
    }
}

