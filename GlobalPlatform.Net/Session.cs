using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using GlobalPlatform.Net.Crypto;
using JetBrains.Annotations;
using log4net;

namespace GlobalPlatform.Net;

/// <summary>
///     An implementation of Global Platform services. It is designed to be used for indirect
///     and asynchronous management of Global Platform compliant cards.
/// </summary>
public class Session
{
#if DEBUG
    /// <summary>
    /// Logger
    /// </summary>
    private static readonly ILog Log = LogManager.GetLogger(typeof(Session));
#endif
    
    /// <summary>
    ///     Global Platform CLA
    /// </summary>
    public const byte CLA_GP = 0x80;

    /// <summary>
    ///     Global Platform secure messaging CLA
    /// </summary>
    public const byte CLA_SECURE_GP = 0x84;

    /// <summary>
    ///     Card default secure channel protocol.  0x00 is valid for SCP03, so use a flag instead.
    /// </summary>
    public const int SCP_ANY = -1;

    /// <summary>
    ///     SCP '01' Secure channel protocol identifier
    /// </summary>
    public const int SCP_01 = 0x01;

    /// <summary>
    ///     SCP '02' Secure channel protocol identifier
    /// </summary>
    public const int SCP_02 = 0x02;

    /// <summary>
    ///     SCP '03' Secure channel protocol identifier
    /// </summary>
    public const int SCP_03 = 0x03;

    /// <summary>
    ///     Card default secure channel implementation option
    /// </summary>
    public const int IMPL_OPTION_ANY = 0x00;

    /// <summary>
    ///     Implementation option "i" = '04': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV
    ///     encryption, 1
    ///     Secure Channel base key.
    /// </summary>
    public const int IMPL_OPTION_I_04 = 0x04;

    /// <summary>
    ///     Implementation option "i" = '05': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, no ICV
    ///     encryption, 3
    ///     Secure Channel Keys.
    /// </summary>
    public const int IMPL_OPTION_I_05 = 0x05;

    /// <summary>
    ///     Implementation option "i" = '0A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no
    ///     ICV
    ///     encryption, 1 Secure Channel base key.
    /// </summary>
    public const int IMPL_OPTION_I_0A = 0x0A;

    /// <summary>
    ///     Implementation option "i" = '0B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, no
    ///     ICV
    ///     encryption, 3 Secure Channel Keys.
    /// </summary>
    public const int IMPL_OPTION_I_0B = 0x0B;

    /// <summary>
    ///     Implementation option "i" = '14': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption
    ///     for
    ///     C-MAC session, 1 Secure Channel base key.
    /// </summary>
    public const int IMPL_OPTION_I_14 = 0x14;

    /// <summary>
    ///     Implementation option "i" = '15': Initiation mode explicit, C-MAC on modified APDU, ICV set to zero, ICV encryption
    ///     for C-MAC session, 3
    ///     Secure Channel Keys.
    /// </summary>
    public const int IMPL_OPTION_I_15 = 0x15;

    /// <summary>
    ///     "i" = '1A': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV
    ///     encryption for C-MAC session, 1 Secure Channel base key.
    /// </summary>
    public const int IMPL_OPTION_I_1A = 0x1A;

    /// <summary>
    ///     "i" = '1B': Initiation mode implicit, C-MAC on unmodified APDU, ICV set to MAC over AID, ICV
    ///     encryption for C-MAC session,3 Secure Channel Keys.
    /// </summary>
    public const int IMPL_OPTION_I_1B = 0x1B;

    /// <summary>
    /// "i" = 00 (SCP03): Random Card Challenge, no R-MAC/R-ENCRYPTION Support
    /// </summary>
    public const int IMPL_OPTION_I_00 = 0x00;

    // IMPL_OPTION_I_00 or IMPL_OPTION_I_10 or IMPL_OPTION_I_20 or IMPL_OPTION_I_30 or IMPL_OPTION_I_70

    /// <summary>
    /// "i" = 10 (SCP03): Pseudo Random Card Challenge, no R-MAC/R-ENCRYPTION
    /// </summary>
    public const int IMPL_OPTION_I_10 = 0x10;

    /// <summary>
    /// "i" = 20 (SCP03): Random Card Challenge, R-MAC, no R-ENCRYPTION
    /// </summary>
    public const int IMPL_OPTION_I_20 = 0x20;

    /// <summary>
    /// "i" = 30 (SCP03): Pseudo-Random Card Challenge, R-MAC, no R-ENCRYPTION
    /// </summary>
    public const int IMPL_OPTION_I_30 = 0x30;

    /// <summary>
    /// "i" = 60 (SCP03): Random Card Challenge, R-MAC, R-ENCRYPTION
    /// </summary>
    public const int IMPL_OPTION_I_60 = 0x60;

    /// <summary>
    /// "i" = 70 (SCP03): Pseudo-Random Card Challenge, R-MAC, R-ENCRYPTION
    /// </summary>
    public const int IMPL_OPTION_I_70 = 0x70;

    /// <summary>
    ///     INITIALIZE UPDATE Command
    /// </summary>
    public const byte INS_INIT_UPDATE = 0x50;

    /// <summary>
    ///     EXTERNAL AUTHENTICATE Command
    /// </summary>
    public const byte INS_EXT_AUTH = 0x82;

    /// <summary>
    ///     PUT KEY Command
    /// </summary>
    public const byte INS_PUT_KEY = 0xD8;

    /// <summary>
    ///     Format 1 for PUT Key command
    /// </summary>
    public const int KEY_FORMAT_1 = 0x01;

    /// <summary>
    ///     Format 2 for PUT Key command. It is reserved for future use.
    /// </summary>
    public const int KEY_FORMAT_2 = 0x02;

    /// <summary>
    /// Offset for the Key Version Number in the INITIALIZE UPDATE command
    /// </summary>
    private const int OFFSET_KVN = 0x0A;

    /// <summary>
    /// Offset for the SCP ID in the INITIALIZE UPDATE command
    /// </summary>
    private const int OFFSET_SCP_ID = 0x0B;
    
    /// <summary>
    /// Offset for the Key Information in the INITIALIZE UPDATE response
    /// </summary>
    private const int OFFSET_KEY_INFO_SCP_VERSION = 0x01;


    /// <summary>
    /// Offset for the SCP Implementation Option in the INITIALIZE UPDATE command
    /// </summary>
    private const int OFFSET_IMPLEMENTATION_SCP03 = 0x0C;
    
    /// <summary>
    /// Offset for the SCP Implementation Option in the INITIALIZE UPDATE response
    /// </summary>
    private const int OFFSET_KEY_INFO_IMPL = 0x02;

    private static readonly byte[] ConstantMac0101 = [0x01, 0x01];
    private static readonly byte[] ConstantRMac0102 = [0x01, 0x02];
    private static readonly byte[] ConstantEnc0182 = [0x01, 0x82];
    private static readonly byte[] ConstantDek0181 = [0x01, 0x81];

    private byte[]? _hostChallenge;

    private byte[] _InitUpdateResponse = [];

    private int mSCPIdentifier;

    private int mSCPImplementationOption;

    private int mSecurityLevel;

    private KeySet mSessionKeys;

    /// <summary>
    /// Static keys for the secure channel
    /// </summary>
    private KeySet mStaticKeys;

    /// <summary>
    ///     Secure Channel
    /// </summary>
    [PublicAPI]
    public SecureChannel SecureChannel { get; private set; }

    /// <summary>
    /// Which logical channel to use
    /// </summary>
    public LogicalChannel Channel { get; set; } = LogicalChannel.BasicChannel;

    /// <summary>
    /// Contains the value of the Host Challenge
    /// </summary>
    [PublicAPI]
    public byte[]? HostChallenge
    {
        // Default getter
        get => _hostChallenge;

        set
        {
            // Ensure that the host challenge is 8 bytes
            if (value?.Length != 8)
                throw new ArgumentException("Host challenge must be 8 bytes long.");
            _hostChallenge = value;
        }
    }

    private static void CheckResponse(int sw1, int sw2, string message)
    {
        if (sw1 != 0x90 && sw2 != 0x00)
            throw new Exception(message);
    }

    /// <summary>
    /// Generate the required session keys for SCP01
    /// </summary>
    /// <param name="cardResponse"></param>
    /// <returns></returns>
    private KeySet GenerateSessionKeysSCP01(byte[] cardResponse)
    {
        var sessionKeySet = new KeySet();
        var derivationData = new byte[16];

        Array.Copy(cardResponse, 16, derivationData, 0, 4);
        Array.Copy(HostChallenge, 0, derivationData, 4, 4);
        Array.Copy(cardResponse, 12, derivationData, 8, 4);
        Array.Copy(HostChallenge, 4, derivationData, 12, 4);

        sessionKeySet.EncKey = new DesKey(
            CryptoUtil.TripleDESECB(
                new DesKey(mStaticKeys.EncKey.BuildTripleDesKey()), derivationData, CryptoUtil.ModeEncrypt));
        sessionKeySet.MacKey = new DesKey(
            CryptoUtil.TripleDESECB(
                new DesKey(mStaticKeys.MacKey.BuildTripleDesKey()), derivationData, CryptoUtil.ModeEncrypt));
        sessionKeySet.KekKey = new DesKey(mStaticKeys.KekKey.Value);

        return sessionKeySet;
    }

    /// <summary>
    /// Generate the required session keys for SCP02
    /// </summary>
    /// <param name="sequenceCounter"></param>
    /// <returns></returns>
    private KeySet GenerateSessionKeysSCP02(byte[] sequenceCounter)
    {
        var sessionKeySet = new KeySet();
        var derivationData = new byte[16];
        Array.Copy(sequenceCounter, 0, derivationData, 2, 2);
        Array.Clear(derivationData, 4, 12);


        // Todo: consider implicit case

        // Derive session MAC key
        Array.Copy(ConstantMac0101, 0, derivationData, 0, 2);
        sessionKeySet.MacKey = new DesKey(
            CryptoUtil.TripleDESCBC(
                new DesKey(mStaticKeys.MacKey.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock, derivationData,
                CryptoUtil.ModeEncrypt));

        // Derive session R-MAC key
        // To build R-MAC key static MAC key is used.
        Array.Copy(ConstantRMac0102, 0, derivationData, 0, 2);
        sessionKeySet.RmacKey = new DesKey(
            CryptoUtil.TripleDESCBC(
                new DesKey(mStaticKeys.MacKey.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock, derivationData,
                CryptoUtil.ModeEncrypt));

        // Derive session ENC key
        Array.Copy(ConstantEnc0182, 0, derivationData, 0, 2);
        sessionKeySet.EncKey = new DesKey(
            CryptoUtil.TripleDESCBC(
                new DesKey(mStaticKeys.EncKey.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock, derivationData,
                CryptoUtil.ModeEncrypt));

        // Derive session KEK key
        Array.Copy(ConstantDek0181, 0, derivationData, 0, 2);
        sessionKeySet.KekKey = new DesKey(
            CryptoUtil.TripleDESCBC(
                new DesKey(mStaticKeys.KekKey.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock, derivationData,
                CryptoUtil.ModeEncrypt));


        return sessionKeySet;
    }
    
    /// <summary>
    /// Generate the required session keys for SCP03
    /// </summary>
    /// <param name="initUpdateResponse">Response from InitializeUpdate</param>
    /// <returns>Keyset</returns>
    /// <exception cref="NotImplementedException"></exception>
    private KeySet GenerateSessionKeysSCP03(byte[] initUpdateResponse)
    {
        // Copy required data from the response
        var diversificationData = new byte[10];
        Array.Copy(initUpdateResponse, 0x00, diversificationData, 0, 0x0A);
        
        var keyInfo = new byte[3];
        Array.Copy(initUpdateResponse, 0x0A, keyInfo, 0, 0x03);
        
        var cardChallenge = new byte[8];
        Array.Copy(initUpdateResponse, 0x0C, cardChallenge, 0, 0x08);
        
        var cardCryptogram = new byte[8];
        Array.Copy(initUpdateResponse, 0x14, cardCryptogram, 0, 0x08);
        
        var sequenceCounter = new byte[2];
        Array.Copy(initUpdateResponse, 0x0C, sequenceCounter, 0, 0x02);
        
        // Validate the key information
        if (!ValidateScp03KeyInfo(keyInfo))
            throw new Exception("Invalid key information for SCP03.");
        
        // We need the host challenge to generate the session keys
        if (HostChallenge == null)
            throw new Exception("Host challenge must be set before generating session keys.");
        
        // Derive the session keys
        // GPC 2.2, Appendix D, 6.2.1: AES Session Keys
        // AES session keys shall be generated every time a Secure Channel is initiated and are used in the mutual 
        // authentication process
        // The session keys are derived from the static Secure Channel keys. The encryption key S-ENC is derived 
        // from Key-ENC. The Secure Channel MAC key S-MAC is derived from Key-MAC. Optionally (if the “i” 
        // parameter indicates R-MAC support), the Secure Channel R-MAC key S-RMAC is derived from Key-MAC. No AES session keys are generated for key and sensitive data encryption operations. That allows 
        // pre-processed data loading and simplifies the personalization process.
        var sessionKeys = new KeySet();
        
        // Ensure that the required keys exist
        if (mStaticKeys.EncKey == null || mStaticKeys.MacKey == null)
            throw new Exception("All keys must be provided.");
        
        // Ensure that all keys are the same length
        var encKeyLength = mStaticKeys.EncKey.Value.Length;
        var macKeyLength = mStaticKeys.MacKey.Value.Length;
        if (encKeyLength != macKeyLength)
            throw new Exception("All keys must be the same length.");
        
        // Derive the three session keys: S-ENC, S-MAC, and S-RMAC
        // GPC 2.2 6.2.1:
        // "The “context“ parameter shall be set to the concatenation of the host challenge (8 bytes) and the card 
        // challenge (8 bytes)."
        var context = new byte[16];
        Array.Copy(HostChallenge, 0, context, 0, 8);
        Array.Copy(cardChallenge, 0, context, 8, 8);
        
        // Derive the session keys
        var sEncKey = Scp03.Kdf(mStaticKeys.EncKey, context);
        var sMacKey = Scp03.Kdf(mStaticKeys.MacKey, context);
        var sRMacKey = Scp03.Kdf(mStaticKeys.MacKey, context, Scp03.COUNTER_SECOND_ITERATION);
        
        // Set the session keys
        sessionKeys.EncKey = new AesKey(sEncKey.Value);
        sessionKeys.MacKey = new AesKey(sMacKey.Value);
        sessionKeys.RmacKey = new AesKey(sRMacKey.Value);
        
        return sessionKeys;
    }

    /// <summary>
    /// Validate the key information for SCP03
    /// </summary>
    /// <param name="keyInfo"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    private static bool ValidateScp03KeyInfo(byte[] keyInfo)
    {
        // Check the length of the key information
        if (keyInfo.Length != 3)
            return false;
        
        // Check the key version number
        if (keyInfo[OFFSET_KEY_INFO_SCP_VERSION] != SCP_03)
            return false;

        // Check the implementation option for SCP03 (bits 5, 6, and 7 only)
        return keyInfo[OFFSET_KEY_INFO_IMPL] is IMPL_OPTION_I_00 or IMPL_OPTION_I_10 or IMPL_OPTION_I_20 or IMPL_OPTION_I_30 or IMPL_OPTION_I_60 or IMPL_OPTION_I_70;
    }

    private byte[] EncodeKeyData(DesKey key, DesKey kek, bool addKCV, int keyFormat)
    {
        var keyData = new MemoryStream();
        if (keyFormat == KEY_FORMAT_1)
        {
            // Key encryption algorithm
            keyData.WriteByte(CryptoUtil.AlgDes);

            // Encrypted key data length
            keyData.WriteByte(0x10);

            var encryptedKey = CryptoUtil.TripleDESECB(kek, key.Value, CryptoUtil.ModeEncrypt);
            keyData.Write(encryptedKey, 0, encryptedKey.Length);

            if (addKCV)
            {
                // KCV length
                keyData.WriteByte(0x03);

                // Calculate KCV
                var kcv = CryptoUtil.TripleDESECB(
                    new DesKey(key.BuildTripleDesKey()), CryptoUtil.BinaryZeros8ByteBlock, CryptoUtil.ModeEncrypt);
                keyData.Write(kcv, 0, 3);
            }
            else
            {
                keyData.WriteByte(0x00);
            }
        }

        return keyData.ToArray();
    }

    /// <summary>
    ///     Generates INITIALIZE UPDATE command with specified static key set.
    /// </summary>
    /// <param name="staticKeySet">Secure channel static key set</param>
    /// <param name="securityLevel">
    ///     Security level. It must be a valid combination of
    ///     security level bit pattern defined in <see cref="SecurityLevel" />.
    /// </param>
    /// <param name="scpIdentifier">
    ///     Secure Channel Identifier according to Global Platform 2.1.1 Card Spec section 8.6.
    ///     Currently SCP '01' and SCP '02' is supported. Use <see cref="SCP_ANY" /> if you are not sure.
    /// </param>
    /// <param name="scpImplementationOption">
    ///     Secure Channel Implementation Option according to
    ///     Global Platform 2.1.1 Card Spec section D.1.1 for SCP '01' or section E.1.1 for SCP '02'. Use
    ///     <see cref="IMPL_OPTION_ANY" />
    ///     along with <see cref="SCP_ANY" /> for Secure Channel Identifier, if you are not sure.
    /// </param>
    /// <returns>CommandAPDU for INITIALIZE UPDATE command for specified static key set</returns>
    public CommandAPDU CreateInitUpdateCommand(KeySet staticKeySet, int securityLevel, int scpIdentifier = SCP_ANY,
        int scpImplementationOption = IMPL_OPTION_ANY)
    {
#if DEBUG
        Log.Debug("Creating INITIALIZE UPDATE command.");
#endif
        
        // Validate Secure Channel Identifier
        if (scpIdentifier != SCP_01 && scpIdentifier != SCP_02 && scpIdentifier != SCP_03 && scpIdentifier != SCP_ANY)
            throw new Exception(
                "Invalid secure channel protocol identifier. Currently SCP 01 (0x01), SCP 02 (0x02), and SCP 03 (0x03) are valid." +
                " See Global Platform Card Specification 2.3.1");
        
        // If R_ENCRYPTION is set, then only SCP03 is supported
        if ((securityLevel & SecurityLevel.R_ENCRYPTION) == SecurityLevel.R_ENCRYPTION)
        {
            if (scpIdentifier == SCP_ANY)
            {
                scpIdentifier = SCP_03;
            } else if (scpIdentifier != SCP_03)
            {
                throw new ArgumentException("R_ENCRYPTION is only supported with SCP03.");
            }
        }

        switch (scpIdentifier)
        {
            // Validate Secure Channel Implementation Option
            case SCP_ANY when scpIdentifier is not (SCP_03 or SCP_ANY):
                throw new ArgumentException(
                    "Secure Channel Implementation Option IMPL_OPTION_ANY can only be used along with Secure Channel Identifier SCP_ANY or SCP_03.");
            case SCP_ANY when scpImplementationOption != IMPL_OPTION_I_05 && scpImplementationOption != IMPL_OPTION_I_15 &&
                              scpImplementationOption != IMPL_OPTION_ANY:
                throw new ArgumentException(
                    "Invalid implementation option. Only IMPL_OPTION_I_05, IMPL_OPTION_I_15 or IMPL_OPTION_ANY can be used along with SCP_ANY.");
            // Validate Secure Channel Implementation Option for SCP 01
            case SCP_01 when scpImplementationOption != IMPL_OPTION_I_05 && scpImplementationOption != IMPL_OPTION_I_15:
                throw new ArgumentException(
                    "Invalid implementation option for SCP 01. See Global Platform 2.1.1 Card Spec section D.1.1.");
            // Validate Secure Channel Implementation Option for SCP 02
            case SCP_02 when scpImplementationOption != IMPL_OPTION_I_04 && scpImplementationOption != IMPL_OPTION_I_05 &&
                             scpImplementationOption != IMPL_OPTION_I_0A && scpImplementationOption != IMPL_OPTION_I_0B &&
                             scpImplementationOption != IMPL_OPTION_I_14 && scpImplementationOption != IMPL_OPTION_I_15 &&
                             scpImplementationOption != IMPL_OPTION_I_1A && scpImplementationOption != IMPL_OPTION_I_1B:
                throw new ArgumentException(
                    "Invalid implementation option for SCP 02. See Global Platform 2.1.1 Card Spec section E.1.1.");
            case SCP_02 when scpImplementationOption is IMPL_OPTION_I_0A or IMPL_OPTION_I_0B or IMPL_OPTION_I_1A or IMPL_OPTION_I_1B:
                throw new ArgumentException("Implicit secure channel can't be initialized explicitly.");
            // Validate Secure Channel Implementation Option for SCP 03
            case SCP_03 when scpImplementationOption is not (IMPL_OPTION_I_00 or IMPL_OPTION_I_10 or IMPL_OPTION_I_20 or IMPL_OPTION_I_30 or IMPL_OPTION_I_60 or IMPL_OPTION_I_70):
                throw new ArgumentException(
                    "Invalid implementation option for SCP03.  See GlobalPlatform Secure Channel Protocol '03' - Public Release v1.1.2");
        }

        mSCPIdentifier = scpIdentifier;
        mSCPImplementationOption = scpImplementationOption;
        mStaticKeys = staticKeySet;
        mSecurityLevel = securityLevel;

        // Validate Security Level
        var validSecurityLevel = ValidateSecurityLevel(securityLevel, mSCPIdentifier);

        if (!validSecurityLevel)        
            throw new Exception(
                "Invalid security level. See Global Platform 2.1.1 Card Spec section E.5.2.3 or section D.4.2.3.");

        // If we already have the host challenge, we don't need to generate another
        if (HostChallenge != null)
            return new CommandAPDU(
                CLA_GP, INS_INIT_UPDATE, staticKeySet.KeyVersion, staticKeySet.KeyId, HostChallenge, 0x00);
        
        HostChallenge = new byte[8];
        var rng = RandomNumberGenerator.Create();
        rng.GetBytes(HostChallenge);

        // Build INITIALIZE UPDATE command
        return new CommandAPDU(
            CLA_GP, INS_INIT_UPDATE, staticKeySet.KeyVersion, staticKeySet.KeyId, HostChallenge, 0x00);
    }

    /// <summary>
    /// Validates the security level based on the secure channel protocol version.
    /// </summary>
    /// <param name="securityLevel"></param>
    /// <param name="scpVersion"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentException"></exception>
    private static bool ValidateSecurityLevel(int securityLevel, int scpVersion)
    {
        var validSecurityLevel = scpVersion switch
        {
            SCP_01 or SCP_02 => securityLevel switch
            {
                SecurityLevel.NO_SECURITY_LEVEL => true,
                SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC | SecurityLevel.R_MAC => true,
                SecurityLevel.C_MAC | SecurityLevel.R_MAC => true,
                SecurityLevel.R_MAC => true,
                SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC => true,
                SecurityLevel.C_MAC => true,
                _ => false
            },
            SCP_03 => securityLevel switch
            {
                SecurityLevel.NO_SECURITY_LEVEL => true,
                SecurityLevel.C_MAC => true,
                SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC => true,
                SecurityLevel.R_MAC => true,
                SecurityLevel.R_MAC | SecurityLevel.C_MAC => true,
                SecurityLevel.R_MAC | SecurityLevel.C_DECRYPTION | SecurityLevel.C_MAC => true,
                SecurityLevel.R_ENCRYPTION | SecurityLevel.R_MAC => true,
                SecurityLevel.R_MAC | SecurityLevel.R_ENCRYPTION | SecurityLevel.C_MAC |
                    SecurityLevel.C_DECRYPTION => true,
                _ => false
            },
            _ => throw new ArgumentException("Invalid secure channel protocol identifier.")
        };
        return validSecurityLevel;
    }

    /// <summary>
    /// Process the response of INITIALIZE UPDATE command.
    /// </summary>
    /// <param name="response"></param>
    [PublicAPI]
    public void ProcessInitUpdateResponse(string response)
    {
        var responseApdu = new ResponseAPDU(response);
        ProcessInitUpdateResponse(responseApdu);
    }

    /// <summary>
    /// Process the response of INITIALIZE UPDATE command.
    /// </summary>
    /// <param name="responseBytes"></param>
    [PublicAPI]
    public void ProcessInitUpdateResponse(byte[] responseBytes)
    {
        var responseApdu = new ResponseAPDU(responseBytes);
        ProcessInitUpdateResponse(responseApdu);
    }

    /// <summary>
    /// Process the response of INIT UPDATE command.
    /// </summary>
    /// <param name="response"></param>
    [PublicAPI]
    public void ProcessInitUpdateResponse(ResponseAPDU response)
    {
#if DEBUG
        Log.Debug("Processing INITIALIZE UPDATE response.");
        Log.Debug("Response: " + Convert.ToHexString(response.ToByteArray()));
#endif
        
        // Validate the status word
        CheckResponse(response.SW1, response.SW2, "INITIALIZE UPDATE command failed.");
        
        // SCP01 and 02 have a different length from SCP03
        if (response.Data.Length is not (28 or 29 or 32))
            throw new ArgumentException("Wrong INIT UPDATE response length.");

        // Store the response
        _InitUpdateResponse = response.Data;

        if (mSCPIdentifier == SCP_ANY)
        {
            var scpIdentifierByte = _InitUpdateResponse[OFFSET_SCP_ID];
            mSCPIdentifier = scpIdentifierByte switch
            {
                SCP_01 => SCP_01,
                SCP_02 => SCP_02,
                SCP_03 => SCP_03,
                _ => throw new ArgumentException("Invalid secure channel protocol identifier.")
            };
            
            switch (response.Data.Length)
            {
                case 28 when mSCPIdentifier is SCP_01 or SCP_02:
                {
                    if (mSCPImplementationOption == IMPL_OPTION_ANY)
                        mSCPImplementationOption = mSCPIdentifier == SCP_02 ? IMPL_OPTION_I_15 : IMPL_OPTION_I_05;
                    break;
                }
                case 29 or 32 when mSCPIdentifier == SCP_03:
                    // SCP03
                    mSCPImplementationOption = _InitUpdateResponse[OFFSET_IMPLEMENTATION_SCP03];
                    break;
                default:
                    throw new InvalidDataException("Invalid INITIALIZE UPDATE response length.");
            }
        }

        if (mSCPIdentifier != _InitUpdateResponse[OFFSET_SCP_ID])
            throw new Exception("Secure channel identifier specified does not match to card");

        // If we use SPC '01' then clear R_MAC bit
        if (mSCPIdentifier == SCP_01)
            mSecurityLevel &= ~SecurityLevel.R_MAC;

        // Derive session keys
        switch (mSCPIdentifier)
        {
            
            case SCP_01:
                mSessionKeys = GenerateSessionKeysSCP01(_InitUpdateResponse);
                break;
            case SCP_02:
            {
                var sequenceCounter = new byte[2];
                Array.Copy(_InitUpdateResponse, 12, sequenceCounter, 0, 2);
                mSessionKeys = GenerateSessionKeysSCP02(sequenceCounter);
                break;
            }
            case SCP_03:
                mSessionKeys = GenerateSessionKeysSCP03(_InitUpdateResponse);
                break;
        }

        var memStream = new MemoryStream();
        memStream.Write(HostChallenge, 0, HostChallenge.Length);
        memStream.Write(_InitUpdateResponse, 12, 8);

        var calculatedCryptogram = CryptoUtil.FullTripleDESMAC(
            mSessionKeys.RetrieveKey(SymmetricKey.KEY_TYPE_ENC), CryptoUtil.BinaryZeros8ByteBlock,
            CryptoUtil.DESPad(memStream.ToArray()));

        var cardCryptogram = new byte[8];
        Array.Copy(_InitUpdateResponse, 20, cardCryptogram, 0, 8);
        if (!cardCryptogram.SequenceEqual(calculatedCryptogram))
            throw new Exception("Invalid cryptogram.");
    }

    /// <summary>
    /// </summary>
    /// <returns></returns>
    public CommandAPDU CreateExternalAuthCommand()
    {
        var memStream = new MemoryStream();
        memStream.Write(_InitUpdateResponse, 12, 8);
        memStream.Write(HostChallenge, 0, HostChallenge.Length);

        var hostCryptogram = CryptoUtil.FullTripleDESMAC(
            mSessionKeys.RetrieveKey(SymmetricKey.KEY_TYPE_ENC), CryptoUtil.BinaryZeros8ByteBlock,
            CryptoUtil.DESPad(memStream.ToArray()));
        var P1 = mSecurityLevel;

        var externalAuth = new CommandAPDU(CLA_SECURE_GP, INS_EXT_AUTH, P1, 0x00, hostCryptogram);
        SecureChannel = new SecureChannel(
            mSessionKeys, SecurityLevel.C_MAC, mSCPIdentifier, mSCPImplementationOption,
            CryptoUtil.BinaryZeros8ByteBlock, CryptoUtil.BinaryZeros8ByteBlock);
        externalAuth = SecureChannel.wrap(externalAuth);
        return externalAuth;
    }

    public void ProcessExternalAuthResponse(ResponseAPDU response)
    {
        CheckResponse(response.SW1, response.SW2, "EXTERNAL AUTHENTICATE command failed.");
        SecureChannel.SecurityLevel = mSecurityLevel;
    }

    /// <summary>
    /// </summary>
    /// <param name="keys"></param>
    /// <param name="replaceExisting"></param>
    /// <param name="keyFormat"></param>
    /// <returns></returns>
    public CommandAPDU CreatePutKeyCommand(List<DesKey> keys, bool replaceExisting, bool addKCV, int keyFormat)
    {
        int p1;
        int p2;
        if (keyFormat == KEY_FORMAT_2)
            throw new Exception("Format 2 is reserved for futrue use.");
        if (keyFormat != KEY_FORMAT_1)
            throw new Exception("Unknown format");

        var prevId = -1;
        for (var i = 0; i < keys.Count; i++)
        {
            var key = keys[i];
            if (i > 1)
                if (key.KeyId != prevId + 1)
                    throw new Exception(
                        "Key Identifiers must sequentially increment. See See Global Platform 2.1.1 Card Spec section 9.8.2.3.1");
            prevId = key.KeyId;
        }

        if (replaceExisting)
        {
            p1 = keys[0].KeyVersion;
        }
        else
        {
            p1 = 0;
        }

        p2 = keys[0].KeyId;

        // Multiple keys
        if (keys.Count > 1)
            p2 |= 0x80;

        DesKey kek = null;
        if (mSCPIdentifier == SCP_01)
        {
            kek = new DesKey(mStaticKeys.KekKey.BuildTripleDesKey());
        }
        else if (mSCPIdentifier == SCP_02)
        {
            kek = new DesKey(mSessionKeys.KekKey.BuildTripleDesKey());
        }

        var allKeyData = new MemoryStream();
        allKeyData.WriteByte((byte) keys[0].KeyVersion);
        for (var i = 0; i < keys.Count; i++)
        {
            var key = keys[i];
            var keyDataBytes = EncodeKeyData(key, kek, addKCV, keyFormat);
            allKeyData.Write(keyDataBytes, 0, keyDataBytes.Length);
        }

        var putKeyCommand = new CommandAPDU(CLA_GP, INS_PUT_KEY, p1, p2, allKeyData.ToArray(), 0x00);
        putKeyCommand = SecureChannel.wrap(putKeyCommand);
        return putKeyCommand;
    }
}