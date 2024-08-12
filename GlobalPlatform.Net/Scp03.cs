using System;
using System.Runtime.Intrinsics.X86;
using GlobalPlatform.Net.Crypto;
using log4net;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities.Encoders;

namespace GlobalPlatform.Net;

public static class Scp03
{
#if DEBUG
    /// <summary>
    /// Logger
    /// </summary>
    private static readonly ILog Log = LogManager.GetLogger(typeof(Session));
#endif
    
    /// <summary>
    /// The label consists of 12 bytes, with the first 11 bytes being 0x00
    /// </summary>
    private static readonly byte[] KdfLabelPrefix = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    
    /// <summary>
    /// Derivation constant for the Session Encryption Key
    /// </summary>
    public const byte DERIVATION_CONSTANT_S_ENC = 4;
    
    /// <summary>
    /// Derivation constant for the Session Mac Key
    /// </summary>
    public const byte DERIVATION_CONSTANT_S_MAC = 5;
    
    /// <summary>
    /// Derivation constant for the Session RMac Key
    /// </summary>
    public const byte DERIVATION_CONSTANT_S_RMAC = 0x06;
    
    /// <summary>
    /// Counter value for the first iteration
    /// </summary>
    public const byte COUNTER_FIRST_ITERATION = 0x01;
    
    /// <summary>
    /// Counter value for the second iteration
    /// </summary>
    public const byte COUNTER_SECOND_ITERATION = 0x02;
    
    /// <summary>
    /// Size of the counter
    /// </summary>
    private const int COUNTER_SIZE = 1;
    
    /// <summary>
    /// Size of the derivation constant
    /// </summary>
    private const int DERIVATION_CONSTANT_SIZE = 1;
    
    public static AesKey Kdf(SymmetricKey key, byte[] context, byte counter = COUNTER_FIRST_ITERATION)
    {
        // GPC 2.2 Appendix D
        // The following data derivation scheme is used to generate keys, pseudo-random card challenges or 
        // cryptograms: 
        // Data derivation shall use KDF in counter mode as specified in NIST SP 800-108 [9]. The PRF used in the 
        // KDF shall be CMAC as specified in NIST SP 800-38B [10], used with full 16 byte output length.
        // 
        // The “fixed input data” plus iteration counter shall be the concatenation of the following items in the given 
        // sequence (note that NIST SP 800-108 [9] allows the reordering of input data fields as long as the order, 
        // coding and length of each field is unambiguously defined):
        //
        // A 12 byte “label” consisting of 11 bytes with value ‘00’ followed by a one byte derivation constant as 
        // defined below. 
        // A one byte “separation indicator” with value ‘00’. 
        // A 2 byte integer “L” specifying the length in bits of the derived data (value ‘0040’, ‘0080’, ‘00C0’ or 
        // ‘0100’).
        // A 1 byte counter “i” as specified in the KDF (which may take the values ‘01’ or ‘02’; value ‘02’ is 
        // used when “L” takes the values ‘00C0’ and ‘0100’, i.e. when the PRF of the KDF is to be called 
        // twice to generate enough derived data).
        // The “context” parameter of the KDF.
        
        byte[] lengthInput = key.KeySize switch {
            KeySize.Aes128 => [0x00, 0x40],
            KeySize.Aes192 => [0x00, 0xC0],
            KeySize.Aes256 => [0x01, 0x00],
            _ => throw new System.NotSupportedException("Unsupported key size")
        };

        // Build the derivation input
        var inputLength = KdfLabelPrefix.Length + DERIVATION_CONSTANT_SIZE + lengthInput.Length + COUNTER_SIZE + context.Length;
        var derivationInput = new byte[inputLength];
        KdfLabelPrefix.CopyTo(derivationInput, 0);
        derivationInput[KdfLabelPrefix.Length] = DERIVATION_CONSTANT_S_ENC;
        lengthInput.CopyTo(derivationInput, KdfLabelPrefix.Length + DERIVATION_CONSTANT_SIZE);
        derivationInput[KdfLabelPrefix.Length + DERIVATION_CONSTANT_SIZE + lengthInput.Length] = counter;
        context.CopyTo(derivationInput, KdfLabelPrefix.Length + DERIVATION_CONSTANT_SIZE + lengthInput.Length + COUNTER_SIZE);
        
#if DEBUG
        Log.Debug($"Derivation input: {Hex.ToHexString (derivationInput)}");
#endif
        // Calculate the first half of the derived data
        var cmac = new CMac(new AesEngine());
        cmac.Init(new KeyParameter(key.Value));
        var firstHalf = new byte[16];
        cmac.BlockUpdate(derivationInput, 0, derivationInput.Length);
        cmac.DoFinal(firstHalf, 0);
        cmac.Reset();
        
        // Set the counter and calculate the second half of the derived data
        var secondHalf = new byte[16];
        derivationInput[KdfLabelPrefix.Length + DERIVATION_CONSTANT_SIZE + lengthInput.Length + COUNTER_SIZE] = COUNTER_SECOND_ITERATION;
        cmac.BlockUpdate(derivationInput, 0, derivationInput.Length);
        cmac.DoFinal(secondHalf, 0);
        
        // Combine the two halves 
        var derivedData = new byte[key.Value.Length];
        Array.Copy(firstHalf, derivedData, firstHalf.Length);
        if (key.Value.Length > 16)
        {
            Array.Copy(secondHalf, 0, derivedData, 16, key.Value.Length - 16);
        }
        
        return new AesKey(derivedData);
    }
}