using System;
using GlobalPlatform.Net;
using GlobalPlatform.Net.Crypto;
using NUnit.Framework;

namespace Globalplatform.Net.Tests;

[TestFixture]
public class Scp03Tests
{
    /// <summary>
    /// Expected response for the Init Update command
    /// </summary>
    private const string INIT_UPDATE_EXPECTED = "8050000008F0F1F2F3F4F5F6F700";
    
    /// <summary>
    /// GlobalPlatform test key
    /// </summary>
    private const string GP_TEST_KEY = "404142434445464748494A4B4C4D4E4F";
    
    /// <summary>
    /// Fixed host challenge, used for testing, eight bytes
    /// </summary>
    private const string FIXED_HOST_CHALLENGE = "F0F1F2F3F4F5F6F7";
    
    /// <summary>
    /// Fixed card challenge, used for testing, eight bytes
    /// </summary>
    private const string FIXED_CARD_CHALLENGE = "F8F9FAFBFCFDFEFF";

    /// <summary>
    /// Fixed card diversification data, used for testing, 10 bytes
    /// </summary>
    private const string FIXED_CARD_DIVERSIFICATION_DATA = "E0E1E2E3E4E5E6E7E8E9";
    
    [Test]
    public void TestScp03()
    {
        var gpSession = new Session()
        {
            Channel = LogicalChannel.BasicChannel,
        };
        
        // Create the AES KeySet
        var keySet = new KeySet
        {
            MacKey = new AesKey(GP_TEST_KEY),
            EncKey = new AesKey(GP_TEST_KEY),
            DekKey = new AesKey(GP_TEST_KEY),
        };
        
        // Command Decryption, Response Encryption, Command Mac, Response Mac
        const int securityLevel = SecurityLevel.C_DECRYPTION | SecurityLevel.R_ENCRYPTION | SecurityLevel.C_MAC | SecurityLevel.R_MAC;
        Assert.That(securityLevel, Is.EqualTo(0b00110011));

        // Create the Init Update Command
        gpSession.HostChallenge = Convert.FromHexString(FIXED_HOST_CHALLENGE);
        var initUpdateCommandBytes = gpSession.CreateInitUpdateCommand(keySet, securityLevel).ToByteArray();
        
        // Verify that the command is properly constructed
        Assert.That(initUpdateCommandBytes, Is.EqualTo(Convert.FromHexString(INIT_UPDATE_EXPECTED)));
        
        // Create the Init Update Response
        const string keyVersionNumber = "FF";
        const string scpVersion = "03";
        const string scpIParameter = "70";
        const string sequenceCounter = "010203";
        const string swSuccess = "9000";
        
        const string cardCryptogram = "0000000000000000";
        
        // Start the session
        var initUpdateData =
            gpSession.CreateInitUpdateCommand(keySet, securityLevel, Session.SCP_03, Session.IMPL_OPTION_I_70);
        
        const string initUpdateResponseHex = $"{FIXED_CARD_DIVERSIFICATION_DATA}{keyVersionNumber}{scpVersion}{scpIParameter}{FIXED_CARD_CHALLENGE}{cardCryptogram}{sequenceCounter}{swSuccess}";
        
        // Process the Init Update Response
        gpSession.ProcessInitUpdateResponse(initUpdateResponseHex);
    }
}