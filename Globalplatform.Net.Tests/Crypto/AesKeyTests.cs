using System;
using GlobalPlatform.Net.Crypto;
using NUnit.Framework;
// ReSharper disable ObjectCreationAsStatement

namespace Globalplatform.Net.Tests.Crypto;

[TestFixture]
public class AesKeyTests
{
    /// <summary>
    /// Sixteen byte test key
    /// </summary>
    private const string TEST_KEY_16_BYTES = "000102030405060708090A0B0C0D0E0F";
    
    /// <summary>
    /// Twenty-four byte test key
    /// </summary>
    private const string TEST_KEY_24_BYTES = "000102030405060708090A0B0C0D0E0F1011121314151617";
    
    /// <summary>
    /// Thirty-two byte test key
    /// </summary>
    private const string TEST_KEY_32_BYTES = "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F";

    /// <summary>
    /// Test AES key functionality
    /// </summary>
    [Test]
    public void TestCreation()
    {
        // Ensure that invalid key lengths throw exceptions
        const string invalidSizeKeyValue = "0001020304050607";
        Assert.Throws<ArgumentException>(() => { new AesKey(invalidSizeKeyValue); });
        
        // Ensure that valid key lengths do not throw exceptions
        var aesKey16 = new AesKey(TEST_KEY_16_BYTES);
        Assert.That(aesKey16.Value, Is.EquivalentTo(new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
        }));
        Assert.That(aesKey16.HexValue, Is.EqualTo(TEST_KEY_16_BYTES));
        Assert.That(aesKey16.KeySize, Is.EqualTo(KeySize.Aes128));
        
        var aesKey24 = new AesKey(TEST_KEY_24_BYTES);
        Assert.That(aesKey24.Value, Is.EquivalentTo(new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
        }));
        Assert.That(aesKey24.HexValue, Is.EqualTo(TEST_KEY_24_BYTES));
        Assert.That(aesKey24.KeySize, Is.EqualTo(KeySize.Aes192));
        
        var aesKey32 = new AesKey(TEST_KEY_32_BYTES);
        Assert.That(aesKey32.Value, Is.EquivalentTo(new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
        }));
        Assert.That(aesKey32.HexValue, Is.EqualTo(TEST_KEY_32_BYTES));
        Assert.That(aesKey32.KeySize, Is.EqualTo(KeySize.Aes256));
        
    }
}