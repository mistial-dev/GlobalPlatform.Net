namespace GlobalPlatform.Net.Crypto;

public class DesKey : SymmetricKey
{
    public DesKey(byte[] value, int keyId = 0, int keyVersion = 0) : base(value, keyId, keyVersion)
    {
    }

    public DesKey(string hexValue, int keyId = 0, int keyVersion = 0) : base(hexValue, keyId, keyVersion)
    {
    }
}