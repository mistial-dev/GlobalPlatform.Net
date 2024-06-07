using System;
using GlobalPlatform.Net;
using NUnit.Framework;

namespace Globalplatform.Net.Tests;

[TestFixture]
public class SessionTests
{
    [Test]
    public void TestHostChallenge()
    {
        // Ensure that invalid host challenge lengths throw exceptions
        const string invalidSizeHostChallengeValue = "000102030405060708";
        var session = new Session();
        Assert.Throws<ArgumentException>(() =>
        {
            session.HostChallenge = Convert.FromHexString(invalidSizeHostChallengeValue);
        });
        
        // Ensure that valid host challenge lengths do not throw exceptions
        const string validSizeHostChallengeValue = "0001020304050607";
        session.HostChallenge = Convert.FromHexString(validSizeHostChallengeValue);

    }
}