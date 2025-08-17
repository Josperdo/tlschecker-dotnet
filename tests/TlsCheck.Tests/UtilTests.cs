using System;
using TlsCheck;
using Xunit;

public class UtilTests
{
    [Fact]
    public void NormalizeHost_Parses_Url_And_Host()
    {
        Assert.Equal("example.com", Util.NormalizeHost("https://example.com/"));
        Assert.Equal("example.com", Util.NormalizeHost("example.com/"));
        Assert.Equal("www.microsoft.com", UtilTests.NormalizeHost("http://www.microsoft.com"));
    }

    [Fact]
    public void DaysUntil_Works()
    {
        var in3 = DateTimeOffset.UtcNow.AddDays(3);
        var days = UtilTests.DaysUntil(in3);
        Assert.True(days is >= 2 and <= 3);
    }
}