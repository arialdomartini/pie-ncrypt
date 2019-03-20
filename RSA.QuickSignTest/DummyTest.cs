using FluentAssertions;
using Xunit;

namespace RSA.QuickSignTest
{
    public class DummyTest
    {
        [Fact]
        public void should_pass()
        {
            "friends".Should().Be("friends");
        }
    }
}