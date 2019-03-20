using FluentAssertions;
using RSA.QuickSign;
using Xunit;

namespace RSA.QuickSignTest
{
    public class QuickSignTest
    {
        [Fact]
        public void should_sign_and_verify_a_string_message()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign.QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = simpleRsa.Sign(message, pair.PrivateKey);

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_detect_a_fake_signature()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign.QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = "fake signature";

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }

        [Fact]
        public void should_detect_a_base64_fake_signature()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign.QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = "fake signature".ToByteArray().ToBase64String();

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }
    }
}