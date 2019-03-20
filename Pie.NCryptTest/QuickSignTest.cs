using System.Security.Cryptography;
using FluentAssertions;
using Pie.NCrypt;
using Xunit;

namespace Pie.NCryptTest
{
    public class QuickSignTest
    {
        [Fact]
        public void should_sign_and_verify_a_string_message()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = simpleRsa.Sign(message, pair.PrivateKey);

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message()
        {
            var message = "message to sign".ToByteArray();

            var simpleRsa = new QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = simpleRsa.Sign(message, pair.PrivateKey);

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_string_message_using_RSAParameters()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign();
            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = simpleRsa.Sign(message, privateKey);

            var verification = simpleRsa.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message_using_RSAParameters()
        {
            var message = "message to sign".ToByteArray();

            var simpleRsa = new QuickSign();
            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = simpleRsa.Sign(message, privateKey);

            var verification = simpleRsa.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }


        [Fact]
        public void should_detect_a_fake_signature()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = "fake signature";

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }

        [Fact]
        public void should_detect_a_base64_fake_signature()
        {
            const string message = "message to sign";

            var simpleRsa = new QuickSign();
            var pair = simpleRsa.GeneratePair();

            var signed = "fake signature".ToByteArray().ToBase64String();

            var verification = simpleRsa.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }
    }
}