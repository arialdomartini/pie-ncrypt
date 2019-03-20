using System.Security.Cryptography;
using FluentAssertions;
using Pie.NCrypt;
using Xunit;
using RSA = Pie.NCrypt.RSA;

namespace Pie.NCryptTest
{
    public class RSATest
    {
        [Fact]
        public void should_sign_and_verify_a_string_message()
        {
            const string message = "message to sign";

            var sut = new RSA();
            var pair = sut.GeneratePair();

            var signed = sut.Sign(message, pair.PrivateKey);

            var verification = sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message()
        {
            var message = "message to sign".ToByteArray();

            var sut = new RSA();
            var pair = sut.GeneratePair();

            var signed = sut.Sign(message, pair.PrivateKey);

            var verification = sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_string_message_using_RSAParameters()
        {
            const string message = "message to sign";

            var sut = new RSA();
            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = sut.Sign(message, privateKey);

            var verification = sut.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message_using_RSAParameters()
        {
            var message = "message to sign".ToByteArray();

            var sut = new RSA();
            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = sut.Sign(message, privateKey);

            var verification = sut.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }


        [Fact]
        public void should_detect_a_fake_signature()
        {
            const string message = "message to sign";

            var sut = new RSA();
            var pair = sut.GeneratePair();

            var signed = "fake signature";

            var verification = sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }

        [Fact]
        public void should_detect_a_base64_fake_signature()
        {
            const string message = "message to sign";

            var sut = new RSA();
            var pair = sut.GeneratePair();

            var signed = "fake signature".ToByteArray().ToBase64String();

            var verification = sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }
    }
}