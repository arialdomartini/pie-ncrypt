using System.Security.Cryptography;
using FluentAssertions;
using Pie.NCrypt;
using Xunit;
using RSA = Pie.NCrypt.RSA;

namespace Pie.NCryptTest
{
    public class RSATest
    {
        private readonly RSA _sut;

        public RSATest()
        {
            _sut = new RSA();
        }

        [Fact]
        public void should_sign_and_verify_a_string_message()
        {
            const string message = "message to sign";

            var pair = _sut.GeneratePair();

            var signed = _sut.Sign(message, pair.PrivateKey);

            var verification = _sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message()
        {
            var message = "message to sign".ToByteArray();

            var pair = _sut.GeneratePair();

            var signed = _sut.Sign(message, pair.PrivateKey);

            var verification = _sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_string_message_using_RSAParameters()
        {
            const string message = "message to sign";

            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = _sut.Sign(message, privateKey);

            var verification = _sut.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }

        [Fact]
        public void should_sign_and_verify_a_byte_array_message_using_RSAParameters()
        {
            var message = "message to sign".ToByteArray();

            RSAParameters privateKey;
            RSAParameters publicKey;
            using (var rsa = new RSACryptoServiceProvider())
            {
                privateKey = rsa.ExportParameters(true);
                publicKey = rsa.ExportParameters(false);
            }

            var signed = _sut.Sign(message, privateKey);

            var verification = _sut.Verify(message, signed, publicKey);

            verification.Should().Be(true);
        }


        [Fact]
        public void should_detect_a_fake_signature()
        {
            const string message = "message to sign";

            var pair = _sut.GeneratePair();

            var signed = "fake signature";

            var verification = _sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }

        [Fact]
        public void should_detect_a_base64_fake_signature()
        {
            const string message = "message to sign";

            var pair = _sut.GeneratePair();

            var signed = "fake signature".ToByteArray().ToBase64String();

            var verification = _sut.Verify(message, signed, pair.PublicKey);

            verification.Should().Be(false);
        }
    }
}