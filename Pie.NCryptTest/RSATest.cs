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

        [Theory]
        [InlineData("message to sign")]
        [InlineData("a")]
        [InlineData("")]
        [InlineData("    ")]
        [InlineData("Japanese (日本語, Nihongo) こちらは田中さんです")]
        [InlineData(@"very long message Pellentesque dapibus suscipit ligula.  Donec posuere
                      augue in quam.  Etiam vel tortor sodales tellus ultricies commodo.
                      Suspendisse potenti.  Aenean in sem ac leo mollis blandit.  Donec neque
                      quam, dignissim in, mollis nec, sagittis eu, wisi.  Phasellus lacus.
                      Etiam laoreet quam sed arcu.  Phasellus at dui in ligula mollis ultricies.
                      Integer placerat tristique nisl.  Praesent augue.  Fusce commodo.  Vestibulum
                      convallis, lorem a tempus semper, dui dui euismod elit, vitae placerat urna
                      tortor vitae lacus.  Nullam libero mauris, consequat quis, varius et, dictum
                      id, arcu.  Mauris mollis tincidunt felis.  Aliquam feugiat tellus ut neque.
                      Nulla facilisis, risus a rhoncus fermentum, tellus tellus lacinia purus, et
                      dictum nunc justo sit amet elit.")]
        public void should_sign_and_verify_a_string_message(string message)
        {
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