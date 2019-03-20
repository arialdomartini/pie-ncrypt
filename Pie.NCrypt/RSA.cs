using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

namespace Pie.NCrypt
{
    public class RSA
    {
        private static readonly UnicodeEncoding Encoding = new UnicodeEncoding();

        public KeyPair GeneratePair()
        {
            var rsaKeyPairGenerator = new RsaKeyPairGenerator();
            rsaKeyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
            var pair = rsaKeyPairGenerator.GenerateKeyPair();

            return new KeyPair(
                pair.SerializedPrivate(),
                pair.SerializedPublic());
        }

        public string Sign(byte[] @object, RSAParameters privateKey) =>
            RSACryptoServiceProviderExtensions.Using(rsa =>  RSACryptoServiceProviderExtensions.ImportKey(rsa, privateKey)
                .SignData(
                    @object,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1)
                .ToBase64String()
            );

        public string Sign(byte[] @object, string serializedPrivateKey) =>
            Sign(@object, serializedPrivateKey.ToRsaParameterPrivate());

        public string Sign(string message, string serializedPrivateKey) =>
            Sign(message.ToByteArray(), serializedPrivateKey);

        public string Sign(string message, RSAParameters privateKey) =>
            Sign(message.ToByteArray(), privateKey);


        public bool Verify(byte[] @object, string signature, RSAParameters publicKey) =>
            signature.BytesFromBase64().Map(s =>
                RSACryptoServiceProviderExtensions.Using(rsa => RSACryptoServiceProviderExtensions.ImportKey(rsa, publicKey)
                    .VerifyData(
                        @object,
                        s,
                        HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1))
            ).Match(l => false, r => r);

        public bool Verify(string message, string signature, string publicKey) =>
            Verify(Encoding.GetBytes(message), signature, publicKey);

        public bool Verify(string message, string signature, RSAParameters publicKey) =>
            Verify(Encoding.GetBytes(message), signature, publicKey);

        public bool Verify(byte[] @object, string signature, string publicKey) =>
            Verify(@object, signature, publicKey.ToRsaParametersPublic());
    }
}