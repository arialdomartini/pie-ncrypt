using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;
using Pie.Monads;
using static RSA.QuickSign.RSACryptoServiceProviderExtensions;

namespace RSA.QuickSign
{
    public class QuickSign
    {
        private static readonly UnicodeEncoding Encoding = new UnicodeEncoding();
        private static RSACryptoServiceProvider RsaCryptoServiceProvider => new RSACryptoServiceProvider(1024);

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
            Using(rsa =>  rsa
                .ImportKey(privateKey)
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
                Using(rsa => rsa
                    .ImportKey(publicKey)
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