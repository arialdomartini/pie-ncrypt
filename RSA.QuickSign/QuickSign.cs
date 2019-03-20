using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Security;

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

        public string Sign(string message, string serializedPrivateKey)
        {
            using (var rsa = RsaCryptoServiceProvider)
            {
                rsa.ImportParameters(
                    serializedPrivateKey.ToRsaParameterPrivate());

                var signData = rsa.SignData(
                    message.ToByteArray(),
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);

                return signData.ToBase64String();

            }
        }

        public bool Verify(string message, string signature, string publicKey)
        {
            try
            {
                using (var rsa = RsaCryptoServiceProvider)
                {
                    rsa.ImportParameters(publicKey.ToRsaParametersPublic());

                    return rsa.VerifyData(Encoding.GetBytes(message), signature.BytesFromBase64(), HashAlgorithmName.SHA256,
                        RSASignaturePadding.Pkcs1);
                }
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}