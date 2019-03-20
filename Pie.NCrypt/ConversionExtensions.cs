using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Pie.Monads;

namespace Pie.NCrypt
{
    public static class ConversionExtensions
    {
        private static readonly UnicodeEncoding Encoding = new UnicodeEncoding();

        public static byte[] ToByteArray(this string s) =>
            Encoding.GetBytes(s);

        internal static string ToBase64String(this byte[] o) =>
            Convert.ToBase64String(o);

        public static Either<bool, byte[]> BytesFromBase64(this string @string)
        {
            try
            {
                return Convert.FromBase64String(@string);
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static RSAParameters ToRsaParametersPublic(this string publicKey) =>
            DotNetUtilities.ToRSAParameters(publicKey.ToPublicKey());

        public static RSAParameters ToRsaParameterPrivate(this string serializedPrivateKey) =>
            DotNetUtilities.ToRSAParameters(serializedPrivateKey.ToPrivateKey());

        private static RsaKeyParameters ToPublicKey(this string serializedPublic) =>
            (RsaKeyParameters) PublicKeyFactory.CreateKey(Convert.FromBase64String(serializedPublic));

        private static RsaPrivateCrtKeyParameters ToPrivateKey(this string serializedPrivate) =>
            (RsaPrivateCrtKeyParameters) PrivateKeyFactory.CreateKey(Convert.FromBase64String(serializedPrivate));

        private static byte[] Encoded(this Asn1Encodable asn1Encodable) =>
            asn1Encodable.ToAsn1Object().GetDerEncoded();

        public static string SerializedPrivate(this AsymmetricCipherKeyPair pair) =>
            PrivateKeyInfoFactory
                .CreatePrivateKeyInfo(pair.Private)
                .Encoded()
                .ToBase64String();

        public static string SerializedPublic(this AsymmetricCipherKeyPair pair) =>
            SubjectPublicKeyInfoFactory
                .CreateSubjectPublicKeyInfo(pair.Public)
                .Encoded()
                .ToBase64String();
    }
}