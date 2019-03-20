using System;
using System.Security.Cryptography;

namespace RSA.QuickSign
{
    internal static class RSACryptoServiceProviderExtensions
    {
        private static RSACryptoServiceProvider RsaCryptoServiceProvider => new RSACryptoServiceProvider(1024);

        internal static RSACryptoServiceProvider ImportKey(this RSACryptoServiceProvider rsa,
            RSAParameters rsaParameters)
        {
            rsa.ImportParameters(rsaParameters);
            return rsa;
        }

        internal static T Using<T>(Func<RSACryptoServiceProvider, T> func)
        {
            using (var rsa = RsaCryptoServiceProvider)
            {
                return func(rsa);
            }
        }
    }
}