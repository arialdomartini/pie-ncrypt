using System;
using System.Security.Cryptography;
using Newtonsoft.Json;

namespace Pie.NCrypt
{
    public class SHA1
    {
        public string HashOf(object object1)
        {
            using (var sha1 = new SHA1Managed())
            {
                return sha1
                    .ComputeHash(
                        object1
                            .Serialized()
                            .ToByteArray())
                    .ToBase64String();

            }
        }
    }
}