namespace RSA.QuickSign
{
    public class KeyPair
    {
        public string PrivateKey { get; }
        public string PublicKey { get; }

        public KeyPair(string privateKey, string publicKey)
        {
            PrivateKey = privateKey;
            PublicKey = publicKey;
        }
    }
}