using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.OpenSsl;
using System;
using System.IO;
using System.Text;

namespace rsa_oeap_256
{
    internal class Program
    {
        public static string RsaDecryptWithPrivateKey(string base64Input, string privateKey)
        {
            var bytesToDecrypt = Convert.FromBase64String(base64Input);

            AsymmetricCipherKeyPair keyPair;
            var decryptEngine = new OaepEncoding(new RsaEngine(), new Sha256Digest());

            using (var stringReader = new StringReader(privateKey))
            {
                keyPair = (AsymmetricCipherKeyPair)new PemReader(stringReader).ReadObject();

                decryptEngine.Init(false, keyPair.Private);
            }

            var decrypted = Encoding.UTF8.GetString(decryptEngine.ProcessBlock(bytesToDecrypt, 0, bytesToDecrypt.Length));
            return decrypted;
        }

        private static void Main(string[] args)
        {
            var encryptedData = File.ReadAllText("encrypted_data.txt");
            var privateKey = File.ReadAllText("key.pem");
            var output = RsaDecryptWithPrivateKey(encryptedData, privateKey);
            Console.WriteLine(output);
            Console.Read();
        }
    }
}