using System;
using System.Security.Cryptography;

namespace KeLi.BouncyCastleRSA.App
{
    public class Program
    {
        public static void Main()
        {
            var content = GetRandomString(100000, true, true, true, true);

            var pair = BouncyCastleHelper.GenerateKeyPair();

            var ciphertext = BouncyCastleHelper.EncryptLongTextByPublicKey(content, pair.PublicKey);

            var text = BouncyCastleHelper.DecryptLongTextByPrivateKey(ciphertext, pair.PrivateKey);

            Console.WriteLine(text);

            Console.ReadKey();
        }

        public static string GetRandomString(int length, bool useNum, bool useLow, bool useUpp, bool useSpe, string customString = null)
        {
            var data = new byte[4];

            new RNGCryptoServiceProvider().GetBytes(data);

            var random = new Random(BitConverter.ToInt32(data, 0));

            var charSet = customString;

            var result = string.Empty;

            if (useNum)
                charSet += "0123456789";

            if (useLow)
                charSet += "abcdefghijklmnopqrstuvwxyz";

            if (useUpp)
                charSet += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            if (useSpe)
                charSet += "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

            for (var i = 0; charSet != null && i < length; i++)
                result += charSet.Substring(random.Next(0, charSet.Length - 1), 1);

            return result;
        }
    }
}