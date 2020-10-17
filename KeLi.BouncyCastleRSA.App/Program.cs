/*
 * MIT License
 *
 * Copyright(c) 2019 KeLi
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
             ,---------------------------------------------------,              ,---------,
        ,----------------------------------------------------------,          ,"        ,"|
      ,"                                                         ,"|        ,"        ,"  |
     +----------------------------------------------------------+  |      ,"        ,"    |
     |  .----------------------------------------------------.  |  |     +---------+      |
     |  | C:\>FILE -INFO                                     |  |  |     | -==----'|      |
     |  |                                                    |  |  |     |         |      |
     |  |                                                    |  |  |/----|`---=    |      |
     |  |              Author: KeLi                          |  |  |     |         |      |
     |  |              Email: kelicto@protonmail.com         |  |  |     |         |      |
     |  |              Creation Time: 03/04/2020 04:12:41 PM |  |  |     |         |      |
     |  | C:\>_                                              |  |  |     | -==----'|      |
     |  |                                                    |  |  |   ,/|==== ooo |      ;
     |  |                                                    |  |  |  // |(((( [66]|    ,"
     |  `----------------------------------------------------'  |," .;'| |((((     |  ,"
     +----------------------------------------------------------+  ;;  | |         |,"
        /_)_________________________________________________(_/  //'   | +---------+
           ___________________________/___  `,
          /  oooooooooooooooo  .o.  oooo /,   \,"-----------
         / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
        /_==__==========__==_ooo__ooo=_/'   /___________,"
*/

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