
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
     |  |              Email: kelistudy@163.com              |  |  |     |         |      |
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
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace KeLi.BouncyCastleRSA.App
{
    public class BouncyCastleHelper
    {
        public static RsaKey GenerateKeyPair()
        {
            var keyGenerator = new RsaKeyPairGenerator();

            var parm = new RsaKeyGenerationParameters(BigInteger.ValueOf(3), new SecureRandom(), 1024, 25);

            keyGenerator.Init(parm);

            var keyPair = keyGenerator.GenerateKeyPair();

            var publicKey = keyPair.Public;

            var privateKey = keyPair.Private;

            var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);

            var asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();

            var publicInfoByte = asn1ObjectPublic.GetEncoded("UTF-8");

            var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);

            var asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();

            var privateInfoByte = asn1ObjectPrivate.GetEncoded( "UTF-8");

            return new RsaKey
            {
                PublicKey = Convert.ToBase64String(publicInfoByte),

                PrivateKey = Convert.ToBase64String(privateInfoByte)
            };
        }

        private static AsymmetricKeyParameter GetPublicKeyParameter(string publicKey)
        {
            publicKey = publicKey.Replace(Environment.NewLine, string.Empty).Trim();

            var publicInfoByte = Convert.FromBase64String(publicKey);

            return PublicKeyFactory.CreateKey(publicInfoByte);
        }

        private static AsymmetricKeyParameter GetPrivateKeyParameter(string privateKey)
        {
            privateKey = privateKey.Replace(Environment.NewLine, string.Empty).Trim();

            var privateInfoByte = Convert.FromBase64String(privateKey);

            return PrivateKeyFactory.CreateKey(privateInfoByte);
        }

        public static string EncryptLongTextByPublicKey(string content, string publicKey)
        {
            var results = new List<string>();

            var maxSubLength = 100;

            var subCount = Math.Ceiling(content.Length / (maxSubLength * 1.0));

            for (var i = 0; i < subCount; i++)
            {
                if (content.Length - i * maxSubLength < maxSubLength)
                    maxSubLength = content.Length - i * maxSubLength;

                var subContent  = content.Substring(i * maxSubLength, maxSubLength);

                var subCiphertext = EncryptByPublicKey(subContent, publicKey);

                results.Add(subCiphertext);
            }

            return string.Join(Environment.NewLine, results);
        }

        public static string DecryptLongTextByPrivateKey(string ciphertext, string privateKey)
        {
            var ciphertexts = ciphertext.Split(Environment.NewLine.ToCharArray());

            return ciphertexts.Aggregate(string.Empty, (current, i) => current + DecryptByPrivateKey(i, privateKey));
        }

        public static string EncryptByPublicKey(string content, string publicKey)
        {
            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            try
            {
                engine.Init(true, GetPublicKeyParameter(publicKey));

                var byteData = Encoding.UTF8.GetBytes(content);

                var ciphertextData = engine.ProcessBlock(byteData, 0, byteData.Length);

                return Convert.ToBase64String(ciphertextData);
            }

            catch (Exception ex)
            {
                return ex.Message;
            }
        }

        public static string DecryptByPrivateKey(string ciphertext, string privateKey)
        {
            ciphertext = ciphertext.Replace(Environment.NewLine, string.Empty).Trim();

            IAsymmetricBlockCipher engine = new Pkcs1Encoding(new RsaEngine());

            try
            {
                engine.Init(false, GetPrivateKeyParameter(privateKey));

                var byteData = Convert.FromBase64String(ciphertext);

                var contentData = engine.ProcessBlock(byteData, 0, byteData.Length);

                return Encoding.UTF8.GetString(contentData);
            }

            catch (Exception ex)
            {
                return ex.Message;
            }
        }
    }
}