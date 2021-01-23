using System;
using System.Security.Cryptography;
using System.Text;
using Vrnz2.Infra.AsymmetricKeyHelper;
using Vrnz2.Infra.AsymmetricKeyHelper.Extensions;

namespace Vrnz2.Infra.Security.Libraries
{
    public class JwtToken
    {
        public string GetJwtSignature(string p_id, string u_id, string rnd)
        {
            byte[] plainText = UTF8Encoding.UTF8.GetBytes(string.Concat(p_id, u_id, rnd));
            byte[] signature = null;

            using (var rsa = new AsymmetricKey())
            {
                var rsaWrite = rsa.GetRSACryptoServiceProvider();

                rsaWrite.FromXmlString2(rsa.PrivateKey);

                signature = rsaWrite.SignData(plainText, CryptoConfig.MapNameToOID("SHA1"));
            }

            return Convert.ToBase64String(signature);
        }

        public bool JwtSignatureIsValid(string p_id, string u_id, string rnd, string sign)
        {
            var hash = new SHA1Managed();
            var result = false;

            byte[] signature = Convert.FromBase64String(sign);
            byte[] original = UTF8Encoding.UTF8.GetBytes(string.Concat(p_id, u_id, rnd));
            byte[] hashedData;

            using (var rsa = new AsymmetricKey())
            {
                var rsaRead = rsa.GetRSACryptoServiceProvider();

                rsaRead.FromXmlString2(rsa.PublicKey);

                if (rsaRead.VerifyData(original, CryptoConfig.MapNameToOID("SHA1"), signature))
                {
                    hashedData = hash.ComputeHash(original);

                    result = rsaRead.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA1"), signature);
                }
            }

            return result;
        }
    }
}
