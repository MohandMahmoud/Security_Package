using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class TripleDES : ICryptographicTechnique<string, List<string>>
    {
        public List<string> Analyse(string plainText,string cipherText)
        {
            throw new NotSupportedException();
        }
        public string Decrypt(string cipherText, List<string> key)
        {
            DES algorithm = new DES();
            var V1 = algorithm.Decrypt(cipherText, key[0]);
            var V2 = algorithm.Encrypt(V1, key[1]);
            return algorithm.Decrypt(V2, key[0]);
        }

        public string Encrypt(string plainText, List<string> key)
        {
            DES algorithm = new DES();
            var V1 = algorithm.Encrypt(plainText, key[0]);
            var V2 = algorithm.Decrypt(V1, key[1]);
            return algorithm.Encrypt(V2, key[0]);
        }


    }
}
