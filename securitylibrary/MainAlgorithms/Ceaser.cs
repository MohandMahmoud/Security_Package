using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string strToReturn = string.Empty;
            for (int i = 0; i < plainText.Length; i++)
            {
                if (plainText[i] >= 'A' && plainText[i] <= 'Z')
                {
                    strToReturn += (char)(((((int)(plainText[i])) - 65 + key) % 26) + 65);
                }
                else if (plainText[i] >= 'a' && plainText[i] <= 'z')
                {
                    strToReturn += (char)(((((int)(plainText[i])) - 97 + key) % 26) + 97);
                }
            }
            return strToReturn;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            key = 26 - key;
            string strToReturn = string.Empty;
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (cipherText[i] >= 'A' && cipherText[i] <= 'Z')
                {
                    strToReturn += (char)(((((int)(cipherText[i])) - 65 + key) % 26) + 65);
                }
                else if (cipherText[i] >= 'a' && cipherText[i] <= 'z')
                {
                    strToReturn += (char)(((((int)(cipherText[i])) - 97 + key) % 26) + 97);
                }
            }
            return strToReturn;
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();

            cipherText = cipherText.ToLower();
            int keyToReturn = 0;
            int np = 0; //number of the first char in plaintext
            if (plainText[0] >= 'a' && plainText[0] <= 'z')
            {
                np = (int)plainText[0] - 97;
            }
            else if (plainText[0] >= 'A' && plainText[0] <= 'Z')
            {
                np = (int)plainText[0] - 65;
            }
            int nc = cipherText[0] - 97; //number of the first char in ciphertext

            if ((int)plainText[0] > (int)cipherText[0])
            {
                keyToReturn = (nc - np) + 26;
            }
            else
            {
                keyToReturn = (nc - np) % 26;
            }
            return keyToReturn;
        }
    }
}