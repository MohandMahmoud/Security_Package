using SecurityLibrary.DES;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            bool isHex = false;
            StringBuilder resultBuilder = new StringBuilder();

            if (cipherText.StartsWith("0x"))
            {
                cipherText = utils.Hex_Asci(cipherText.Substring(2));
                key = utils.Hex_Asci(key.Substring(2));
                isHex = true;
            }

            int[] S = new int[256];
            char[] T = new char[256];
            char[] keystream = new char[cipherText.Length];
            char[] output = new char[cipherText.Length];

            int i = 0;
            while (i < 256)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
                i++;
            }

            int j = 0;
            i = 0;
            while (i < 256)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
                i++;
            }

            int I = 0;
            j = 0;
            int k = 0;
            while (k < cipherText.Length)
            {
                I = (I + 1) % 256;
                j = (j + S[I]) % 256;
                int temp = S[I];
                S[I] = S[j];
                S[j] = temp;
                int t = (S[I] + S[j]) % 256;
                keystream[k] = (char)S[t];
                output[k] = (char)(cipherText[k] ^ keystream[k]);
                k++;
            }

            resultBuilder.Append(output);

            string result = resultBuilder.ToString();

            if (isHex)
            {
                result = utils.Asci_Hex(result);
                result = "0x" + result;
            }

            return result;
        }

        public override  string Encrypt(string plainText, string key)
        {
            bool isHex = false;

            if (plainText.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                plainText = utils.Hex_Asci(plainText.Substring(2));
                key = utils.Hex_Asci(key.Substring(2));
                isHex = true;
            }

            int[] S = new int[256];
            char[] T = new char[256];
            char[] keyStream = new char[plainText.Length];
            char[] output = new char[plainText.Length];

            for (int i = 0; i < 256; i++)
            {
                S[i] = i;
                T[i] = key[i % key.Length];
            }

            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }

            int I = 0;
            j = 0;
            for (int k = 0; k < plainText.Length; k++)
            {
                I = (I + 1) % 256;
                j = (j + S[I]) % 256;
                int temp = S[I];
                S[I] = S[j];
                S[j] = temp;
                int t = (S[I] + S[j]) % 256;
                keyStream[k] = (char)S[t];
                output[k] = (char)(plainText[k] ^ keyStream[k]);
            }

            string result = new string(output);

            if (isHex)
            {
                result = utils.Asci_Hex(result);
                result = "0x" + result;
            }

            return result;
        }
    }
}
