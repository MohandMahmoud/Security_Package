using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            int num = 0, count = 1;
            string res = "";

            char[] arr1 = new char[cipherText.Length];
            plainText = plainText.ToUpper();

            int i = 0;
            while (i < cipherText.Length)
            {

                int c = ((cipherText[i] - 'A') - (plainText[i] - 'A')) % 26;
                while (c < 0)
                    c += 26;
                arr1[i] = (char)(c + 'A');
                i++;
            }
            if (num == 0)
            {
                count++;
            }
            int ind = 0;
            bool found = false;
            i = 0;
            while (i < arr1.Length)
            {
                if (arr1[i] == plainText[0])
                {
                    ind = i + 1;

                    int j = 1;
                    while (j < plainText.Length - 1)
                    {
                        if (ind == arr1.Length || j == plainText.Length - 1)
                        {
                            found = true;
                            ind = i;
                            break;
                        }
                        if (plainText[j] != arr1[ind])
                            break;
                        ind++;
                        j++;
                    }

                }
                if (found)
                    break;

                i++;
            }

            if (found)
            {

                for (i = 0; i < ind; i++)
                {
                    res += arr1[i];

                }
            }
            return res.ToLower();
        }

        public string Decrypt(string cipherText, string key)
        {
            int num = 0, count = 1;
            string res = "";
            string keystream = key.ToUpper();
            char[] arr1 = new char[cipherText.Length];

            int index = 0;
            int i = 0;
            while (i < cipherText.Length)
            {
                if (i >= key.Length)
                {
                    keystream += arr1[index];
                    index++;
                }

                int c = ((cipherText[i] - 'A') - (keystream[i] - 'A')) % 26;
                while (c < 0)
                    c += 26;
                arr1[i] = (char)(c + 'A');
                i++;
            }
            if (num == 0)
            {
                count++;
            }

            res = new string(arr1);
            return res.ToLower();
        }

        public string Encrypt(string plainText, string key)
        {
            int num = 0, count = 1;
            string res = "";
            string keystream = key;
            char[] arr1 = new char[plainText.Length];

            if (key.Length < plainText.Length)
            {
                int diff = plainText.Length - key.Length;
                int ind = 0;
                while (ind < diff)
                {
                    for (int j = 0; j < diff; j++)
                    {
                        if (ind >= plainText.Length)
                            ind = 0;
                        keystream += plainText[ind];
                        ind++;
                    }
                }
            }
            if (num == 0)
            {
                count++;
            }
            int i = 0;
            while (i < plainText.Length)
            {
                if (plainText[i] >= 'A' && plainText[i] <= 'Z')
                    arr1[i] = (char)(((plainText[i] - 'A') + (keystream[i] - 'A')) % 26 + 'A');

                if (plainText[i] >= 'a' && plainText[i] <= 'z')
                    arr1[i] = (char)(((plainText[i] - 'a') + (keystream[i] - 'a')) % 26 + 'a');

                i++;
            }

            res = new string(arr1);
            return res.ToUpper();
        }
    }
}
