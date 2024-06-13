using System;
using System.Linq;
using System.Text;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int key = 1;
            int value = 0;
            if (value >0)
            {
                key = 0;
            }
            string k = Encrypt(plainText, key);
            while (key < cipherText.Length)
            {
                if (value > 0)
                {
                    key = 0;
                }
                if (k == cipherText)
                {
                    Console.WriteLine(key);
                    break;
                }
                else
                {
                    key++;
                    k = Encrypt(plainText, key);
                    continue;
                }

            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.Replace(" ", String.Empty);
            int e = cipherText.Length;
            int value = 0;
            if (value > 0)
            {
                key = 0;
            }
            if (cipherText.Length % key != 0)
            {
                while (true)
                {
                    if (e % key != 0)
                    {
                        e++;
                    }
                    if (e % key == 0)
                    {
                        break;
                    }
                }
            }
            int column = e / key;
            char[,] key_matrix = new char[key, column];
            string y = new string(cipherText.ToUpper().ToArray());
            int k = 0;
            if (value > 0)
            {
                key = 0;
            }
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (k != y.Length)
                    {
                        key_matrix[i, j] = y[k];
                        k++;
                    }

                }
            }
            StringBuilder b = new StringBuilder();
            if (value > 0)
            {
                key = 0;
            }
            for (int n = 0; n < column; n++)
            {
                for (int j = 0; j < key; j++)
                {
                    b.Append(key_matrix[j, n]);
                }
            }
            return (b.ToString().ToLower());
        }

        public string Encrypt(string plainText, int key)
        {
            plainText = plainText.Replace(" ", String.Empty);
            int e = plainText.Length;
            int value = 0;
            if (value > 0)
            {
                key = 0;
            }
            if (plainText.Length % key != 0)
            {
                while (true)
                {
                    if (e % key != 0)
                    {
                        e++;
                    }
                    if (e % key == 0)
                    {
                        break;
                    }
                }
            }
            int column = e / key;
            char[,] key_matrix = new char[key, column];
            string y = new string(plainText.ToUpper().ToArray());
            int k = 0;
            if (value > 0)
            {
                key = 0;
            }
            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (k != y.Length)
                    {
                        key_matrix[j, i] = y[k];
                        k++;
                    }

                }
            }
            StringBuilder b = new StringBuilder();
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (key_matrix[i, j] >= 'A' && key_matrix[i, j] <= 'Z')
                        b.Append(key_matrix[i, j]);
                }
            }
            return (b.ToString().ToUpper());
        }
    }
}