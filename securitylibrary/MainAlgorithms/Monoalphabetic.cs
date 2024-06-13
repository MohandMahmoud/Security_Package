using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        String alphabetic_Elements = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        String alphabetic_Elements_freq = "etaoinsrhldcumfpgwybvkxjqz";
        private Dictionary<string, int> frequencyMap = new Dictionary<string, int>();
        public char[] Checkey_Analyse(char[] plainTextArray, char[] charArray, char[] cipherTextArray)
        {
            char[] keyArray = new char[charArray.Length];
            foreach (char plainChar in plainTextArray)
            {
                foreach (char charElement in charArray)
                {
                    if (plainChar == charElement)
                    {
                        keyArray[Array.IndexOf(charArray, charElement)] = cipherTextArray[Array.IndexOf(plainTextArray, plainChar)];
                    }
                }
            }
            return keyArray;
        }
        public char[] Handle_Analyse(char[] keyArray, char[] charArray)
        {
            foreach (char keyElement in keyArray)
            {
                if (keyElement == '\0')
                {
                    foreach (char charElement in charArray)
                    {
                        if (!keyArray.Contains(charElement))
                        {
                            keyArray[Array.IndexOf(keyArray, '\0')] = charElement;
                            break;
                        }
                    }
                }
            }
            return keyArray;
        }
        public string Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            char[] plainTextArray = plainText.ToCharArray();
            char[] cipherTextArray = cipherText.ToCharArray();
            char[] charArray = alphabetic_Elements.Substring(26).ToCharArray();
            char[] keyArray = new char[charArray.Length];
            keyArray = Checkey_Analyse(plainTextArray, charArray, cipherTextArray);
            string key = new string(Handle_Analyse(keyArray, charArray));
            return key;
        }

        public string Handle_Decrypt(char[] cipherTextArray, char[] alphabetic_ElementsArray, string key)
        {
            string plainText = "";
            foreach (char i in cipherTextArray)
            {
                if (char.IsLetter(i))
                {
                    int index = key.IndexOf(char.ToLower(i));

                    if (index != -1)
                    {
                        char decryptedChar = char.IsUpper(i) ? alphabetic_ElementsArray[index] : char.ToLower(alphabetic_ElementsArray[index]);
                        plainText += decryptedChar;
                    }
                    else
                    {
                        plainText += i;
                    }
                }
                else
                {
                    plainText += i;
                }
            }

            return plainText;
        }
        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            char[] cipherTextArray = cipherText.ToCharArray();
            char[] alphabetic_ElementsArray = alphabetic_Elements.ToCharArray();
            return Handle_Decrypt(cipherTextArray, alphabetic_ElementsArray, key);
        }

        public string Handle_Encrypt(char[] plainTextArray, char[] alphabetic_ElementsArray, string key)
        {
            string ciphertext = "";
            foreach (char i in plainTextArray)
            {
                if (char.IsLetter(i))
                {
                    int index = Array.IndexOf(alphabetic_ElementsArray, char.ToUpper(i));
                    if (index != -1)
                    {
                        char encryptedChar = char.IsUpper(i) ? key[index] : char.ToLower(key[index]);
                        ciphertext += encryptedChar;
                    }
                    else
                    {
                        ciphertext += i;
                    }
                }
                else
                {
                    ciphertext += i;
                }
            }
            return ciphertext;
        }
        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            char[] plainTextArray = plainText.ToCharArray();
            char[] alphabetic_ElementsArray = alphabetic_Elements.ToCharArray();
            return Handle_Encrypt(plainTextArray, alphabetic_ElementsArray, key);

        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public Dictionary<string, int> Handle_CharFrequency(string cipher)
        {
            foreach (char c in cipher)
            {
                string currentKey = c.ToString();

                if (frequencyMap.ContainsKey(currentKey))
                {
                    frequencyMap[currentKey]++;
                }
                else
                {
                    frequencyMap[currentKey] = 1;
                }
            }
            return frequencyMap.OrderByDescending(entry => entry.Value).ToDictionary(v => v.Key, v => v.Value);
        }

        public string Finish_CharFrequency(Dictionary<string, int> My_plain_Map, string cipher)
        {
            string plainText = "";
            foreach (char c in cipher)
            {
                plainText += alphabetic_Elements_freq[My_plain_Map.Keys.ToList().IndexOf(c.ToString())];
            }
            return plainText;
        }
        public string AnalyseUsingCharFrequency(string cipher)
        {
            //throw new NotImplementedException();
            cipher = cipher.ToLower();
            Dictionary<string, int> My_plain_Map = Handle_CharFrequency(cipher);
            return Finish_CharFrequency(My_plain_Map, cipher);
        }
    }
}
