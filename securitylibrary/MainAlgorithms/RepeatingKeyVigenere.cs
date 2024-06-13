using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            //This method to get the keyby cipher text and plain 

            // here get the cipher text to lower text
            cipherText = cipherText.ToLower();
            // here get the plain text to lower text
            plainText = plainText.ToLower();
            // Generating the Repetative Key Vigenere Matrix Key is done here
            char[,] KeyVigenereMatrix = GenerateRepetativeKeyVigenereMatrixKey();
            //Initialize the key stream instaance
            string KeyStream = "";

            // for loop to iterate through the plain and cipher
            for (int i = 0; i < cipherText.Length; i++)
            {
                //Here I make sure of every character of plain and cipher text
                Console.WriteLine("plain text char: " + plainText[i]);
                Console.WriteLine("cipher text char: " + cipherText[i]);

                // GetKeyStreamCharacterIndex is a method that takes each character of plain and cipher and check the Key Vigenere Matrix
                // to retrieve the keystream character index
                int KeyIndex =
                    GetKeyStreamCharacterIndex(KeyVigenereMatrix, cipherText[i], plainText[i]);

                //Here checks the GetAlphapet() to get the it's index in the alphapetic order
                KeyStream += GetAlphaptical().ElementAt(KeyIndex);
            }
            // Here make sure that this is the key stream
            Console.WriteLine("KeyStream: " + KeyStream);
            //string key = ExtractKeyStream(KeyStream);
            // Here this method extracts the exact key by tracing the repeating pattern
            string key = ExtractKeyAlgorithm(KeyStream);
            Console.WriteLine("Key; " + key);
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            // first step is to lower case the cipher and key to ensure the right flow
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            // Generate the key stream from keyword
            string KeyStraem = GenerateKeyStream(cipherText, key);
            //Generate the RepetativeKeyVigenereMatrixKey
            char[,] KeyVigenereMatrix = GenerateRepetativeKeyVigenereMatrixKey();
            string Plain = "";
            for (int i = 0; i < cipherText.Length; i++)
            {
                // Each iteration we extract a plain char and by GetAlphaptical() we extract the char index
                int PlainIndex = GetPlainCharacterIndex(KeyVigenereMatrix, cipherText[i], KeyStraem[i]);
                //and after getting the index we get the char it self and concat it to the plain variable
                Plain += GetAlphaptical().ElementAt(PlainIndex);
            }
            Console.WriteLine(Plain);
            return Plain;
        }

        public string Encrypt(string plainText, string key)
        {
            // first step is to lower case the cipher and key to ensure the right flow
            plainText.ToLower();
            key.ToLower();
            //Generate the RepetativeKeyVigenereMatrixKey
            char[,] KeyVigenereMatrix = GenerateRepetativeKeyVigenereMatrixKey();
            // Generate the key stream from keyword
            string KeyStream = GenerateKeyStream(plainText, key);
            //get the list of the alphapetical to be able to get the indecies
            List<char> alphabet = GetAlphaptical();
            Console.WriteLine(alphabet.Count);
            // Initialize a string variable to hold the cipher
            string cipher = "";
            for (int i = 0; i < plainText.Length; i++)
            {
                Console.WriteLine(i);
                //get the index of the plain character
                int PlainIndex = alphabet.IndexOf(plainText[i]);
                Console.WriteLine("index of plain: " + PlainIndex);
                //get the index of the keystream character
                int KeyStreamIndex = alphabet.IndexOf(KeyStream[i]);
                Console.WriteLine("index of key: " + KeyStreamIndex);
                //At the end use the index of the plain as row #
                //and the index of the key stream as column # 
                //this extracts a char from the intersection
                //between row and column and this char is a cupher char that concats together to generate new cipher text
                cipher += KeyVigenereMatrix[PlainIndex, KeyStreamIndex];
            }
            return cipher;
        }

        // Here we generate the vigenere matrix
        private char[,] GenerateRepetativeKeyVigenereMatrixKey()
        {
            //determine the matrix size that is 26 due to size of english alphapetical
            int MatrixSize = 26;
            //Initialize the matrix with the pre-defined size (26,26)
            var RepetativeKeyVigenereMatrixKey = new char[MatrixSize, MatrixSize];

            //Loop that generates the matrix
            for (int Row = 0; Row < MatrixSize; Row++)
            {
                for (int Column = 0; Column < MatrixSize; Column++)
                {
                    //every iteration we fill the row and fill a cell in a column
                    // we do it by the ascii code and when adds the 'a' it converts to a code
                    RepetativeKeyVigenereMatrixKey[Row, Column] = CastToChar((Row + Column) % MatrixSize + 'a');
                }
            }
            return RepetativeKeyVigenereMatrixKey;
        }

        // This method casts every code that generates from the loop to a character
        private char CastToChar(int CharCode) => (char)CharCode;

        //Takes the key and returns the key stream
        private static string GenerateKeyStream(string pt, string key)
        {
            // this is the base case 
            // if the pt length and key length are equals then key is the key stream
            if (pt.Length == key.Length)
            {
                return key;
            }
            else
            {
                // else then we get the difference between the length of pt and key
                int diff = pt.Length - key.Length;
                // we loop to concat a cahars that satisfy the difference
                for (int i = 0; i < diff; i++)
                {
                    key += key[i];
                    Console.WriteLine("key after concat: " + key);
                }
                Console.WriteLine("key is: " + key);
                return key;
            }
        }

        private static List<char> GetAlphaptical()
        {
            List<char> alphabet = new List<char>()
        {
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
        };
            return alphabet;
        }
        //Method to get the index of every plain character
        private int GetPlainCharacterIndex(
    char[,] RepetativeKeyVigenereMatrixKey,
    char CharacterOfCiphrt, char CharacterOfKeyStream)
        {
            //Get the length of rows
            int rows = RepetativeKeyVigenereMatrixKey.GetLength(0);
            //Get the length of columns
            int cols = RepetativeKeyVigenereMatrixKey.GetLength(0);
            // initialize the plain index with initial value => -1
            int PlainIndex = -1;
            for (int row = 0; row < rows; row++)
            {
                for (int col = 0; col < cols; col++)
                {
                    // We loop until find the intersection where a char of cipher 
                    // and at the same time the row has a char of the keystream
                    if (RepetativeKeyVigenereMatrixKey[row, col] == CharacterOfCiphrt
                        && GetAlphaptical()[row] == CharacterOfKeyStream)
                    {
                        PlainIndex = col;
                    }
                }
            }
            return PlainIndex;
        }

        private static int GetKeyStreamCharacterIndex(
            char[,] RepetativeKeyVigenereMatrixKey,
            char CharacterOfCipher, char CharacterOfPlain
            )
        {
            //Get the length of rows
            int rows = RepetativeKeyVigenereMatrixKey.GetLength(0);
            //Get the length of columns
            int cols = RepetativeKeyVigenereMatrixKey.GetLength(1);
            // initialize the plain index with initial value => -1
            int KeyIndex = -1;
            for (int col = 0; col < cols; col++)
            {
                for (int row = 0; row < rows; row++)
                {
                    // We loop until find the intersection where a char of cipher 
                    // and at the same time the row has a char of the plain
                    if (
                        RepetativeKeyVigenereMatrixKey[row, col] == CharacterOfCipher
                        && GetAlphaptical()[row] == CharacterOfPlain
                        )
                    {
                        Console.WriteLine("col:" + col);
                        return col;
                    }
                }
            }
            return KeyIndex;
        }

        string ExtractKeyAlgorithm(string KeyStream)
        {
            int KeyStreamLength = KeyStream.Length;

            // Iterate through all possible lengths of the pattern
            for (int _KeyStreamLength = 1; _KeyStreamLength <= KeyStreamLength / 2; _KeyStreamLength++)
            {
                // Check if the substring of length 'len' repeats throughout the string
                bool isRepetitive = true;
                for (int i = _KeyStreamLength; i < KeyStreamLength; i++)
                {
                    if (IsRepetitiveCheck(KeyStream, i, _KeyStreamLength))
                    {
                        isRepetitive = false;
                        break;
                    }
                }

                if (isRepetitive)
                {
                    // Repetitive Pattern found and is extracted from index => 0 to _KeyStreamLength
                    return KeyRepetitivePattern(KeyStream, _KeyStreamLength);
                }
            }

            return null; // No repetitive pattern found
        }

        private string KeyRepetitivePattern(string keyStream, int keyStreamLength) => keyStream.Substring(0, keyStreamLength);

        private bool IsRepetitiveCheck(string KeyStream, int CurrentIndex, int CurrentLegnth) => KeyStream[CurrentIndex] != KeyStream[CurrentIndex - CurrentLegnth];
    }

}