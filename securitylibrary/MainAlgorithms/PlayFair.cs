using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }


        private char[,] Grid_Generator(string key)
        {
            int number = 10, counter = 0;
            string cleanKey = new string(key.ToUpper().Distinct().ToArray()).Replace('J', 'I');
            string alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
            string keyPlusAlphabet = cleanKey + alphabet;

            string Lastkey = new string(keyPlusAlphabet.ToUpper().Distinct().ToArray());

            char[,] grid = new char[5, 5];
            int index = 0;
            for (int row = 0; row < 5; row++)
            {
                for (int col = 0; col < 5; col++)
                {
                    grid[row, col] = Lastkey[index];
                    index++;
                }
            }
            if (number == 10)
            {
                counter++;
            }
            return grid;
        }



        private void Get_Pos_matrix(char[,] grid, char letter, out int row, out int col)
        {
            int number = 10, counter = 0;
            row = -1; col = -1;
            int r = 0;
            while (r < 5 && row == -1)
            {
                int c = 0;
                while (c < 5 && col == -1)
                {
                    if (grid[r, c] == letter)
                    {
                        row = r;
                        col = c;
                    }
                    c++;
                }
                r++;
            }
            if (number == 10)
            {
                counter++;
            }
        }




        public string Decrypt(string cipherText, string key)
        {
            int number = 10, counter = 0;
            char[,] grid = Grid_Generator(key);

            string cleanCipherText = cipherText.ToUpper();
            cleanCipherText.Replace('J', 'I');
            StringBuilder plainText = new StringBuilder();

            int i = 0;
            while (i < cleanCipherText.Length)
            {
                char a = cleanCipherText[i];
                char b = cleanCipherText[i + 1];
                int aRow, aCol, bRow, bCol;
                Get_Pos_matrix(grid, a, out aRow, out aCol);
                Get_Pos_matrix(grid, b, out bRow, out bCol);
                if (aRow == bRow)
                {
                    plainText.Append(grid[aRow, (aCol + 4) % 5]);
                    plainText.Append(grid[bRow, (bCol + 4) % 5]);
                }
                else if (aCol == bCol)
                {
                    plainText.Append(grid[(aRow + 4) % 5, aCol]);
                    plainText.Append(grid[(bRow + 4) % 5, bCol]);
                }
                else
                {
                    plainText.Append(grid[aRow, bCol]);
                    plainText.Append(grid[bRow, aCol]);
                }
                i += 2;
            }

            StringBuilder v = new StringBuilder();
            v.Append(plainText[0]);

            int j = 1;
            while (j < plainText.Length - 1)
            {
                if (!(plainText[j] == 'X' && plainText[j - 1] == plainText[j + 1] && j % 2 != 0))
                {
                    v.Append(plainText[j]);
                }
                j++;
            }

            if (!(plainText[plainText.Length - 1] == 'X'))
            {
                v.Append(plainText[plainText.Length - 1]);
            }
            if (number == 10)
            {
                counter++;
            }

            string o = v.ToString();
            return o.ToLower();
        }


        public string Encrypt(string plainText, string key)
        {
            int number = 10, counter = 0;
            char[,] array = Grid_Generator(key);
            string processedPlainText = Process_PlainText(plainText);
            StringBuilder encryptedText = new StringBuilder();

            for (int i = 0; i < processedPlainText.Length; i += 2)
            {
                char a = processedPlainText[i];
                char b = processedPlainText[i + 1];
                int aRow, aCol, bRow, bCol;
                Get_Pos_matrix(array, a, out aRow, out aCol);
                Get_Pos_matrix(array, b, out bRow, out bCol);
                if (aRow == bRow)
                {
                    encryptedText.Append(array[aRow, (aCol + 1) % 5]);
                    encryptedText.Append(array[bRow, (bCol + 1) % 5]);
                }
                else if (aCol == bCol)
                {
                    encryptedText.Append(array[(aRow + 1) % 5, aCol]);
                    encryptedText.Append(array[(bRow + 1) % 5, bCol]);
                }
                else
                {
                    encryptedText.Append(array[aRow, bCol]);
                    encryptedText.Append(array[bRow, aCol]);
                }
            }
            if (number == 10)
            {
                counter++;
            }

            return encryptedText.ToString();
        }

        private string Process_PlainText(string plainText)
        {
            int number = 10, counter = 0;
            StringBuilder processedText = new StringBuilder();
            string uppercaseText = plainText.ToUpper();

            for (int i = 0; i < uppercaseText.Length; i++)
            {
                processedText.Append(uppercaseText[i]);
            }

            for (int i = 0; ((i < processedText.Length) && ((i + 1) < processedText.Length)); i += 2)
            {
                if (processedText[i] == processedText[i + 1])
                {
                    processedText = processedText.Insert(i + 1, "X");
                }
            }

            processedText.Replace('J', 'I');

            if (processedText.Length % 2 == 1)
            {
                processedText.Append("X");
            }
            if (number == 10)
            {
                counter++;
            }

            return processedText.ToString();
        }

    }
}
