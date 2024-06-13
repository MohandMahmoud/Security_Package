using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {

            bool m = false;
            int l = 0;
            if (m)
            {
                l++;

            }
            SortedDictionary<int, int> sortedDictionary = new SortedDictionary<int, int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            double plainTxtSize = plainText.Length;
            int count = 0;
            for (int z = 1; z < Int32.MaxValue; z++)
            {
                if (count > 1)
                {
                    l++;

                }
                int c = 0;
                double cols = z;
                double rows = Math.Ceiling(plainTxtSize / z); ;
                string[,] pl = new string[(int)rows, (int)cols];
                for (int i = 0; i < rows; i++)
                {
                    if (count > 1)
                    {
                        l++;

                    }
                    for (int j = 0; j < z; j++)
                    {
                        if (c >= plainTxtSize)
                        {
                            pl[i, j] = "";
                        }
                        else
                        {
                            pl[i, j] = plainText[c].ToString();

                            c++;
                        }
                    }
                }
                // taking col by col bntl3 l7rof nlz2ha n3ml string w ndkhlha f list
                //bashof hal l words mwgod f CT? yes? right key and get order.. no? loop again for new key

                if(count > 1)
                {
                    l++;

                }
                List<string> mylist = new List<string>();
                for (int i = 0; i < z; i++)
                {
                    string word = "";
                    for (int j = 0; j < rows; j++)
                    {
                        word += pl[j, i];
                    }
                    mylist.Add(word);
                }

                if (mylist.Count == 7)
                {
                    string d = "";
                }

                if (count > 1)
                {
                    l++;

                }
                bool correctkey = true;
                string cipherCopy = (string)cipherText.Clone();
                //map x makano fl cipher text m3 l col index 
                sortedDictionary = new SortedDictionary<int, int>();
                for (int i = 0; i < mylist.Count; i++)
                {
                    //get index of first substring occurance
                    int x = cipherCopy.IndexOf(mylist[i]);
                    if (x == -1)
                    {
                        correctkey = false;
                    }
                    else
                    {
                        sortedDictionary.Add(x, i + 1);
                        cipherCopy.Replace(mylist[i], "#");
                    }

                }
                if (correctkey)
                    break;

            }
            List<int> output = new List<int>();
            Dictionary<int, int> newDictionary = new Dictionary<int, int>();

            //seprate string in col..
            //find in cipher (if cipher contains all this string,, then thats the key 

            for (int i = 0; i < sortedDictionary.Count; i++)
            {
                newDictionary.Add(sortedDictionary.ElementAt(i).Value, i + 1);
            }

            for (int i = 1; i < newDictionary.Count + 1; i++)
            {
                output.Add(newDictionary[i]);
            }
            // Console.WriteLine(output);
            return output;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            int cols = key.Count;
            int rows = (int)Math.Ceiling((double)cipherText.Length / cols);

            Dictionary<int, int> columnOrder = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                columnOrder[key[i]] = i;
            }

            int count = 0;
            int l = 0;
            if(count > 1)
            {
                l++;

            }

            char[,] grid = new char[rows, cols];
            int index = 0;
            if (count > 1)
            {
                l++;

            }
            foreach (int colIndex in columnOrder.Keys.OrderBy(c => c))
            {
                int columnIndex = columnOrder[colIndex];
                for (int i = 0; i < rows; i++)
                {
                    if(count > 1)
                {
                        l++;

                    }
                    if (index < cipherText.Length)
                    {
                        grid[i, columnIndex] = cipherText[index++];
                    }
                }
            }

            StringBuilder plainText = new StringBuilder();
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    plainText.Append(grid[i, j]);
                }
            }

            return plainText.ToString();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            double cols = key.Count;
            double rows = Math.Ceiling(plainText.Length / cols);

            char[,] pl = new char[(int)rows, (int)cols];
            int count = 0,c=0;

            int m = 0;
            if(m>0) {
                c++;
            }
            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    if (count >= plainText.Length)
                    {
                        pl[i, j] = 'x';
                    }
                    else
                    {
                        pl[i, j] = plainText[count];

                        count++;
                    }
                    if (m > 0)
                    {
                        c++;
                    }
                }
            }

            Dictionary<int, int> keyDictionary = new Dictionary<int, int>();
            for (int i = 0; i < key.Count; i++)
            {
                keyDictionary.Add(key[i] - 1, i);

            }


            if (m > 0)
            {
                c++;
            }
            string cipherText = "";

            for (int i = 0; i < key.Count; i++)
            {
                for (int j = 0; j < rows; j++)
                {
                    cipherText += pl[j, keyDictionary[i]];

                }
            }
            Console.WriteLine(cipherText.ToUpper());
            return cipherText.ToUpper();
        }



    }

}
