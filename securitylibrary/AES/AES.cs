using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class AES : CryptographicTechnique
    {

        /// <summary>
        /// S-Box used for the SubBytes step in AES encryption and decryption
        /// </summary>
        ///         /// <summary>
        /// Convert_Bytes to make vectoes with Bytes
        /// </summary>
        public Byte Convert_Bytes(Byte Vector_A, Byte Vector_B)
        {
            Byte My_Bytes = 0;
            Byte temp;
            Byte[] bitPositions = new Byte[8];
            int position = 0;
            while (position < 8)
            {
                bitPositions[position] = (Byte)((Vector_B >> position) & 0x01);
                position++;
            }
            int index = 0;
            foreach (Byte bit in bitPositions)
            {
                if (bit == 0x01)
                {
                    temp = Vector_A;
                    int count = 0;
                    while (count < index)
                    {
                        Byte highBit = (Byte)(temp & 0x80);
                        temp <<= 1;
                        if (highBit != 0)
                        {
                            temp ^= 0x1B;
                        }
                        count++;
                    }
                    My_Bytes ^= temp;
                }
                index++;
            }

            return My_Bytes;
        }

        public static Byte[,] SBOX = AES_utils.SBOX;
        /// <summary>
        /// Inverse S-Box used for the Inverse SubBytes step in AES decryption.
        /// </summary>
        public static Byte[,] SBOXInverse = AES_utils.SBOXInverse;
        /// <summary>
        /// Decrypt Convert from cipherText to plainTxt 
        /// </summary>
        public override string Decrypt(string cipherText, string key)
        {
            /// <summary>
            /// Intlize 2 vectoers 
            /// </summary>
            List<Byte> vector_A = new List<Byte>();
            for (int i = 0; i < 4; i++)
                vector_A.Add(0x00);
            List<Byte> vector_B = new List<Byte>();
            for (int i = 0; i < 4; i++)
                vector_B.Add(0x00);
            /// <summary>
            /// Creat matrix to Cipher 
            /// </summary>
            List<List<Byte>> Text_matrix = new List<List<Byte>>();
            for (int i = 0; i < 4; i++)
                Text_matrix.Add(new List<byte>());
            foreach (var sublist in Text_matrix)
            {
                for (int j = 0; j < 44; j++)
                    sublist.Add(0x00);
            }
            /// <summary>
            /// Creat matrix to key  
            /// </summary>
            List<List<Byte>> Key_matrix = new List<List<Byte>>();
            for (int i = 0; i < 4; i++)
                Key_matrix.Add(new List<byte>());
            foreach (var sublist in Key_matrix)
            {
                for (int j = 0; j < 4; j++)
                    sublist.Add(0x00);
            }
            /// <summary>
            /// pass cipher to matrix
            /// skip first 2 char 0x
            /// </summary>
            int Skip = 2;
            List<List<Byte>> cipherText_matrix = new List<List<Byte>>();
            for (int i = 0; i < 4; i++)
            {
                List<Byte> cipherText_value = new List<Byte>();
                for (int k = 0; k < 4; k++)
                {
                    string Bytes = "";
                    Bytes += cipherText[Skip];
                    Bytes += cipherText[Skip + 1];
                    Byte byteValue = Byte.Parse(Bytes, System.Globalization.NumberStyles.AllowHexSpecifier);
                    cipherText_value.Add(byteValue);
                    Skip += 2;
                }
                cipherText_matrix.Add(cipherText_value);
            }
            /// <summary>
            /// Transposed Cipher Matrix 
            /// </summary>
            List<List<byte>> transposed_cipherText_matrix = new List<List<byte>>();
            for (int i = 0; i < 4; i++)
            {
                List<byte> new_cipherText_value = new List<byte>();
                foreach (var word in cipherText_matrix)
                {
                    new_cipherText_value.Add(word[i]);
                }
                transposed_cipherText_matrix.Add(new_cipherText_value);
            }
            /// <summary>
            /// pass Key to matrix
            /// skip first 2 char 0x
            /// </summary>
            List<List<Byte>> Key_Text_matrix = new List<List<Byte>>();
            int Skip_key = 2;
            for (int i = 0; i < 4; i++)
            {
                List<Byte> Key_Text_matrix_value = new List<Byte>();
                for (int k = 0; k < 4; k++)
                {
                    string Bytes = "";
                    Bytes += key[Skip_key];
                    Bytes += key[Skip_key + 1];
                    Byte byteValue = Byte.Parse(Bytes, System.Globalization.NumberStyles.AllowHexSpecifier);
                    Key_Text_matrix_value.Add(byteValue);
                    Skip_key += 2;
                }
                Key_Text_matrix.Add(Key_Text_matrix_value);
            }
            /// <summary>
            /// Transposed Key Matrix 
            /// </summary>
            List<List<byte>> transposed_Key_Text_matrix = new List<List<byte>>();
            for (int i = 0; i < 4; i++)
            {
                List<byte> new_Key_Text_matrix = new List<byte>();
                foreach (var word in Key_Text_matrix)
                {
                    new_Key_Text_matrix.Add(word[i]);
                }
                transposed_Key_Text_matrix.Add(new_Key_Text_matrix);
            }
            /// <summary>
            ///  Key expansion routine to derive all round keys from the initial key
            /// </summary>
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    if (i < transposed_Key_Text_matrix[j].Count)
                        Text_matrix[j][i] = transposed_Key_Text_matrix[j][i];
            /// <summary>
            ///  Key expansion routine to derive all round keys from the initial key
            /// </summary>
            for (int i = 4; i < 44; i++)
            {
                List<byte> prev = new List<byte>();
                for (int j = 0; j < 4; j++)
                    prev.Add(Text_matrix[j][i - 1]);

                if (i % 4 == 0)
                {
                    byte temp = prev[0];
                    prev.RemoveAt(0);
                    prev.Add(temp);
                    for (int k = 0; k < 4; k++)
                        prev[k] = SBOX[prev[k] / 16, prev[k] % 16];
                    byte B = 0x01;
                    for (int m = 0; m < (i / 4) - 1; m++)
                        B = (byte)((B << 1) ^ ((B >> 7) * 0x11b));
                    prev[0] ^= B;
                    prev[1] ^= 0x00;
                    prev[2] ^= 0x00;
                    prev[3] ^= 0x00;
                }
                for (int j = 0; j < 4; j++)
                    Text_matrix[j][i] = (byte)(Text_matrix[j][i - 4] ^ prev[j]);
            }
            int Start = 0, End;
            while (Start < 4)
            {
                End = 0;
                while (End < 4)
                {
                    Key_matrix[End][Start] = Text_matrix[End][40 + Start];
                    End++;
                }
                Start++;
            }
            int Start_key = 0;
            while (Start_key < 4)
            {
                int End_key = 0;
                while (End_key < 4)
                {
                    transposed_cipherText_matrix[End_key][Start_key] = (Byte)(transposed_cipherText_matrix[End_key][Start_key] ^ Key_matrix[End_key][Start_key]);
                    End_key++;
                }
                Start_key++;
            }
            /// <summary>
            ///  Beginning of the actual decryption rounds involving inverse operations
            /// </summary>
            int[] numbers = Enumerable.Range(1, 9).Reverse().ToArray();
            foreach (int i in numbers)
            {
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int V = 0; V < 3; V++)
                {
                    Byte temp = transposed_cipherText_matrix[1][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[1][j] = transposed_cipherText_matrix[1][j + 1];
                    }
                    transposed_cipherText_matrix[1][3] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int C = 0; C < 2; C++)
                {
                    Byte temp = transposed_cipherText_matrix[2][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[2][j] = transposed_cipherText_matrix[2][j + 1];
                    }
                    transposed_cipherText_matrix[2][3] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int G = 0; G < 1; G++)
                {
                    Byte temp = transposed_cipherText_matrix[3][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[3][j] = transposed_cipherText_matrix[3][j + 1];
                    }
                    transposed_cipherText_matrix[3][3] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                int Box_i = 0;
                while (Box_i < 4)
                {
                    int Box_j = 0;
                    while (Box_j < 4)
                    {
                        transposed_cipherText_matrix[Box_j][Box_i] = SBOXInverse[transposed_cipherText_matrix[Box_j][Box_i] / 16, transposed_cipherText_matrix[Box_j][Box_i] % 16];
                        Box_j++;
                    }
                    Box_i++;
                }
                int index = i * 4;
                int N = 0;
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                while (N < 4)
                {
                    int L = 0;
                    while (L < 4)
                    {
                        Key_matrix[L][N] = Text_matrix[L][index + N];
                        L++;
                    }
                    N++;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                int Box_key = 0;
                while (Box_key < 4)
                {
                    int End_key = 0;
                    while (End_key < 4)
                    {
                        transposed_cipherText_matrix[End_key][Box_key] = (Byte)(transposed_cipherText_matrix[End_key][Box_key] ^ Key_matrix[End_key][Box_key]);
                        End_key++;
                    }
                    Box_key++;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int col = 0; col < 4; col++)
                {

                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    for (int row = 0; row < 4; row++)
                    {
                        vector_A[row] = transposed_cipherText_matrix[row][col];
                    }

                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    vector_B[0] = (Byte)(Convert_Bytes(0x0E, vector_A[0]) ^ Convert_Bytes(0x0B, vector_A[1]) ^ Convert_Bytes(0x0D, vector_A[2]) ^ Convert_Bytes(0x09, vector_A[3]));
                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    vector_B[1] = (Byte)(Convert_Bytes(0x09, vector_A[0]) ^ Convert_Bytes(0x0E, vector_A[1]) ^ Convert_Bytes(0x0B, vector_A[2]) ^ Convert_Bytes(0x0D, vector_A[3]));
                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    vector_B[2] = (Byte)(Convert_Bytes(0x0D, vector_A[0]) ^ Convert_Bytes(0x09, vector_A[1]) ^ Convert_Bytes(0x0E, vector_A[2]) ^ Convert_Bytes(0x0B, vector_A[3]));
                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    vector_B[3] = (Byte)(Convert_Bytes(0x0B, vector_A[0]) ^ Convert_Bytes(0x0D, vector_A[1]) ^ Convert_Bytes(0x09, vector_A[2]) ^ Convert_Bytes(0x0E, vector_A[3]));
                    /// <summary>
                    /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                    /// </summary>
                    for (int row = 0; row < 4; row++)
                    {
                        transposed_cipherText_matrix[row][col] = vector_B[row];
                    }
                }
            }
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            for (int V = 0; V < 3; V++)
            {
                Byte temp = transposed_cipherText_matrix[1][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[1][j] = transposed_cipherText_matrix[1][j + 1];
                }
                transposed_cipherText_matrix[1][3] = temp;
            }
            /// <summary>
            /// Final round operations excluding the Inverse MixColumns
            /// </summary>
            for (int C = 0; C < 2; C++)
            {
                Byte temp = transposed_cipherText_matrix[2][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[2][j] = transposed_cipherText_matrix[2][j + 1];
                }
                transposed_cipherText_matrix[2][3] = temp;
            }
            /// <summary>
            /// Final round operations excluding the Inverse MixColumns
            /// </summary>
            for (int G = 0; G < 1; G++)
            {
                Byte temp = transposed_cipherText_matrix[3][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[3][j] = transposed_cipherText_matrix[3][j + 1];
                }
                transposed_cipherText_matrix[3][3] = temp;
            }
            int final = 0;
            while (final < 4)
            {
                int Box_j = 0;
                while (Box_j < 4)
                {
                    transposed_cipherText_matrix[Box_j][final] = SBOXInverse[transposed_cipherText_matrix[Box_j][final] / 16, transposed_cipherText_matrix[Box_j][final] % 16];
                    Box_j++;
                }
                final++;
            }
            int P = 0;
            /// <summary>
            /// Final round operations excluding the Inverse MixColumns
            /// </summary>
            while (P < 4)
            {
                int L = 0;
                while (L < 4)
                {
                    Key_matrix[L][P] = Text_matrix[L][P];
                    L++;
                }
                P++;
            }
            int final_key = 0;
            /// <summary>
            /// Final round operations excluding the Inverse MixColumns
            /// </summary>
            while (final_key < 4)
            {
                int End_key = 0;
                while (End_key < 4)
                {
                    transposed_cipherText_matrix[End_key][final_key] = (Byte)(transposed_cipherText_matrix[End_key][final_key] ^ Key_matrix[End_key][final_key]);
                    End_key++;
                }
                final_key++;
            }
            /// <summary>
            /// Conversion of the decrypted state matrix back to a hexadecimal string
            /// </summary>
            string Plain_txt = "0x";
            int O = 0;
            while (O < 4)
            {
                foreach (var row in transposed_cipherText_matrix)
                {
                    string value = Convert.ToString(row[O], 16);
                    if (value.Length == 1)
                        value = "0" + value;
                    Plain_txt += value;
                }
                O++;
            }
            return Plain_txt;
            /// <summary>
            /// Retrun Plain_txt
            /// </summary>
        }
        public override string Encrypt(string plainText, string key)
        {
            /// <summary>
            /// Intlize 2 vectoers 
            /// </summary>
            List<Byte> vector_A = new List<Byte>();
            for (int i = 0; i < 4; i++)
                vector_A.Add(0x00);
            List<Byte> vector_B = new List<Byte>();
            for (int i = 0; i < 4; i++)
                vector_B.Add(0x00);
            List<List<Byte>> Text_matrix = new List<List<Byte>>();
            /// <summary>
            /// Creat matrix to Cipher 
            /// </summary>
            for (int i = 0; i < 4; i++)
                Text_matrix.Add(new List<byte>());
            foreach (var sublist in Text_matrix)
            {
                for (int j = 0; j < 44; j++)
                    sublist.Add(0x00);
            }
            List<List<Byte>> Key_matrix = new List<List<Byte>>();
            for (int i = 0; i < 4; i++)
                Key_matrix.Add(new List<byte>());
            /// <summary>
            /// Creat matrix to key  
            /// </summary>
            foreach (var sublist in Key_matrix)
            {
                for (int j = 0; j < 4; j++)
                    sublist.Add(0x00);
            }
            /// <summary>
            /// pass cipher to matrix
            /// skip first 2 char 0x
            /// </summary>
            int Skip = 2;
            List<List<Byte>> cipherText_matrix = new List<List<Byte>>();
            for (int i = 0; i < 4; i++)
            {
                List<Byte> cipherText_value = new List<Byte>();
                for (int k = 0; k < 4; k++)
                {
                    string Bytes = "";
                    Bytes += plainText[Skip];
                    Bytes += plainText[Skip + 1];
                    Byte byteValue = Byte.Parse(Bytes, System.Globalization.NumberStyles.AllowHexSpecifier);
                    cipherText_value.Add(byteValue);
                    Skip += 2;
                }
                cipherText_matrix.Add(cipherText_value);
            }
            /// <summary>
            /// Transposed Cipher Matrix 
            /// </summary>
            List<List<byte>> transposed_cipherText_matrix = new List<List<byte>>();
            for (int i = 0; i < 4; i++)
            {
                List<byte> new_cipherText_value = new List<byte>();
                foreach (var word in cipherText_matrix)
                {
                    new_cipherText_value.Add(word[i]);
                }
                transposed_cipherText_matrix.Add(new_cipherText_value);
            }
            /// <summary>
            /// Transposed Key Matrix 
            /// </summary>
            List<List<Byte>> Key_Text_matrix = new List<List<Byte>>();
            int Skip_key = 2;
            for (int i = 0; i < 4; i++)
            {
                List<Byte> Key_Text_matrix_value = new List<Byte>();
                for (int k = 0; k < 4; k++)
                {
                    string Bytes = "";
                    Bytes += key[Skip_key];
                    Bytes += key[Skip_key + 1];
                    Byte byteValue = Byte.Parse(Bytes, System.Globalization.NumberStyles.AllowHexSpecifier);
                    Key_Text_matrix_value.Add(byteValue);
                    Skip_key += 2;
                }
                Key_Text_matrix.Add(Key_Text_matrix_value);
            }
            List<List<byte>> transposed_Key_Text_matrix = new List<List<byte>>();
            /// <summary>
            ///  Key expansion routine to derive all round keys from the initial key
            /// </summary>
            for (int i = 0; i < 4; i++)
            {
                List<byte> new_Key_Text_matrix = new List<byte>();
                foreach (var word in Key_Text_matrix)
                {
                    new_Key_Text_matrix.Add(word[i]);
                }
                transposed_Key_Text_matrix.Add(new_Key_Text_matrix);
            }
            for (int i = 0; i < 4; i++)
                for (int j = 0; j < 4; j++)
                    if (i < transposed_Key_Text_matrix[j].Count)
                        Text_matrix[j][i] = transposed_Key_Text_matrix[j][i];
            /// <summary>
            ///  Beginning of the actual decryption rounds involving inverse operations
            /// </summary>

            for (int i = 4; i < 44; i++)
            {
                List<byte> prev = new List<byte>();
                for (int j = 0; j < 4; j++)
                    prev.Add(Text_matrix[j][i - 1]);

                if (i % 4 == 0)
                {
                    byte temp = prev[0];
                    prev.RemoveAt(0);
                    prev.Add(temp);
                    for (int k = 0; k < 4; k++)
                        prev[k] = SBOX[prev[k] / 16, prev[k] % 16];
                    byte B = 0x01;
                    for (int m = 0; m < (i / 4) - 1; m++)
                        B = (byte)((B << 1) ^ ((B >> 7) * 0x11b));
                    prev[0] ^= B;
                    prev[1] ^= 0x00;
                    prev[2] ^= 0x00;
                    prev[3] ^= 0x00;
                }
                for (int j = 0; j < 4; j++)
                    Text_matrix[j][i] = (byte)(Text_matrix[j][i - 4] ^ prev[j]);
            }
            int N = 0;
            /// <summary>
            ///  Key expansion routine to derive all round keys from the initial key
            /// </summary>
            while (N < 4)
            {
                int L = 0;
                while (L < 4)
                {
                    Key_matrix[L][N] = Text_matrix[L][N];
                    L++;
                }
                N++;
            }
            /// <summary>
            ///  Key expansion routine to derive all round keys from the initial key
            /// </summary>
            int Box_key = 0;
            while (Box_key < 4)
            {
                int End_key = 0;
                while (End_key < 4)
                {
                    transposed_cipherText_matrix[End_key][Box_key] = (Byte)(transposed_cipherText_matrix[End_key][Box_key] ^ Key_matrix[End_key][Box_key]);
                    End_key++;
                }
                Box_key++;
            }
            /// <summary>
            ///  Beginning of the actual decryption rounds involving inverse operations
            /// </summary>
            int[] numbers = Enumerable.Range(1, 9).ToArray();
            foreach (int i in numbers)
            {
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                int R = 0;
                while (R < 4)
                {
                    int j = 0;
                    while (j < 4)
                    {
                        int high = transposed_cipherText_matrix[j][R] / 16;
                        int low = transposed_cipherText_matrix[j][R] % 16;
                        transposed_cipherText_matrix[j][R] = SBOX[high, low];
                        j++;

                    }
                    R++;

                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int W = 0; W < 1; W++)
                {
                    Byte temp = transposed_cipherText_matrix[1][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[1][j] = transposed_cipherText_matrix[1][j + 1];
                    }
                    transposed_cipherText_matrix[1][4 - 1] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int Q = 0; Q < 2; Q++)
                {
                    Byte temp = transposed_cipherText_matrix[2][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[2][j] = transposed_cipherText_matrix[2][j + 1];
                    }
                    transposed_cipherText_matrix[2][3] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int F = 0; F < 3; F++)
                {
                    Byte temp = transposed_cipherText_matrix[3][0];
                    for (int j = 0; j < 3; j++)
                    {
                        transposed_cipherText_matrix[3][j] = transposed_cipherText_matrix[3][j + 1];
                    }
                    transposed_cipherText_matrix[3][3] = temp;
                }
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                for (int col = 0; col < 4; col++)
                {
                    for (int row = 0; row < 4; row++)
                    {
                        vector_A[row] = transposed_cipherText_matrix[row][col];
                    }

                    vector_B[0] = (byte)(Convert_Bytes(0x02, vector_A[0]) ^ Convert_Bytes(0x03, vector_A[1]) ^ vector_A[2] ^ vector_A[3]);
                    vector_B[1] = (byte)(vector_A[0] ^ Convert_Bytes(0x02, vector_A[1]) ^ Convert_Bytes(0x03, vector_A[2]) ^ vector_A[3]);
                    vector_B[2] = (byte)(vector_A[0] ^ vector_A[1] ^ Convert_Bytes(0x02, vector_A[2]) ^ Convert_Bytes(0x03, vector_A[3]));
                    vector_B[3] = (byte)(Convert_Bytes(0x03, vector_A[0]) ^ vector_A[1] ^ vector_A[2] ^ Convert_Bytes(0x02, vector_A[3]));

                    for (int row = 0; row < 4; row++)
                    {
                        transposed_cipherText_matrix[row][col] = vector_B[row];
                    }
                }
                int index = i * 4;
                int H = 0;
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                while (H < 4)
                {
                    int L = 0;
                    while (L < 4)
                    {
                        Key_matrix[L][H] = Text_matrix[L][index + H];
                        L++;
                    }
                    H++;
                }
                int final_key = 0;
                /// <summary>
                /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
                /// </summary>
                while (final_key < 4)
                {
                    int End_key = 0;
                    while (End_key < 4)
                    {
                        transposed_cipherText_matrix[End_key][final_key] = (Byte)(transposed_cipherText_matrix[End_key][final_key] ^ Key_matrix[End_key][final_key]);
                        End_key++;
                    }
                    final_key++;
                }


            }

            int Final_Box = 0;
            int END_Box;
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            while (Final_Box < 4)
            {
                END_Box = 0;
                while (END_Box < 4)
                {
                    transposed_cipherText_matrix[END_Box][Final_Box] = SBOX[transposed_cipherText_matrix[END_Box][Final_Box] / 16, transposed_cipherText_matrix[END_Box][Final_Box] % 16];
                    END_Box++;
                }
                Final_Box++;
            }
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            for (int W = 0; W < 1; W++)
            {
                Byte temp = transposed_cipherText_matrix[1][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[1][j] = transposed_cipherText_matrix[1][j + 1];
                }
                transposed_cipherText_matrix[1][4 - 1] = temp;
            }
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            for (int Q = 0; Q < 2; Q++)
            {
                Byte temp = transposed_cipherText_matrix[2][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[2][j] = transposed_cipherText_matrix[2][j + 1];
                }
                transposed_cipherText_matrix[2][3] = temp;
            }
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            for (int F = 0; F < 3; F++)
            {
                Byte temp = transposed_cipherText_matrix[3][0];
                for (int j = 0; j < 3; j++)
                {
                    transposed_cipherText_matrix[3][j] = transposed_cipherText_matrix[3][j + 1];
                }
                transposed_cipherText_matrix[3][3] = temp;
            }
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            int D = 0;
            int I;
            /// <summary>
            /// Inverse SubBytes, Inverse ShiftRows, AddRoundKey, and Inverse MixColumns operations
            /// </summary>
            while (D < 4)
            {
                I = 0;
                while (I < 4)
                {
                    Key_matrix[I][D] = Text_matrix[I][40 + D];
                    I++;
                }
                D++;
            }
            int U_Key = 0;
            /// <summary>
            /// Conversion of the decrypted state matrix back to a hexadecimal string
            /// </summary>
            while (U_Key < 4)
            {
                int End_key = 0;
                while (End_key < 4)
                {
                    transposed_cipherText_matrix[End_key][U_Key] = (Byte)(transposed_cipherText_matrix[End_key][U_Key] ^ Key_matrix[End_key][U_Key]);
                    End_key++;
                }
                U_Key++;
            }
            string CipherText = "0x";
            int O = 0;
            while (O < 4)
            {
                foreach (var row in transposed_cipherText_matrix)
                {
                    string value = Convert.ToString(row[O], 16);
                    if (value.Length == 1)
                        value = "0" + value;
                    CipherText += value;
                }
                O++;
            }
            /// <summary>
            /// Retrun CipherText
            /// </summary>
            return CipherText;
        }
    }
}
