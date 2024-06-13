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
    public class DES : CryptographicTechnique
    {

        private static readonly byte[] IP = utils.IP;

        readonly int[] FP = utils.FP;
        private static readonly byte[] NShiftBits = utils.NShiftBits;

        readonly int[] EP = utils.EP;

        private static readonly byte[] SBoxPermutation = utils.SBoxPermutation;
        private static readonly byte[] K1P = utils.K1P;

        private static readonly byte[] K2P = utils.K2P;
        private static readonly byte[,,] SBox = utils.SBox;



        public override string Decrypt(string cipherText, string key)
        {
            var BinaryPlain = utils.hex2binary(cipherText);
            var permutatedBinary = utils.Perm(BinaryPlain, IP);//do the initial permutation
            var leftPlain = permutatedBinary.Substring(0, 32);
            var rightPlain = permutatedBinary.Substring(32, 32);
            var BinaryKey = utils.hex2binary(key);
            var NewBinaryKey = utils.Perm(BinaryKey, K1P); //first key permutation

            var keys = utils.getKeys(NewBinaryKey);
            for (int nRound = 15; nRound >= 0; nRound--)
            {
                var expandedRight = utils.Perm(rightPlain, EP);//do the expansion permutation

                var temp = utils.XorString(keys[nRound], expandedRight);
                var sboxtemp = utils.Sbox(temp);
                var permutationTemp = utils.Perm(sboxtemp, SBoxPermutation);//do the expansion permutation

                leftPlain = utils.XorString(leftPlain, permutationTemp);

                utils.swap(ref leftPlain, ref rightPlain);
            }
            utils.swap(ref leftPlain, ref rightPlain);            //last swap
            cipherText = leftPlain + rightPlain;
            string result = utils.Perm(cipherText, FP);//second key permutation
            return utils.binary2hex(result);
        }

        public override string Encrypt(string plainText, string key)
        {
            var BinaryPlain = utils.hex2binary(plainText);
            var permutatedBinary = utils.Perm(BinaryPlain, IP);//do the initial permutation
            var leftPlain = permutatedBinary.Substring(0, 32);
            var rightPlain = permutatedBinary.Substring(32, 32);
            var BinaryKey = utils.hex2binary(key);
            var NewBinaryKey = utils.Perm(BinaryKey, K1P); //first key permutation

            var keys = utils.getKeys(NewBinaryKey);
            for (int nRound = 0; nRound < 16; nRound++)
            {
                var expandedRight = utils.Perm(rightPlain, EP);//do the expansion permutation

                var temp = utils.XorString(keys[nRound], expandedRight);
                var sboxtemp = utils.Sbox(temp);
                var permutationTemp = utils.Perm(sboxtemp, SBoxPermutation);//do the expansion permutation

                leftPlain = utils.XorString(leftPlain, permutationTemp);

                utils.swap(ref leftPlain, ref rightPlain);
            }

            utils.swap(ref leftPlain, ref rightPlain);            //last swap
            plainText = leftPlain + rightPlain;
            string result = utils.Perm(plainText, FP);//second key permutation

            return utils.binary2hex(result);
        }
    }
}
