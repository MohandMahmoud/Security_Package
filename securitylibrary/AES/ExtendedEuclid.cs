using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.AES
{
    public class ExtendedEuclid 
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="number"></param>
        /// <param name="baseN"></param>
        /// <returns>Mul inverse, -1 if no inv</returns>
        public int GetMultiplicativeInverse(int number, int baseN)
        {
            int tempNumber = number, tempMod = baseN, b1 = 1, b2 = 0, quotient = 0, remainder =0, tempX = 0;
            
            while (tempMod != 0)
            {
                quotient = tempNumber / tempMod;
                remainder = tempNumber % tempMod;
                tempNumber = tempMod;
                tempMod = remainder;
                tempX = b2;
                b2 = b1 - quotient * b2;
                b1 = tempX;
            }
            if (tempNumber != 1)
            {
                return -1;
            }
            return (b1 % baseN + baseN) % baseN;
        }
    }
}
