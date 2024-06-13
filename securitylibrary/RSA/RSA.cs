using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RSA
{
    public class RSA
    {
        public int Encrypt(int p, int q, int M, int e)
        {
            int rea = p * q;

            return (utils.Mod_Pow(M, e, rea));
        }

        public int Decrypt(int p, int q, int C, int e)
        {
            int res = (p - 1) * (q - 1);

            int d = utils.Multiplicative_Inverse(e, res);
            int n = p * q;

            return (utils.Mod_Pow(C, d, n));
        }
    }
}
