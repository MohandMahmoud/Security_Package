using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DiffieHellman
{
    public class DiffieHellman 
    {
        public List<int> GetKeys(int q, int alpha, int xa, int xb)
        {
            int ya = utils.Mod_Pow(alpha, xa, q);
            int yb = utils.Mod_Pow(alpha, xb, q);
            List<int> K = new List<int>();
            K.Add(utils.Mod_Pow(yb, xa, q));
            K.Add(utils.Mod_Pow(ya, xb, q));
            return K;
        }
    }
}
