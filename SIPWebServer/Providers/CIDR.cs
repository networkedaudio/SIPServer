using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SIPServer.Providers
{
    internal class CIDR
    {
        public static string CidrToMask(int cidr)
        {
            var mask = (cidr == 0) ? 0 : uint.MaxValue << (32 - cidr);
            var bytes = BitConverter.GetBytes(mask).Reverse().ToArray();
            return new IPAddress(bytes).ToString();
        }

        public static int MaskToCidr(IPAddress address)
        {
            var bytes = address.GetAddressBytes();
            var cidr = 0;
            foreach (var t in bytes)
            {
                var b = t;
                while (b > 0)
                {
                    cidr++;
                    b = (byte)(b << 1);
                }
            }
            return cidr;
        }
    }
}
