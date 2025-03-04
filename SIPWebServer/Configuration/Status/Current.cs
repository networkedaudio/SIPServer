using SIPServer.Configuration.Xml;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace SIPServer.Configuration.Status
{
    internal class Current
    {
        
        internal static void GenerateDefaults()
        {
            Acl.GenerateDefaults();
            Timezones.GenerateDefaults();
        }
    }
}
