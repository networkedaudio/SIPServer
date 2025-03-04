using SIPServer.Loaders;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIPServerEmbedded.Communication
{
    internal class SIPServerCommands
    {
        internal static string SendCommand(string command)
        {
            Serilog.Log.Logger.Debug(command);
            var result = SIPEngine.SIPServerAPI.ExecuteString(command);
            Serilog.Log.Logger.Information(result);

            return result;
        }
    }
}
