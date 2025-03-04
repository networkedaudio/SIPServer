using FreeSWITCH.Native;
using SIPServerEmbedded.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SIPServer.Logging
{
    internal class LogEngine
    {
        internal static void LogHandler(IntPtr nodePointer, switch_log_level_t level)
        {
            switch_log_node_t nodeReference = new switch_log_node_t(nodePointer, false);


            var time = Marshal.ReadInt64(nodeReference.timestamp.Ptr.Handle);

            DateTime unixEpochTime = DateTime.UnixEpoch.AddMicroseconds(time);


            Serilog.Log.Write(LogLevelConversion.ToSerilog(level),nodeReference.data);
            //  Console.WriteLine(unixEpochTime);

        }
    }
}
