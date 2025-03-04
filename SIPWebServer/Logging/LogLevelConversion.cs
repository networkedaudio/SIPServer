using Serilog.Events;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Serilog.Events;
using FreeSWITCH.Native;

namespace SIPServerEmbedded.Logging
{
    internal class LogLevelConversion
    {
        public static LogEventLevel ToSerilog(switch_log_level_t level)
        {
            switch (level)
            {
                case switch_log_level_t.SWITCH_LOG_WARNING:
                case switch_log_level_t.SWITCH_LOG_ALERT:
                    return LogEventLevel.Warning;

                case switch_log_level_t.SWITCH_LOG_CONSOLE:
                    return LogEventLevel.Verbose;

                case switch_log_level_t.SWITCH_LOG_CRIT:
                    return LogEventLevel.Fatal;

                case switch_log_level_t.SWITCH_LOG_DEBUG:
                    return LogEventLevel.Debug;

                case switch_log_level_t.SWITCH_LOG_ERROR:
                    return LogEventLevel.Error;

                case switch_log_level_t.SWITCH_LOG_INFO:
                case switch_log_level_t.SWITCH_LOG_NOTICE:
                    return LogEventLevel.Information;


                default:
                    return LogEventLevel.Debug;
            }
        }
    }
}
