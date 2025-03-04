using FreeSWITCH.Native;
using FreeSWITCH;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIPServer.Loaders
{
    internal class SIPEngine
    {
        internal static Api? SIPServerAPI;

        internal static IDisposable event_bind;

        internal static IDisposable log_bind;
        internal static void RunSipServer()
        {
            try
            {
                Configuration.Status.Current.GenerateDefaults();
                String err = "";
                const uint flags = (uint)(switch_core_flag_enum_t.SCF_VERBOSE_EVENTS | switch_core_flag_enum_t.SCF_USE_WIN32_MONOTONIC);
                freeswitch.switch_core_set_globals();
                /*Next 3 lines only needed if you want to bind to the initial event or xml config search loops */
                freeswitch.switch_core_init(flags, switch_bool_t.SWITCH_FALSE, out err);
                Serilog.Log.Information("Binding configuration");
                //var search_config_bind = SwitchXmlSearchBinding.Bind(Configuration.Xml.Generator.ConfigXmlProvider, switch_xml_section_enum_t.SWITCH_XML_SECTION_CONFIG);
                Serilog.Log.Information("Binding dialplan");
                //var search_dialplan_bind = SwitchXmlSearchBinding.Bind(Configuration.Xml.Generator.DialplanXmlProvider, switch_xml_section_enum_t.SWITCH_XML_SECTION_DIALPLAN);
                Serilog.Log.Information("Binding events");
                event_bind = EventBinding.Bind("SIPClient", switch_event_types_t.SWITCH_EVENT_ALL, null, Events.Handler.SIPEventHandler, true);
                
                log_bind = LogBinding.Bind(switch_log_level_t.SWITCH_LOG_DEBUG, switch_bool_t.SWITCH_TRUE, Logging.LogEngine.LogHandler);

                freeswitchPINVOKE.set_realtime_priority();

                /* End Optional Lines */
                freeswitch.switch_core_init_and_modload(flags, switch_bool_t.SWITCH_TRUE, out err);

                SIPServerAPI = new Api(null);

                
                freeswitch.switch_console_loop();
            }
            catch (Exception e)
            {
                Serilog.Log.Logger.Error(e.Message);
                //Console.WriteLine(e.ToString());
            }
        }
    }
}
