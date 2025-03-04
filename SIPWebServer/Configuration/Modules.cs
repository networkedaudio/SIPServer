using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIPServer.Configuration
{
    internal class Modules
    {
        internal static ConcurrentDictionary<string, bool> LoadedModules = new ConcurrentDictionary<string, bool>();
       // internal static ConcurrentDictionary<string, bool> RequestedModules = new () { { "mod_console", false }, { "mod_graylog2", false }, { "mod_logfile", false }, { "mod_syslog", false }, { "mod_yaml", false }, { "mod_enum", false }, { "mod_xml_rpc", false }, { "mod_xml_curl", false }, { "mod_xml_cdr", false }, { "mod_xml_radius", false }, { "mod_xml_scgi", false }, { "mod_amqp", false }, { "mod_cdr_csv", false }, { "mod_cdr_sqlite", false }, { "mod_event_multicast", false }, { "mod_event_socket", false }, { "mod_event_zmq", false }, { "mod_zeroconf", false }, { "mod_erlang_event", false }, { "mod_smpp", false }, { "mod_snmp", false }, { "mod_ldap", false }, { "mod_dingaling", false }, { "mod_portaudio", false }, { "mod_sofia", false }, { "mod_loopback", false }, { "mod_woomera", false }, { "mod_freetdm", false }, { "mod_unicall", false }, { "mod_skinny", false }, { "mod_khomp", false }, { "mod_rtc", false }, { "mod_rtmp", false }, { "mod_verto", false }, { "mod_signalwire", false }, { "mod_commands", false }, { "mod_conference", false }, { "mod_curl", false }, { "mod_db", false }, { "mod_dptools", false }, { "mod_expr", false }, { "mod_fifo", false }, { "mod_hash", false }, { "mod_mongo", false }, { "mod_voicemail", false }, { "mod_directory", false }, { "mod_distributor", false }, { "mod_lcr", false }, { "mod_easyroute", false }, { "mod_esf", false }, { "mod_fsv", false }, { "mod_valet_parking", false }, { "mod_fsk", false }, { "mod_spy", false }, { "mod_sms", false }, { "mod_sms_flowroute", false }, { "mod_smpp", false }, { "mod_random", false }, { "mod_httapi", false }, { "mod_translate", false }, { "mod_snom", false }, { "mod_dialplan_directory", false }, { "mod_dialplan_xml", false }, { "mod_dialplan_asterisk", false }, { "mod_spandsp", false }, { "mod_g723_1", false }, { "mod_g729", false }, { "mod_amr", false }, { "mod_ilbc", false }, { "mod_h26x", false }, { "mod_b64", false }, { "mod_siren", false }, { "mod_isac", false }, { "mod_opus", false }, { "mod_av", false }, { "mod_sndfile", false }, { "mod_native_file", false }, { "mod_opusfile", false }, { "mod_png", false }, { "mod_shout", false }, { "mod_local_stream", false }, { "mod_tone_stream", false }, { "mod_timerfd", false }, { "mod_v8", false }, { "mod_perl", false }, { "mod_python", false }, { "mod_python3", false }, { "mod_lua", false }, { "mod_flite", false }, { "mod_pocketsphinx", false }, { "mod_cepstral", false }, { "mod_tts_commandline", false }, { "mod_rss", false }, { "mod_say_en", false }, { "mod_say_ru", false }, { "mod_say_zh", false }, { "mod_say_sv", false } };

        internal static void ReportModifyModules(string module, bool loaded)
        {
            LoadedModules.AddOrUpdate(module, loaded, (key, oldValue) => loaded);

            if(loaded)
            {
                Serilog.Log.Information($"Loaded module => {module}");
            } 
            else
            {
                Serilog.Log.Information($"Unloaded module => {module}");
            }
        }

        internal static string LoadModule(string module)
        {
            if (LoadedModules.ContainsKey(module))
            {
                if (LoadedModules[module] == true)
                {
                    Serilog.Log.Error($"Already loaded {module}");
                    return $"Already loaded {module}";
                }
            }
            Serilog.Log.Error($"Unable to load {module}");
            return $"Unable to load {module}";
            
        }
    }
}
