using FreeSWITCH.Native;
using FreeSWITCH;
using SIPServer.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SIPServerEmbedded.Events;

namespace SIPServer.Events
{
    internal class Handler
    {
        internal static void SIPEventHandler(EventBinding.EventBindingArgs args)
        {
            var eventID = args.EventObj.event_id;

            if ((eventID == switch_event_types_t.SWITCH_EVENT_RE_SCHEDULE) || (eventID == switch_event_types_t.SWITCH_EVENT_HEARTBEAT) || (eventID == switch_event_types_t.SWITCH_EVENT_SESSION_HEARTBEAT))
            {
                return;
            }
            var eventDictionary = Converter.ToDictionary(args);

            switch (args.EventObj.event_id)
            {

                case switch_event_types_t.SWITCH_EVENT_RELOADXML:

                    break;


                case switch_event_types_t.SWITCH_EVENT_API:
                    {
                        if (eventDictionary.ContainsKey("API-Command") && eventDictionary.ContainsKey("API-Command-Argument"))
                        {
                            Serilog.Log.Debug($"API request => {eventDictionary["API-Command"]} {eventDictionary["API-Command-Argument"]}");
                        }

                    }
                    break;

                case switch_event_types_t.SWITCH_EVENT_MODULE_LOAD:
                case switch_event_types_t.SWITCH_EVENT_MODULE_UNLOAD:
                    {
                        if (eventDictionary.ContainsKey("name"))
                        {
                            Modules.ReportModifyModules(eventDictionary["name"], args.EventObj.event_id == switch_event_types_t.SWITCH_EVENT_MODULE_LOAD);
                        }

                    }
                    break;
            }
            // throw new NotImplementedException();
        }

       
    }
}
