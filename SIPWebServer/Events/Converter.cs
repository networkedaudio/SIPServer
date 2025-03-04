using FreeSWITCH;
using FreeSWITCH.Native;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static FreeSWITCH.EventBinding;

namespace SIPServerEmbedded.Events
{
    internal class Converter
    {
        public static Dictionary<string, string> ToDictionary(EventBindingArgs args)
        {

            Dictionary<string, string> returnDictionary = new Dictionary<string, string>();

            try
            {
                var firstHeader = args.EventObj.headers;
                while (true)
                {
                    if (!returnDictionary.ContainsKey(firstHeader.name))
                    {
                        returnDictionary.Add(firstHeader.name, firstHeader.value);
                        if (firstHeader.next != null)
                        {
                            firstHeader = firstHeader.next;
                        }
                        else
                        {
                            break;
                        }
                    }
                }
            } catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
            return returnDictionary;
        }

        public static Event ToEvent(string type, string subclass, string body, Dictionary<string, string> headers)
        {
            Event newEvent = new Event("CUSTOM", "SMS::SEND_MESSAGE");
            if (headers != null)
            {
                foreach (var entry in headers)
                {
                    newEvent.AddHeader(entry.Key, entry.Value);
                }
            }
            
            newEvent.AddBody(body);

            return newEvent;
        }

        public static Event ToEvent(string type, string subclass, string body)
        {
            return ToEvent(type, subclass, body, new Dictionary<string, string>());
        }
    }
}
