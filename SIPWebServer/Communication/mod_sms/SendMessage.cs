using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIPServerEmbedded.Communication.mod_sms
{
    internal class Message
    {
        public string Subject { get; set; }
        public string Body { get; set; }
        public string From { get; set; }
        public string To { get; set; }


        public bool Send()
        {
            Dictionary<string, string> headers = new Dictionary<string, string>
            {
                { "proto", "sip" },
                { "dest_proto", "sip" },
                { "from", From },
                { "from_full", $"sip:{From}" },
                { "to", To },
                { "subject", To },
                { "type", "text/html" },
                { "hint", "Hint" },
                { "replying", "true" },
                { "sip_profile", "external" }
            };

            var newEvent = Events.Converter.ToEvent("CUSTOM", "SMS::SEND_MESSAGE", Body, headers);
            var result = newEvent.Fire();

            return false;
        }
    }
}
