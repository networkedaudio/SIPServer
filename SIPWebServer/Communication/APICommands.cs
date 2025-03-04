using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SIPServerEmbedded.Communication
{
    public class APICommands
    {
        public static bool Decode(string newCommand)
        {
            if (!string.IsNullOrEmpty(newCommand.Trim()))
            {
                var array = newCommand.Split(' ');
                if(array.Length > 0 )
                {
                    switch (array[0].ToLower())
                    {
                        case "test":
                            mod_sms.Message message = new mod_sms.Message();
                            message.From = "1000@127.0.0.1";
                            message.To = "1000@127.0.0.1";
                            message.Subject = "Test message";
                            message.Body = "Never going to work";
                            message.Send();
                            return true;
                    }
                }
            }

            return false;
        }
    }
}
