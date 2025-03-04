using SIPServerEmbedded.Communication;

namespace SIPWebServer.Communication
{
    public class CommandProcessor
    {
        public static string ProcessCommandOnEngine(string newCommand)
        {


            if (!string.IsNullOrEmpty(newCommand))
            {
                return SIPServerCommands.SendCommand(newCommand);
            }

            return "";

        }

        public static string ProcessCommand(string newCommand)
        {
            if (!APICommands.Decode(newCommand))
            {

                return ProcessCommandOnEngine(newCommand);
            }

            return "";
        }

        public static string ProcessCommand(string newCommand, bool fromConsole)
        {
            string returnString = ProcessCommand(newCommand);
            Console.Write("MAS>");
            return returnString;

        }
    }
}
