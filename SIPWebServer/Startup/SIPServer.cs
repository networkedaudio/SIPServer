using Serilog;
using Serilog.Sinks.SystemConsole.Themes;
using SIPServer.Loaders;

namespace SIPWebServer.Startup
{
    public class SIPServer
    {

        public static void Start()
        {
            Serilog.Log.Logger = new LoggerConfiguration()
                    .WriteTo.Console(theme: AnsiConsoleTheme.Sixteen)
                .CreateLogger();

            Serilog.Log.Logger.Information("Starting Engine");

            Task.Factory.StartNew(() => { SIPEngine.RunSipServer(); });
            while (true)
            {
                var newCommand = Console.ReadLine();
                ProcessCommand(newCommand, true);
            }
        }

        private static void ProcessCommand(string? newCommand, bool v)
        {
            throw new NotImplementedException();
        }
    }
}
