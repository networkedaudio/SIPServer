using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Serialization;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace SIPServer.Configuration.Xml
{
    internal class Conference : ConfigurationXml
    {
        internal static Dictionary<string, string> RoomsToAdvertise = new Dictionary<string, string>();
        internal static Dictionary<string, string> CallerControls = new Dictionary<string, string>();
        internal static Dictionary<string, ConferenceProfile> ConferenceProfiles = new Dictionary<string, ConferenceProfile>();
        
        public static void GenerateDefaults()
        {
            RoomsToAdvertise.Clear();
            RoomsToAdvertise.Add("3001@$${domain}", "SIPServer");

            CallerControls.Clear();

        }

        public static XmlDocument GenerateXml(XmlDocument xmlDocument)
        {
            throw new NotImplementedException();
        }

        internal class ConferenceCommands
        {
            [XmlElement(ElementName = "mute")]
            public Char Mute { get; set; } = '0';

            [XmlElement(ElementName = "deaf mute")]
            public Char DeafMute { get; set; } = '*';
            public Char EnergyUp { get; set; } = '9';
            public Char EnergyEqual { get; set; } = '8';

            public Char VolumeTalkUp { get; set; } = '3';

            public Char VolumeTalkZero { get; set; } = '2';

            public Char VolumeTalkDown { get; set; } = '1';


            public Char VolumeListenUp { get; set; } = '6';

            public Char VolumeListenZero { get; set; } = '5';

            public Char VolumeListenDown { get; set; } = '4';

            public Char Hangup { get; set; } = '#';

       
        }

        internal class ConferenceProfile
        {
            public ConferenceProfile() { }

            public string Name { get; set; }
            public string Domain { get; set; }
            public int Rate { get; set; }
            public int Interval { get; set; } = 20;
            public int EnergyLevel { get; set; } = 300;         
            public string SoundPrefix { get; set; } = "$${sounds_dir}/en/us/callie";
            public string MutedSound { get; set; } = "conference/conf-muted.wav";
            public string UnmutedSound { get; set; } = "conference/conf-unmuted.wav";
            public string AloneSound { get; set; } = "conference/conf-alone.wav";
            public string MOHSound { get; set; } = "$${hold_music}";
            public string EnterSound { get; set; } = "tone_stream://%(200,0,500,600,700)";
            public string ExitSound { get; set; } = "tone_stream://%(500,0,300,200,100,50,25)";
            public string KickedSound { get; set; } = "conference/conf-kicked.wav";
            public string LockedSound { get; set; } = "conference/conf-locked.wav";
            public string IsLockedSound { get; set; } = "conference/conf-is-locked.wav";
            public string IsUnLockedSound { get; set; } = "conference/conf-is-unlocked.wav";
            public string PinSound { get; set; } = "conference/conf-pin.wav";
            public string BadPinSound { get; set; } = "conference/conf-bad-pin.wav";
            public string CallerIDName { get; set; } = "$${outbound_caller_name}";
            public string CallerIDNumber { get; set; } = "$${outbound_caller_id}";
            public bool ComfortNoise { get; set; } = true;
            public string TTSEngine { get; set; } = "flite";
            public string TTSVoice { get; set; } = "kal16";
        }
    }
}
