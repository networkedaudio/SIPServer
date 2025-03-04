using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SIPServer.Configuration.Xml
{
    internal class Timezones : ConfigurationXml
    {
        internal static Dictionary<string, string> Timezone = new Dictionary<string, string>();
        public static void GenerateDefaults()
        {
            Timezone.Clear();

            foreach (TimeZoneInfo z in TimeZoneInfo.GetSystemTimeZones())
            {
                Timezone.Add(z.StandardName, "UTC" + z.GetUtcOffset(DateTime.Now).Hours);
            }
        }

        public static XmlDocument GenerateXml(XmlDocument returnDocument)
        {
            GenerateDefaults();

            XmlNode rootNode = returnDocument.CreateElement("timezones");
            returnDocument.ChildNodes[1].FirstChild.FirstChild.AppendChild(rootNode);

            foreach (var timeZoneInfo in Timezone)
            {
                XmlNode zoneNode = returnDocument.CreateElement("zone");
                XmlAttribute nameAttribute = returnDocument.CreateAttribute("name");
                nameAttribute.Value = timeZoneInfo.Key;
                zoneNode.Attributes.Append(nameAttribute);
                XmlAttribute valueAttribute = returnDocument.CreateAttribute("value");
                valueAttribute.Value = timeZoneInfo.Value.ToString();
                zoneNode.Attributes.Append(valueAttribute);
                rootNode.AppendChild(zoneNode);

            }

            return returnDocument;
        }
    }
}
