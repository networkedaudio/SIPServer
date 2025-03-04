using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace SIPServer.Configuration.Xml
{
    internal class Speex : ConfigurationXml
    {
        internal static Dictionary<string, string> SpeexProperties = new() { { "quality", "5" }, { "complexity", "5" }, {"enhancement", "true" }, {"vad", "false"},
            {"vbr", "false" }, {"vbr-quality", "4.0" }, {"abr", "0" }, {"dtx", "false" }, {"preproc", "false" }, {"pp-vad", "false" }, {"pp-agc", "false" }, {"pp-agc-level", "8000.0" },
            {"pp-denoise", "false"}, {"pp-dereverb", "false"} };
        public static void GenerateDefaults()
        {
        }

        public static XmlDocument GenerateXml(XmlDocument returnDocument)
        {
            XmlNode rootNode = returnDocument.CreateElement("settings");
            XmlAttribute nameAttribute = returnDocument.CreateAttribute("name");
            nameAttribute.Value = "default";
            rootNode.Attributes.Append(nameAttribute);
            returnDocument.ChildNodes[1].FirstChild.FirstChild.AppendChild(rootNode);

            foreach (var speexProperty in SpeexProperties)
            {
                XmlNode propertyNode = returnDocument.CreateElement("param");
                XmlAttribute propNameAttribute = returnDocument.CreateAttribute("name");
                propNameAttribute.Value = speexProperty.Key;
                propertyNode.Attributes.Append(propNameAttribute);
                XmlAttribute valueAttribute = returnDocument.CreateAttribute("value");
                valueAttribute.Value = speexProperty.Value.ToString();
                propertyNode.Attributes.Append(valueAttribute);
                rootNode.AppendChild(propertyNode);

            }

            return returnDocument;
        }
    }
}
