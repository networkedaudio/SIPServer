using FreeSWITCH;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace SIPServer.Configuration.Xml
{
    internal class Generator
    {
        internal static string ConfigXmlProvider(SwitchXmlSearchBinding.XmlBindingArgs args)
        {
            Serilog.Log.Logger.Debug("Configuration Provider: " + args.KeyName + " " + args.KeyValue);
            return CreateXml(args.Section, args.KeyValue, args.TagName);
        }

        internal static string DialplanXmlProvider(SwitchXmlSearchBinding.XmlBindingArgs args)
        {
            Serilog.Log.Logger.Debug("Dialplan Provider: " + args.KeyName + " " + args.KeyValue);
            return CreateXml(args.Section, args.KeyValue, args.TagName);
        }
        internal static string CreateXml(string section, string moduleName, string moduleDescription)
        {
            XmlDocument returnDocument = new XmlDocument();
            returnDocument.AppendChild(returnDocument.CreateXmlDeclaration("1.0", "UTF-8", "no"));

            XmlNode rootNode = returnDocument.CreateElement("document");
            var typeAttribute = returnDocument.CreateAttribute("type");
            typeAttribute.Value = "freeswitch/xml";
            rootNode.Attributes.Append(typeAttribute);
            returnDocument.AppendChild(rootNode);

            XmlNode sectionNode = returnDocument.CreateElement("section");
            var sectionNameAttribute = returnDocument.CreateAttribute("name");
            sectionNameAttribute.Value = "configuration";
            sectionNode.Attributes.Append(sectionNameAttribute);
            rootNode.AppendChild(sectionNode);

            XmlNode configurationNode = returnDocument.CreateElement("configuration");
            sectionNode.AppendChild(configurationNode);

            var nameAttribute = returnDocument.CreateAttribute("name");
            nameAttribute.Value = moduleName;

            var descriptionAttribute = returnDocument.CreateAttribute("description");
            descriptionAttribute.Value = moduleDescription;

            configurationNode.Attributes.Append(nameAttribute);
            configurationNode.Attributes.Append(descriptionAttribute);
            Serilog.Log.Debug("Asking for configuration for " + moduleName);
            switch (moduleName)
            {
                case "modules.conf":
                    returnDocument = Modules.GenerateXml(returnDocument); 
                    break;
                case "acl.conf":
                    returnDocument = Acl.GenerateXml(returnDocument);
                    break;
                case "msrp.conf":
                    returnDocument = Msrp.GenerateXml(returnDocument);
                    break;
                case "timezones.conf":
                    returnDocument = Timezones.GenerateXml(returnDocument);
                    break;
                case "speex.conf":
                    returnDocument = Speex.GenerateXml(returnDocument);
                    break;
            }
           
            return returnDocument.OuterXml;
        }

   
        
    }
}
