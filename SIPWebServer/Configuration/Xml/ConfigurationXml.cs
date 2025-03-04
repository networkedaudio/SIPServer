using System.Xml;

namespace SIPServer.Configuration.Xml
{
    internal interface ConfigurationXml
    {
        internal abstract static void GenerateDefaults();
        internal abstract static XmlDocument GenerateXml(XmlDocument xmlDocument);
    }
}