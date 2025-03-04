using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

namespace SIPServer.Configuration.Xml
{
    internal class Msrp : ConfigurationXml
    {
        internal static bool UseMsrp = true;
        internal static string listen_ip = "$${local_ip_v4}";
        internal static int listen_port = 2855;
        internal static int listen_ssl_port = 2856;
        internal static int message_buffer_size =50; 
        internal static bool debugBool = false;
        internal static string secure_cert ="$${certs_dir}/wss.pem";
        internal static string secure_key = "$${certs_dir}/wss.pem";
        public static void GenerateDefaults()
        {
        }

        public static XmlDocument GenerateXml(XmlDocument returnDocument)
        {
            XmlNode rootNode = returnDocument.CreateElement("settings");
            returnDocument.ChildNodes[1].FirstChild.FirstChild.AppendChild(rootNode);

            if(UseMsrp)
            {
                XmlNode listenIP = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute1 = returnDocument.CreateAttribute("name");
                nameAttribute1.Value = "listen-ip";
                listenIP.Attributes.Append(nameAttribute1);

                XmlAttribute valueAttribute1 = returnDocument.CreateAttribute("value");
                valueAttribute1.Value = listen_ip;
                listenIP.Attributes.Append(valueAttribute1);

                rootNode.AppendChild(listenIP);

                XmlNode listenPort = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute2 = returnDocument.CreateAttribute("name");
                nameAttribute2.Value = "listen-port";
                listenPort.Attributes.Append(nameAttribute2);

                XmlAttribute valueAttribute2 = returnDocument.CreateAttribute("value");
                valueAttribute2.Value = listen_port.ToString();
                listenPort.Attributes.Append(valueAttribute2);

                rootNode.AppendChild(listenPort);

                XmlNode listenSslPort = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute3 = returnDocument.CreateAttribute("name");
                nameAttribute3.Value = "listen-ssl-port";
                listenSslPort.Attributes.Append(nameAttribute3);

                XmlAttribute valueAttribute3 = returnDocument.CreateAttribute("value");
                valueAttribute3.Value = listen_ssl_port.ToString();
                listenSslPort.Attributes.Append(valueAttribute3);

                rootNode.AppendChild(listenSslPort);

                XmlNode messageBuffer = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute4 = returnDocument.CreateAttribute("name");
                nameAttribute4.Value = "message-buffer-size";
                messageBuffer.Attributes.Append(nameAttribute4);

                XmlAttribute valueAttribute4 = returnDocument.CreateAttribute("value");
                valueAttribute4.Value = message_buffer_size.ToString();
                messageBuffer.Attributes.Append(valueAttribute4);

                rootNode.AppendChild(messageBuffer);


                XmlNode debug = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute5 = returnDocument.CreateAttribute("name");
                nameAttribute5.Value = "debug";
                debug.Attributes.Append(nameAttribute5);

                XmlAttribute valueAttribute5 = returnDocument.CreateAttribute("value");
                valueAttribute5.Value = debugBool.ToString();
                debug.Attributes.Append(valueAttribute5);

                rootNode.AppendChild(debug);

                XmlNode secureCert = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute6 = returnDocument.CreateAttribute("name");
                nameAttribute6.Value = "secure-cert";
                secureCert.Attributes.Append(nameAttribute6);

                XmlAttribute valueAttribute6 = returnDocument.CreateAttribute("value");
                valueAttribute6.Value = secure_cert.ToString();
                secureCert.Attributes.Append(valueAttribute6);

                rootNode.AppendChild(secureCert);

                XmlNode secureKey = returnDocument.CreateElement("param");
                XmlAttribute nameAttribute7 = returnDocument.CreateAttribute("name");
                nameAttribute7.Value = "secure-key";
                secureKey.Attributes.Append(nameAttribute7);

                XmlAttribute valueAttribute7 = returnDocument.CreateAttribute("value");
                valueAttribute7.Value = secure_key.ToString();
                secureKey.Attributes.Append(valueAttribute7);

                rootNode.AppendChild(secureKey);

            }

            return returnDocument;
        }

    }


}