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
    internal class Acl : ConfigurationXml
    {
        internal static List<Acl> AclList = new List<Acl>();
        public static void GenerateDefaults()
        {
            Acl acl = new Acl(Acl.AclPermission.allow);
            acl.ListName = "lan";

            Acl.AclNode aclNode1 = new Acl.AclNode(Acl.AclPermission.deny, IPAddress.Parse("192.168.42.0"), IPAddress.Parse("255.255.255.0"));
            Acl.AclNode aclNode2 = new Acl.AclNode(Acl.AclPermission.allow, IPAddress.Parse("192.168.42.42"), IPAddress.Parse("255.255.255.255"));

            acl.ListNodes.Add(aclNode1);
            acl.ListNodes.Add(aclNode2);

            AclList.Add(acl);
        }

        public static XmlDocument GenerateXml(XmlDocument returnDocument)
        {
            XmlNode rootNode = returnDocument.CreateElement("network-lists");
            returnDocument.ChildNodes[1].FirstChild.FirstChild.AppendChild(rootNode);


            foreach (var aclInfo in AclList)
            {
                XmlNode listNode = returnDocument.CreateElement("list");
                XmlAttribute nameAttribute = returnDocument.CreateAttribute("name");
                nameAttribute.Value = aclInfo.ListName;
                listNode.Attributes.Append(nameAttribute);
                XmlAttribute defaultAttribute = returnDocument.CreateAttribute("default");
                defaultAttribute.Value = aclInfo.ListDefault.ToString();
                listNode.Attributes.Append(defaultAttribute);
                rootNode.AppendChild(listNode);

                foreach(var aclNode in aclInfo.ListNodes)
                {
                    XmlNode aclListNode = returnDocument.CreateElement("node");
                    XmlAttribute typeAttribute = returnDocument.CreateAttribute("type");
                    typeAttribute.Value = aclNode.NodeType.ToString();
                    aclListNode.Attributes.Append(typeAttribute);
                    XmlAttribute cidrAttribute = returnDocument.CreateAttribute("cidr");
                    cidrAttribute.Value = aclNode.CIDR;
                    aclListNode.Attributes.Append(cidrAttribute);

                    listNode.AppendChild(aclListNode);
                }
            }

            return returnDocument;
        }

        internal string ListName { get; set; }
        internal AclPermission ListDefault {  get; set; }

        internal List<AclNode> ListNodes = new List<AclNode>();

        internal Acl(AclPermission permission)
        {
            ListDefault = permission;
        }

        internal enum AclPermission
        {
            allow,
            deny
        }

        internal class AclNode
        {
            internal AclNode(AclPermission nodeType, IPAddress ipAddress, IPAddress subnetAddress)
            {
                NodeType = nodeType;
                IPAddress = ipAddress;
                SubnetAddress = subnetAddress;
            }

            internal AclPermission NodeType {  get; set; }
            internal IPAddress IPAddress { get; set; }
            internal IPAddress SubnetAddress {  get; set; }

            public string CIDR { 
                get
                {
                    return IPAddress.ToString() + "/" + Providers.CIDR.MaskToCidr(SubnetAddress);
                }
            }

        }


    }
}
