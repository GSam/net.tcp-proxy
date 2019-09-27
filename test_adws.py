import socket
from nettcp.stream.socket import SocketStream
from nettcp.stream.nmf import NMFStream

from samba.credentials import Credentials
from samba.param import LoadParm

import samba
import samba.getopt as options
import optparse
import sys

parser = optparse.OptionParser("test_adws.py [options] <host>")
sambaopts = options.SambaOptions(parser)
parser.add_option_group(sambaopts)
parser.add_option_group(options.VersionOptions(parser))

# use command line creds if available
credopts = options.CredentialsOptions(parser)
parser.add_option_group(credopts)
opts, args = parser.parse_args()

if len(args) < 1:
    parser.print_usage()
    sys.exit(1)

host = args[0]

lp = sambaopts.get_loadparm()
creds = credopts.get_credentials(lp)

realm = creds.get_realm()

if credopts.ipaddress:
    s = socket.create_connection((credopts.ipaddress, 9389))
else:
    s = socket.create_connection((host, 9389))

socket_stream = SocketStream(s)

fqdn = '{}.{}'.format(host, realm) if realm.lower() not in host.lower() else host

uri = 'net.tcp://{}:9389/ActiveDirectoryWebServices/Windows/Resource'.format(fqdn)

# GSSAPI
# stream = NMFStream(socket_stream, uri, 'HOST@HOST-A.REALM.COM')

# GENSEC
stream = NMFStream(socket_stream, uri, host, creds)
stream.preamble()

XML = u'''<s:Envelope
xmlns:s="http://www.w3.org/2003/05/soap-envelope"
xmlns:a="http://www.w3.org/2005/08/addressing"
xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
xmlns:da="http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
<ad:instance>ldap:389</ad:instance>
<ad:objectReferenceProperty>{dn}</ad:objectReferenceProperty>
<da:IdentityManagementOperation s:mustUnderstand="1"
xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
</da:IdentityManagementOperation>
<a:MessageID>urn:uuid:cae7b0c1-753f-418c-862b-7dca9e661d18</a:MessageID>
<a:ReplyTo>
<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
</a:ReplyTo>
<a:To s:mustUnderstand="1">{uri}</a:To>
</s:Header>
<s:Body>
<da:BaseObjectSearchRequest Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
<da:AttributeType>ad:distinguishedName</da:AttributeType>
<da:AttributeType>addata:name</da:AttributeType>
<da:AttributeType>addata:objectClass</da:AttributeType>
<da:AttributeType>addata:objectGUID</da:AttributeType>
<da:AttributeType>addata:extendedAttributeInfo</da:AttributeType>
<ad:controls>
<ad:control type="1.2.840.113556.1.4.319" criticality="true">
<ad:controlValue xsi:type="xsd:base64Binary">MIQAAAAFAgECBAA=</ad:controlValue>
</ad:control>
<ad:control type="1.2.840.113556.1.4.801" criticality="true">
<ad:controlValue xsi:type="xsd:base64Binary">MIQAAAADAgEH</ad:controlValue>
</ad:control>
</ad:controls>
</da:BaseObjectSearchRequest>
</s:Body>
</s:Envelope>
'''.format(uri=uri, dn='CN=Aggregate,CN=Schema,CN=Configuration,{}'.format("DC=" + realm.replace(".",",DC=")))

XML2 = u'''<s:Envelope
xmlns:s="http://www.w3.org/2003/05/soap-envelope"
xmlns:a="http://www.w3.org/2005/08/addressing"
xmlns:addata="http://schemas.microsoft.com/2008/1/ActiveDirectory/Data"
xmlns:ad="http://schemas.microsoft.com/2008/1/ActiveDirectory"
xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<s:Header>
<a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</a:Action>
<ad:instance>ldap:389</ad:instance>
<ad:objectReferenceProperty>11111111-1111-1111-1111-111111111111</ad:objectReferenceProperty>
<a:MessageID>urn:uuid:88e9ddee-aa50-4512-9727-b02553f6a559</a:MessageID>
<a:ReplyTo>
<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
</a:ReplyTo>
<a:To s:mustUnderstand="1">{uri}</a:To>
</s:Header>
<s:Body></s:Body>
</s:Envelope>'''.format(uri=uri)

from wcf.xml2records import XMLParser
from wcf.records import print_records, dump_records

from nettcp.protocol2xml import parse, build_dictionary

x = XMLParser.parse(XML)
print_records(x)
stream.write(b'\x00' + dump_records(x))
from nettcp.nmf import Record
payload = stream.read()
# print len(payload)
# with open('/tmp/ssssss' , 'wb') as f:
#     f.write(payload)

# r = Record.parse_stream(stream)

from wcf.records import Record as WCFRecord

from io import BytesIO, StringIO
fp = BytesIO(payload)
build_dictionary(fp, ('client', 'c>s'))
records = WCFRecord.parse(fp)
out = StringIO()
print_records(records, fp=out)
print(out.getvalue())

from adws import xmlutils

xmlhelper = xmlutils.XMLHelper(out.getvalue())

for x in xmlhelper.get_elem_list('.//s:Body/da:BaseObjectSearchResponse/da:PartialAttribute/addata:extendedAttributeInfo/ad:value', as_text=True):
    print(x)
