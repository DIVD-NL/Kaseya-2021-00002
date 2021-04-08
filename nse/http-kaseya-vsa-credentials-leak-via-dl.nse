local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"
local vulns = require "vulns"


description = [[
]]

---
--@output

author = "Frank Breedijk of Dutch Institute for Vulnerability Disclosure (DIVD.nl)"
last_update = "April 07, 2021"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe", "vuln"}

portrule = shortport.port_or_service( {80, 443, 5721}, {"http", "https"}, "tcp", "open")

local last_len = 0

function split(source, delimiters)
    local elements = {}
    local pattern = '([^'..delimiters..']+)'
    string.gsub(source, pattern, function(value) elements[#elements + 1] =     value;  end);
    return elements
end

-- Check if the returned page is a client download page
local function check_if_download_page(body)
  local found = false
  for line in body:gmatch("<title>Download Agent</title>") do
    if line == "<title>Download Agent</title>" then
      found = true
    end
  end
  return found
end

-- Check if the returned page is a redirect to client download API
local function check_if_redirect_to_download(answer)
  if ( answer.status == 301 or answer.status == 302 ) then
    if answer['location'][1] == "/api/v2.0/AssetManagement/asset/download-agent-package?packageid=-1" then
      return true
    else
      return false
    end
  else
    return false
  end
end

action = function(host, port, redirects)
  local dis_count, noun

  local vuln = {
    title = "Kaseya VSA credential leak via client download page",
    state = vulns.STATE.NOT_VULN,
    description = [[
Kaseya VS leaks agenta credentials if the agenta download page is openly accessible.
It is recommended that you restrict access to this page.
Vulnerability discovered by Wietse Boonstra of DIVD (https://www.divd.nl/team/Wietse%20Boonstra/)
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

  options = {header={}}    
  options['header']['User-Agent'] = "Mozilla/5.0 (Kaseya vulnerability check)"
  local answer = http.get(host, port, "/dl.asp", options )

  if answer.status == 301 or answer.status == 302 then
    return "Error " .. answer.status .. " : " .. table.concat(answer.location," -> ")
  elseif answer.status ~= 200 then
    return "Error: " .. tostring(answer["status-line"]) 
  end

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  if check_if_download_page(answer.body) then
    vuln.state = vulns.STATE.VULN
  else
    options['redirect_ok'] = false
    answer = http.get(host, port, "/mkDefault.asp?id=-1", options)
    if check_if_redirect_to_download(answer) then
      vuln.state = vulns.STATE.VULN
    end
  end
  return vuln_report:make_output(vuln)
end
