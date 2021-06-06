local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local strbuf = require "strbuf"

description = [[
]]

---
--@output

author = "Frank Breedijk of Dutch Institute for Vulnerability Disclosure (DIVD.nl)"
last_update = "April 08, 2021"
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"default", "discovery", "safe"}

portrule = shortport.port_or_service( {80, 443, 5721}, {"http", "https"}, "tcp", "open")

local last_len = 0

function split(source, delimiters)
    local elements = {}
    local pattern = '([^'..delimiters..']+)'
    string.gsub(source, pattern, function(value) elements[#elements + 1] =     value;  end);
    return elements
end

-- Extract version information from body
local function extract_version_info(body)
  local version = ""
  local patchlevel = ""
  local customer_id = ""
  for line in body:gmatch("\"SystemVersion\":%s\"[%d+%.]+") do
    version = string.gsub(line,"[^%d%.]","")
  end
  for line in body:gmatch("\"PatchLevel\":%s\"[%d+%.]+") do
    patchlevel = string.gsub(line,"[^%d%.]","")
  end
  for line in body:gmatch("\"CustomerID\":%s\"[^\"]+") do
    customer_id = string.gsub(line,"\"CustomerID\":%s\"","")
  end
  return version,patchlevel,customer_id
end

action = function(host, port, redirects)
  local dis_count, noun

  options = {header={}}    
  options['header']['User-Agent'] = "Mozilla/5.0 (Kaseya vulnerability check)"
  local answer = http.get(host, port, "/api/v1.5/cw/environment", options )

  if answer.status == 301 or answer.status == 302 then
    return "Error " .. answer.status .. " : " .. table.concat(answer.location," -> ")
  elseif answer.status ~= 200 then
    return "Error: " .. tostring(answer["status-line"]) 
  end

  local v_level = nmap.verbosity() + (nmap.debugging()*2)
  local output = strbuf.new()
  local detail = 15

  version, patchlevel, customer_id = extract_version_info(answer.body)
  if (string.find(version,"^[%d%.]+$") and string.find(patchlevel,"^[%d%.]+$")) then
    port.version.name = "Kaseya VSA api v1.5"
    port.version.name_confidence = 8
    port.version.product = "Kaseya VSA"
    port.version.version = version
    port.version.extrainfo = "Patchlevel: " .. patchlevel .. ", CustomerID: " .. customer_id
    port.version.devicetype = "remote management"
    if answer.ssl then
      port.version.service_tunnel = "ssl"
    else
      port.version.service_tunnel = "none"
    end
    port.version.service_dtype = "probe"
    port.version.cpe = {"cpe:/a:kaseya:virtual_system_administrator:" .. version}
    nmap.set_port_version(host, port)
    return port.version.product .. " v" .. port.version.version .. ", " .. port.version.extrainfo
  end
  return 
end

