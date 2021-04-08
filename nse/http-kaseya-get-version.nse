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

local function checkversion(w)
  local output = w .. "\n"
  local mytable = split(w, ".")

  -- Completely out support releases

  if w:find("^6.5.*") ~= nil then
                output = "Exchange 2003 - AT RISK as out of support!"

  elseif w:find("^8.*") ~= nil then
                output = "Exchange 2007 - AT RISK as out of support!"

  -- Exchange 2010 RTM had 14.0 build numbers - these need uplifting to at least Service Pack 2

  -- Discontinued this section because the updates to 2010 are jsut because of defense in depth
  -- elseif w:find("^14.0.*") ~= nil then
  --          if tonumber(mytable[3]) < 727 then
  --           output = "Exchange 2010 VULNERABLE! to Unified Messaging issues! (< 14 RTM version installed, no Service Packs)"
  --          end

  elseif w:find("^14.*") ~= nil then
                -- Discontinued this section because the updates to 2010 are jsut because of defense in depth
                -- if tonumber(mytable[3]) < 496 then
                --         output = "Exchange 2010 VULNERABLE! to Unified Messaging issues! (< 14.*.496)"
                -- elseif 
                if tonumber(mytable[3]) == 496 then
                        output = "Exchange 2010 patch status cannot be determined from version number, check locally if latest security update is applied (= 14.*.496)"
                else
                        output = "Exchange 2010 PATCHED (>14.*.496)"
                end

  --Exchange 2013 - Patches available for CU23 (1497), CU22 (1473), CU21 (1395) and SP1 (847)

  elseif w:find("^15.0.*") ~= nil then
                minor = tonumber(mytable[3])
                if  minor == 1497 then
                        output = "Exchange 2013 CU23. Patch status cannot be determined from version number, check locally if patches are applied (= 15.0." .. minor .. ")"
                elseif minor == 1473 then
                        output = "Exchange 2013 CU22. Patch status cannot be determined from version number, check locally if patches are applied (= 15.0." .. minor .. ")"
                elseif minor == 1395 then
                        output = "Exchange 2013 CU21. Patch status cannot be determined from version number, check locally if patches are applied (= 15.0." .. minor .. ")"
                elseif minor - 847 then
                        output = "Exchange 2013 SP1. Patch status cannot be determined from version number, check locally if patches are applied (= 15.0." .. minor .. ")"
                elseif  minor > 1497 then
                        output = "Exchange 2013 after CU23. PATCHED (> 15.0.1497)"
                else
                        output = "Exchange 2013. Likely VULNERABLE! No security patches available on " .. last_update .. "(!~ 15.0.(1497|1473|1395|847) and < 15.0.1497)"
                end

  -- Exchange 2016 - Patches available for CU19 (2176), CU18 (2106), CU17 (2044), CU16 (1979), CU15 (1913), CU14 (1847), CU13 (1779), CU12 (1713), CU11 (1591), 
  --                                       CU10 (1531), CU9 (1466), CU8 (1415)

  elseif w:find("^15.1.*") ~= nil then
                minor = tonumber(mytable[3])
                if minor == 2176 then
                        output = "Exchange 2016 CU19. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 2106 then
                        output = "Exchange 2016 CU18. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 2044 then
                        output = "Exchange 2016 CU17. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1979 then
                        output = "Exchange 2016 CU16. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1913 then
                        output = "Exchange 2016 CU15. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1847 then
                        output = "Exchange 2016 CU14. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1779 then
                        output = "Exchange 2016 CU13. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1713 then
                        output = "Exchange 2016 CU12. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1591 then
                        output = "Exchange 2016 CU11. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1531 then
                        output = "Exchange 2016 CU10. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1466 then
                        output = "Exchange 2016 CU9. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor == 1415 then
                        output = "Exchange 2016 CU8. Patch status cannot be determined from version number, check locally if patches are applied (= 15.1." .. minor .. ")"
                elseif minor > 2176 then
                        output = "Exchange 2016 after CU19. PATCHED (> 15.1.2176)"
                else
                        output = "Exchange 2016 before CU8. VULNERABLE! No patches available on " .. last_update .. "(< 15.1.1415)"
                end

  -- Exchange 2019 - Patches available for CU8 (792), CU7 (721), CU6 (659), CU5 (595), CU4 (529), CU3 (464), CU2 (397), CU1 (221)

  elseif w:find("^15.2.*") ~= nil then
                minor = tonumber(mytable[3])
                if minor == 792 then
                        output = "Exchange 2019 CU8. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 721 then
                        output = "Exchange 2019 CU7. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 659 then
                        output = "Exchange 2019 CU6. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 595 then
                        output = "Exchange 2019 CU5. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 529 then
                        output = "Exchange 2019 CU4. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 464 then
                        output = "Exchange 2019 CU3. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 397 then
                        output = "Exchange 2019 CU2. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor == 221 then
                        output = "Exchange 2019 CU1. Patch status cannot be determined from version number, check locally if patches are applied (= 15.2." .. minor .. ")"
                elseif minor > 792 then
                        output = "Exchange 2019 after CU8, PATCHED (> 15.2.792)"
                else
                        output = "Exchange 2019 before CU1. VULNERABLE! No patches available on " .. last_update .. " (< 15.2.221)"
                end
  else
                output = "Exchange " .. w
  end
  return "(" .. w .. ") " .. output
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
