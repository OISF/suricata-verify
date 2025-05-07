function init (args)
   return {
      protocol = "tls"
   }
end

function setup (args)
   file = assert(io.open(SCLogPath() .. "/lua.log", "w"))
end

local function tohex(str)
    local hex = {}
    for i = 1, #str do
        hex[i] = string.format("%02x", string.byte(str, i))
    end
    return table.concat(hex)
end

function log (args)
   write("SNI:" .. TlsGetSNI())
   write("NotBefore:" .. TlsGetCertNotBefore())
   write("NotAfter:" ..TlsGetCertNotAfter())
   write("Version:" ..TlsGetVersion())
   write("Serial:" .. TlsGetCertSerial())

   -- Chain is table.
   local chain = TlsGetCertChain()
   for i, cert in ipairs(chain) do
      write(i .. ":length:" .. cert.length)
      write(i .. ":data:" .. tohex(cert.data))
   end
end

function write(msg)
   file:write(msg .. "\n")
end

function deinit (args)
   file:close()
end

