local filelib = require("suricata.file")
local config = require("suricata.config")
local results
local seen

function init(args)
   return { ["type"] = "file" }
end

function setup(args)
   results = assert(io.open(config.log_path() .. "/results.log", "w"))
   seen = {}
end

function log(args)
   local f = filelib.get_file()
   if f == nil then
      results:write("no-file\n")
      return
   end
   local ok, fid = pcall(function() return f:file_id() end)
   local name = tostring(f:name())
   if not ok then
      results:write(string.format("id-err %s name=%s\n", tostring(fid), name))
      return
   end
   -- the file log callback fires per file state change; record each
   -- (id, name) once
   local key = fid .. "/" .. name
   if seen[key] then
      return
   end
   seen[key] = true
   results:write(string.format("id=%d name=%s\n", fid, name))
end

function deinit()
   if results then
      results:close()
   end
end
