local filelib = require("suricata.file")
local logger = require("suricata.log")
local config = require("suricata.config")

-- Output test for SCFileInfo
file_name = "scfileinfo.log"

function init (args)
    return {type = "file"}
end

function setup(args)
    filename = config.log_path() .. "/" .. file_name
    output = assert(io.open(filename, "w"))
    logger.info("lua SCFileInfo Log Filename " .. filename)
end

function log(args)
    local file = filelib.get_file()

    local fileid = file:file_id()
    local txid = file:tx_id()
    local name = file:name()
    local size = file:size()
    local magic = file:magic()
    if magic == nil then
        magic = "nomagic"
    end
    local md5 = file:md5()
    local sha1 = file:sha1()
    local sha256 = file:sha256()

    output:write("** SCFileInfo is: [**] fileid: " .. fileid .. " [**] txid: " .. txid .. "\nname: " .. name .. "\nsize: " .. size .. " [**] magic: " .. magic .. "\nmd5: " .. md5 .. "\nsha1: " .. sha1 .. "\nsha256: " .. sha256 .. "\n")
    output:write("state: " .. file:get_state() .. "\n")
    output:write("is_stored: " .. tostring(file:is_stored()) .. "\n")
    output:flush()
end

function deinit(args)
    logger.info ("SCFileInfo logging finished");
    output:close()
end
