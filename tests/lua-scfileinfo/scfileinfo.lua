-- Output test for SCFileInfo
file_name = "scfileinfo.log"

function init (args)
    local needs = {}
    needs['type'] = 'file'
    return needs
end

function setup(args)
    filename = SCLogPath() .. "/" .. file_name
    file = assert(io.open(filename, "w"))
    SCLogInfo("lua SCFileInfo Log Filename " .. filename)
end

function log(args)
    fileid, txid, name, size, magic, md5, sha1, sha256 = SCFileInfo()
    if magic == nil then
        magic = "nomagic"
    end

    file:write ("** SCFileInfo is: [**] fileid: " .. fileid .. " [**] txid: " .. txid .. "\nname: " .. name .. "\nsize: " .. size .. " [**] magic: " .. magic .. "\nmd5: " .. md5 .. " \nsha1: " .. sha1 .. "\nsha256: " .. sha256 .. "\n\n")
    file:flush()
end

function deinit(args)
    SCLogInfo ("SCFileInfo logging finished");
    file:close(file)
end
