filename = "lua-stats.log"

function init (args)
    local needs = {}
    needs["type"] = "stats"
    return needs
end

function setup (args)
   file = assert(io.open(SCLogPath() .. "/" .. filename, "w"))
end

function log(args)
    for n, v in ipairs(args) do
        --print(n .. " - " .. v["name"] .. " == " .. v["value"]);
        if (v["name"] == "decoder.pkts") then
            msg = string.format("packets %u", v["value"]);
            write(msg)
        end
    end
end

function deinit(args)
   file:close(file)
end

function write(msg)
   file:write(msg .. "\n")
end
