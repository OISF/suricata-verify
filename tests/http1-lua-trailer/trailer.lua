-- Log the trailer fields of each HTTP transaction through the http tx interface.
local http = require "suricata.http"
local config = require "suricata.config"

name = "trailer_lua.log"

function init(args)
    local needs = {}
    needs["protocol"] = "http"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/" .. name, "a"))
end

-- table to "name=value" sorted by name, so the log is stable across runs
local function fields(t)
    if t == nil then
        return "<nil>"
    end
    local names = {}
    for k in pairs(t) do
        table.insert(names, k)
    end
    table.sort(names)
    local out = {}
    for _, n in ipairs(names) do
        table.insert(out, n .. "=" .. t[n])
    end
    return table.concat(out, " ")
end

local function raw(s)
    if s == nil then
        return "<nil>"
    end
    return (string.gsub(s, "%c", "."))
end

function log(args)
    local tx = http.get_tx()

    local v, err = tx:request_trailer("Checksum")
    if v == nil then
        v = "err:" .. err
    end

    file:write("req " .. fields(tx:request_trailers()) .. "\n")
    file:write("resp " .. fields(tx:response_trailers()) .. "\n")
    file:write("checksum " .. v .. "\n")
    file:write("miss ")
    local m, merr = tx:request_trailer("No-There")
    file:write((m == nil and "err:" .. merr or m) .. "\n")
    file:write("reqraw " .. raw(tx:request_trailers_raw()) .. "\n")
    file:write("respraw " .. raw(tx:response_trailers_raw()) .. "\n")
    file:flush()
end

function deinit(args)
    file:close()
end
