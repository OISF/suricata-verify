local config = require("suricata.config")
local dataset = require("suricata.dataset")

local set = nil
local adds = 0
local failures = 0

function init(args)
    local needs = {}
    needs["protocol"] = "dns"
    return needs
end

function setup(args)
    file = assert(io.open(config.log_path() .. "/results.log", "w"))
end

function log(args)
    if set == nil then
        set = dataset.new()
        local ok, err = pcall(function()
            set:get("ds-reload")
        end)
        if not ok or err ~= nil then
            file:write("get failed: " .. tostring(err) .. "\n")
            set = nil
            return
        end
    end

    local value = "one.example.com"
    local ret, err = set:add(value, #value)
    if err == nil and ret ~= nil then
        adds = adds + 1
    else
        failures = failures + 1
        if failures == 1 then
            file:write("add failed: " .. tostring(err) .. "\n")
        end
    end
end

function deinit()
    file:write("adds=" .. adds .. " failures=" .. failures .. "\n")
    file:write("done\n")
    file:close()
end
