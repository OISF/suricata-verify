local http = require("suricata.http")
local flowintlib = require("suricata.flowint")

function init(args)
    local needs = {}
    needs["flowint"] = { "cnt" }
    return needs
end

function match(args)
    print("inspecting")

    local cnt = flowintlib.get("cnt")
    local value = cnt:value()

    if value then
        cnt:set(value + 1)
    else
        cnt:set(1)
    end

    local new_value = cnt:value()

    if new_value == 2 then
        print("match")
        return 1
    end

    return 0
end

