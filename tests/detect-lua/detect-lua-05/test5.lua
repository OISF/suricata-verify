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
    local new_value = cnt:incr()

    print("value =", new_value)

    if new_value == 2 then
        print("match")
        return 1
    end

    return 0
end
