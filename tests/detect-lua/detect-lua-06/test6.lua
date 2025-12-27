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

    -- Initialize the counter to 2 if it doesn't exist
    if value == nil then
        print("new var set to 2")
        cnt:set(2)
    end

    -- Decrement the counter
    local new_value = cnt:value()
    cnt:set(new_value - 1)
    new_value = cnt:value()

    if new_value == 0 then
        print("match")
        return 1
    end

    return 0
end

