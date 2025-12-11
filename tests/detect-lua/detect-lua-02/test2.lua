local http = require("suricata.http")
local flowvarlib = require("suricata.flowvar")

local cnt_var  -- will hold the flowvar handle

function init(args)
    flowvarlib.register("cnt")
    local needs = {}
    needs["flowvar"] = { "cnt" }
    return needs
end

function thread_init(args)
    cnt_var = flowvarlib.get("cnt")
end

function match(args)
    local value_str = cnt_var:value()
    local value_num

    if value_str then
        value_num = tonumber(value_str) + 1
    else
        value_num = 1
    end

    local new_str = tostring(value_num)
    cnt_var:set(new_str, #new_str)

    print("pre check:", new_str)

    if value_num == 2 then
        print("match")
        return 1
    end

    return 0
end
