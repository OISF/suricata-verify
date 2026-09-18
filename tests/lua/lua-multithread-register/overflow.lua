local flowint = require("suricata.flowint")

function init(args)
    return {}
end

function match(args)
    for i = 1, 16 do
        -- the 16th call must fail cleanly
        flowint.register("ov_fi_" .. i)
    end
    return 1
end
