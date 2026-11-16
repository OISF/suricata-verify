local dataset = require "suricata.dataset"
local logger = require "suricata.log"

local dataset_ok = false

function init(args)
    local needs = {}
    needs["packet"] = tostring(true)
    return needs
end

function thread_init(args)
    local ds_obj = dataset.new()
    local ret, err = ds_obj:get("rfc1918-cidr")
    if err ~= nil then
        logger.warning("CIDR dataset get failed: " .. err)
        dataset_ok = false
        return 0
    end
    dataset_ok = true
end

-- Return 1 only when the CIDR dataset was successfully retrieved via get()
function match(args)
    if not dataset_ok then
        return 0
    end
    return 1
end
