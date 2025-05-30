local dataset = require("suricata.dataset")
local logger = require("suricata.log")

function thread_init(args)
    dataset_new, err = dataset.new()
    if err ~= nil then
        logger.warning("dataset warning: " .. err)
        return 0
    end
    ret, err = dataset_new:get("versions-seen")
    if err ~= nil then
        logger.warning("dataset warning: " .. err)
        return 0
    end
end

function transform(input, args)
    ret, err = dataset_new:add(input, #input)
    if err ~= nil then
        logger.warning("lua warning: " .. err)
        return 0
    end
    if ret == 1 then
        logger.notice(input .. " => " .. ret)
    end
    return ret
end
