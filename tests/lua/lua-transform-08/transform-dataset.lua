local dataset = require("suricata.dataset")

function thread_init(args)
    dataset_new, err = dataset.new()
    if err ~= nil then
        SCLogWarning("dataset warning: " .. err)
        return 0
    end
    ret, err = dataset_new:get("versions-seen")
    if err ~= nil then
        SCLogWarning("dataset warning: " .. err)
        return 0
    end
end

function transform(input, args)
    ret, err = dataset_new:add(input, #input)
    if err ~= nil then
        SCLogWarning("lua warning: " .. err)
        return 0
    end
    if ret == 1 then
        SCLogNotice(input .. " => " .. ret)
    end
    return ret
end
