-- Keep the transaction handle obtained from the flow's first
-- transaction and, once the parser has moved on to a second
-- transaction, read it again. By then the parser has freed that
-- transaction. The accessors fail closed for a stale handle: the
-- accessor check raises, which aborts this script's run for the packet
-- (the sandbox blocks pcall, so the script cannot catch it) - the
-- engine logs the error, which is the observable the test asserts on.
local smtp = require("suricata.smtp")

cached = nil
cached_from = nil

function init (args)
    return { packet = true }
end

function match (args)
    local tx = smtp.get_tx()
    if tx == nil then
        return 0
    end
    local from = tx:get_mail_from()
    if from == nil then
        return 0
    end
    if cached == nil then
        -- the flow's first transaction: cache its handle
        cached = tx
        cached_from = from
        return 0
    end
    if from == cached_from then
        -- still the first transaction: nothing stale to assert
        return 0
    end

    -- a second transaction is current, so the first has been freed;
    -- this read raises, the run aborts and the engine logs
    -- "tx no longer valid"
    return cached:get_mail_from()
end
