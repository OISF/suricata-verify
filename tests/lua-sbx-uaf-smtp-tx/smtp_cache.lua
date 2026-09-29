-- Caches the smtp tx handle of the first logged transaction and
-- touches it from the log call of a later transaction: by then the
-- parser has freed the first one. The accessors fail closed for a
-- stale handle: this read raises at the accessor check, the log()
-- call errors and the engine logs "tx no longer valid" - the
-- observable the test asserts on. The sandbox blocks pcall, so the
-- script cannot catch it. On base the read dereferences the freed
-- transaction and completes silently: nothing is logged.
local smtp = require('suricata.smtp')
local cached = nil
function init(args)
    local needs = {}
    needs['protocol'] = 'smtp'
    return needs
end
function setup(args) end
function log(args)
    local tx = smtp.get_tx()
    if tx == nil then return 0 end
    if cached == nil then
        cached = tx
        return 0
    end
    -- stale handle: this raises and the engine logs the error
    return cached:get_mail_from()
end
function deinit(args) return 0 end
