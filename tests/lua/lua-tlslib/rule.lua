function init(args)
    return {}
end

function match(args)
    if TlsGetSNI() ~= "example.com" then
        return 0
    end

    if TlsGetCertNotBefore() ~= 1543363200 then
        return 0
    end

    if TlsGetCertNotAfter() ~= 1606910400 then
        return 0
    end

    if TlsGetVersion() ~= "TLS 1.2" then
        return 0
    end

    if TlsGetCertSerial() ~= "0F:D0:78:DD:48:F1:A2:BD:4D:0F:2B:A9:6B:60:38:FE" then
        return 0
    end

    return 1
end
