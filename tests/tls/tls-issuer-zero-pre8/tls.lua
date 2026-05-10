function init(args)
    local needs = {}
    needs["tls"] = tostring(true)
    return needs
end

function match(args)
    version, subject, issuer, fingerprint = TlsGetCertInfo();
    if subject == issuer then
        return 1
    end
    return 0
end
