-- luaxform: Convert IPv4 + hex/netmask to CIDR
-- Example: input="192.168.1.45", arg="0xffffff00" → "192.168.1.0/24"

-- Trim leading/trailing whitespace
local function trim(s)
    return s:match("^%s*(.-)%s*$")
end

-- Parse a mask string (hex format like 0xffffff00)
local function parse_mask(mask_hex)
    if not mask_hex then return nil end
    mask_hex = trim(mask_hex)
    -- Remove optional 0x/0X prefix
    local hex = mask_hex:match("^0[xX](%x+)$") or mask_hex
    local num = tonumber(hex, 16)
    return num
end

-- Count the number of 1 bits in a 32-bit number
local function count_bits(n)
    local count = 0
    for i = 0, 31 do
        if (n & (1 << i)) ~= 0 then count = count + 1 end
    end
    return count
end

-- Convert IPv4 string + mask to CIDR notation
local function ip_to_cidr2(ip_str, mask_hex)
    if not ip_str or not mask_hex then return nil end

    local mask = parse_mask(mask_hex)
    if not mask then return nil end

    local a, b, c, d = ip_str:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
    if not a then return nil end

    local ip = (tonumber(a) << 24) | (tonumber(b) << 16) | (tonumber(c) << 8) | tonumber(d)
    local net = ip & mask
    local bits = count_bits(mask)

    return string.format("%d.%d.%d.%d/%d",
        (net >> 24) & 0xFF,
        (net >> 16) & 0xFF,
        (net >> 8) & 0xFF,
        net & 0xFF,
        bits
    )
end

-- Convert a 4-byte host-order IPv4 address and a mask to CIDR
local function ip_to_cidr(ip_bytes, mask_hex)
    if not ip_bytes or #ip_bytes ~= 4 then return nil end

    -- Parse the mask
    local mask = parse_mask(mask_hex)
    if not mask then return nil end

    -- Convert host-order bytes to IP number
    local a, b, c, d = string.byte(ip_bytes, 1, 4)
    local ip = (a << 24) | (b << 16) | (c << 8) | d

    -- Compute network
    local net = ip & mask

    -- Count prefix length
    local bits = count_bits(mask)

    -- Convert back to dotted-decimal
    return string.format("%d.%d.%d.%d/%d",
        (net >> 24) & 0xFF,
        (net >> 16) & 0xFF,
        (net >> 8) & 0xFF,
        net & 0xFF,
        bits
    )
end

-- Transform an IPv4 address and a netmask into a CIDR
-- example: 1.2.3.4 0xffffff00 returns 1.2.3.0/24
function transform(input, args)
    if not input or not args or not args[1] then
        return nil, 0
    end

    local cidr = ip_to_cidr(input, args[1])
    if not cidr then return nil, 0 end

    return cidr, #cidr
end
