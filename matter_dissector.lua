-- matter_dissector.lua
-- Wireshark Lua dissector for Matter protocol with AES-CCM decryption
-- Supports loading session keys from chip-tool logs via keylog file
--
-- Install: Copy to ~/.local/lib/wireshark/plugins/ (Linux)
--          or ~/Library/Application Support/Wireshark/plugins/ (macOS)
-- Configure: Edit > Preferences > Protocols > MATTER_DECRYPT > Key Log File

----------------------------------------
-- Bit operations compatibility
-- Supports: Lua 5.2 (bit32), LuaJIT (bit), Lua 5.4 (native operators)
----------------------------------------
local band, bor, bxor, lshift, rshift

if bit32 then
    band = bit32.band
    bor = bit32.bor
    bxor = bit32.bxor
    lshift = bit32.lshift
    rshift = bit32.rshift
elseif bit then
    band = bit.band
    bor = bit.bor
    bxor = bit.bxor
    lshift = bit.lshift
    rshift = bit.rshift
else
    band = load("return function(a,b) return a & b end")()
    bor = load("return function(a,b) return a | b end")()
    bxor = load("return function(a,b) return a ~ b end")()
    lshift = load("return function(a,b) return (a << b) & 0xFFFFFFFF end")()
    rshift = load("return function(a,b) return (a >> b) & 0xFFFFFFFF end")()
end

----------------------------------------
-- AES-128 Implementation (encrypt only, needed for CCM)
----------------------------------------
local SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
}

local RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 }

local function xtime(a)
    local r = lshift(a, 1)
    if band(a, 0x80) ~= 0 then
        r = bxor(r, 0x1b)
    end
    return band(r, 0xFF)
end

local function aes_key_expansion(key_bytes)
    local w = {}
    for i = 0, 3 do
        w[i] = {
            key_bytes[4*i + 1],
            key_bytes[4*i + 2],
            key_bytes[4*i + 3],
            key_bytes[4*i + 4],
        }
    end
    for i = 4, 43 do
        local t = { w[i-1][1], w[i-1][2], w[i-1][3], w[i-1][4] }
        if i % 4 == 0 then
            local rot = t[1]
            t[1] = SBOX[t[2] + 1]
            t[2] = SBOX[t[3] + 1]
            t[3] = SBOX[t[4] + 1]
            t[4] = SBOX[rot + 1]
            t[1] = bxor(t[1], RCON[i / 4])
        end
        w[i] = {
            bxor(w[i-4][1], t[1]),
            bxor(w[i-4][2], t[2]),
            bxor(w[i-4][3], t[3]),
            bxor(w[i-4][4], t[4]),
        }
    end
    return w
end

local function aes_encrypt_block(block, round_keys)
    -- State is column-major: state[col*4 + row + 1] (1-indexed)
    -- Input maps directly: state[i] = block[i]
    local s = {}
    for i = 1, 16 do s[i] = block[i] end

    -- AddRoundKey (round 0)
    for c = 0, 3 do
        local rk = round_keys[c]
        for r = 1, 4 do
            s[c*4 + r] = bxor(s[c*4 + r], rk[r])
        end
    end

    -- Rounds 1-9
    for round = 1, 9 do
        -- SubBytes
        for i = 1, 16 do s[i] = SBOX[s[i] + 1] end

        -- ShiftRows (row indices: row0={1,5,9,13}, row1={2,6,10,14}, etc.)
        local t2 = s[2]; s[2] = s[6]; s[6] = s[10]; s[10] = s[14]; s[14] = t2
        local t3 = s[3]; local t7 = s[7]; s[3] = s[11]; s[7] = s[15]; s[11] = t3; s[15] = t7
        local t16 = s[16]; s[16] = s[12]; s[12] = s[8]; s[8] = s[4]; s[4] = t16

        -- MixColumns
        for c = 0, 3 do
            local i = c * 4
            local s0, s1, s2, s3 = s[i+1], s[i+2], s[i+3], s[i+4]
            local x = bxor(s0, bxor(s1, bxor(s2, s3)))
            s[i+1] = bxor(s0, bxor(xtime(bxor(s0, s1)), x))
            s[i+2] = bxor(s1, bxor(xtime(bxor(s1, s2)), x))
            s[i+3] = bxor(s2, bxor(xtime(bxor(s2, s3)), x))
            s[i+4] = bxor(s3, bxor(xtime(bxor(s3, s0)), x))
        end

        -- AddRoundKey
        for c = 0, 3 do
            local rk = round_keys[round * 4 + c]
            for r = 1, 4 do
                s[c*4 + r] = bxor(s[c*4 + r], rk[r])
            end
        end
    end

    -- Final round (no MixColumns)
    for i = 1, 16 do s[i] = SBOX[s[i] + 1] end

    local t2 = s[2]; s[2] = s[6]; s[6] = s[10]; s[10] = s[14]; s[14] = t2
    local t3 = s[3]; local t7 = s[7]; s[3] = s[11]; s[7] = s[15]; s[11] = t3; s[15] = t7
    local t16 = s[16]; s[16] = s[12]; s[12] = s[8]; s[8] = s[4]; s[4] = t16

    for c = 0, 3 do
        local rk = round_keys[40 + c]
        for r = 1, 4 do
            s[c*4 + r] = bxor(s[c*4 + r], rk[r])
        end
    end

    return s
end

----------------------------------------
-- AES-CCM Decryption
-- nonce: 13 bytes, tag_len: 16 bytes (Matter standard)
----------------------------------------
local function str_to_bytes(s)
    local t = {}
    for i = 1, #s do t[i] = s:byte(i) end
    return t
end

local function bytes_to_str(t)
    local chars = {}
    for i = 1, #t do chars[i] = string.char(t[i]) end
    return table.concat(chars)
end

local function xor_blocks(a, b, len)
    local r = {}
    for i = 1, len do r[i] = bxor(a[i] or 0, b[i] or 0) end
    return r
end

local function pad_block(data, offset, len)
    local block = {}
    for i = 1, 16 do
        if offset + i - 1 <= len then
            block[i] = data[offset + i - 1]
        else
            block[i] = 0
        end
    end
    return block
end

local function aes_ccm_decrypt(key_bytes, nonce_bytes, aad_bytes, ct_with_tag)
    local tag_len = 16
    if #ct_with_tag <= tag_len then return nil end

    local ct_len = #ct_with_tag - tag_len
    local ct = {}
    for i = 1, ct_len do ct[i] = ct_with_tag[i] end
    local recv_tag = {}
    for i = 1, tag_len do recv_tag[i] = ct_with_tag[ct_len + i] end

    local rk = aes_key_expansion(key_bytes)

    -- q = 2 (nonce is 13 bytes, L = 15-13 = 2)
    -- Counter block A_i: flags(1) | nonce(13) | counter(2, big-endian)
    -- flags for counter = L-1 = 1
    local function make_ctr_block(counter)
        local b = {0x01}
        for i = 1, 13 do b[i + 1] = nonce_bytes[i] end
        b[15] = band(rshift(counter, 8), 0xFF)
        b[16] = band(counter, 0xFF)
        return b
    end

    -- S_0 for tag encryption
    local s0 = aes_encrypt_block(make_ctr_block(0), rk)

    -- CTR decrypt ciphertext
    local plaintext = {}
    local block_count = math.ceil(ct_len / 16)
    for blk = 0, block_count - 1 do
        local s_i = aes_encrypt_block(make_ctr_block(blk + 1), rk)
        for j = 1, 16 do
            local idx = blk * 16 + j
            if idx <= ct_len then
                plaintext[idx] = bxor(ct[idx], s_i[j])
            end
        end
    end

    -- CBC-MAC to verify
    -- B_0: flags(1) | nonce(13) | payload_len(2, big-endian)
    -- flags: bit6=Adata, bits[5:3]=(t-2)/2=7, bits[2:0]=q-1=1
    local b0_flags = 0x79
    if #aad_bytes == 0 then b0_flags = bxor(b0_flags, 0x40) end
    local b0 = {b0_flags}
    for i = 1, 13 do b0[i + 1] = nonce_bytes[i] end
    b0[15] = band(rshift(ct_len, 8), 0xFF)
    b0[16] = band(ct_len, 0xFF)

    -- X_1 = AES(K, B_0)
    local x = aes_encrypt_block(b0, rk)

    -- Process AAD
    if #aad_bytes > 0 then
        local aad_encoded = {}
        local aad_len = #aad_bytes
        if aad_len < 65280 then
            aad_encoded[1] = band(rshift(aad_len, 8), 0xFF)
            aad_encoded[2] = band(aad_len, 0xFF)
            for i = 1, aad_len do aad_encoded[i + 2] = aad_bytes[i] end
        end
        local total_aad = #aad_encoded
        local aad_blocks = math.ceil(total_aad / 16)
        for blk = 0, aad_blocks - 1 do
            local b = pad_block(aad_encoded, blk * 16 + 1, total_aad)
            x = aes_encrypt_block(xor_blocks(x, b, 16), rk)
        end
    end

    -- Process plaintext
    local pt_blocks = math.ceil(#plaintext / 16)
    if pt_blocks == 0 and #plaintext > 0 then pt_blocks = 1 end
    for blk = 0, pt_blocks - 1 do
        local b = pad_block(plaintext, blk * 16 + 1, #plaintext)
        x = aes_encrypt_block(xor_blocks(x, b, 16), rk)
    end

    -- T = CBC-MAC result, encrypted with S_0
    local computed_tag = xor_blocks(x, s0, tag_len)

    -- Verify tag
    local tag_ok = true
    for i = 1, tag_len do
        if computed_tag[i] ~= recv_tag[i] then
            tag_ok = false
            break
        end
    end

    if not tag_ok then return nil end
    return plaintext
end

----------------------------------------
-- Matter Protocol Constants
----------------------------------------
local PROTOCOL_IDS = {
    [0x0000] = "Secure Channel",
    [0x0001] = "Interaction Model",
    [0x0002] = "BDX",
    [0x0003] = "User Directed Commissioning",
}

local SC_OPCODES = {
    [0x10] = "StandaloneAck",
    [0x20] = "PBKDFParamRequest",
    [0x21] = "PBKDFParamResponse",
    [0x22] = "PASE_Pake1",
    [0x23] = "PASE_Pake2",
    [0x24] = "PASE_Pake3",
    [0x30] = "CASE_Sigma1",
    [0x31] = "CASE_Sigma2",
    [0x32] = "CASE_Sigma3",
    [0x33] = "CASE_Sigma2Resume",
    [0x40] = "StatusReport",
}

local IM_OPCODES = {
    [0x01] = "StatusResponse",
    [0x02] = "ReadRequest",
    [0x03] = "SubscribeRequest",
    [0x04] = "SubscribeResponse",
    [0x05] = "ReportData",
    [0x06] = "WriteRequest",
    [0x07] = "WriteResponse",
    [0x08] = "InvokeRequest",
    [0x09] = "InvokeResponse",
    [0x0A] = "TimedRequest",
}

local DSIZ_NAMES = {
    [0] = "None",
    [1] = "Node ID (64-bit)",
    [2] = "Group ID (16-bit)",
    [3] = "Reserved",
}

local SESSION_TYPE_NAMES = {
    [0] = "Unicast",
    [1] = "Group",
}

local TLV_TYPES = {
    [0x00] = "Int8",    [0x01] = "Int16",   [0x02] = "Int32",   [0x03] = "Int64",
    [0x04] = "UInt8",   [0x05] = "UInt16",  [0x06] = "UInt32",  [0x07] = "UInt64",
    [0x08] = "False",   [0x09] = "True",
    [0x0A] = "Float32", [0x0B] = "Float64",
    [0x0C] = "UTF8-1",  [0x0D] = "UTF8-2",  [0x0E] = "UTF8-4",  [0x0F] = "UTF8-8",
    [0x10] = "Bytes-1", [0x11] = "Bytes-2", [0x12] = "Bytes-4", [0x13] = "Bytes-8",
    [0x14] = "Null",
    [0x15] = "Structure", [0x16] = "Array", [0x17] = "List",
    [0x18] = "EndOfContainer",
}

----------------------------------------
-- Key Management
----------------------------------------
local session_keys = {}  -- { {i2r={bytes}, r2i={bytes}, src_node=number}, ... }
local keylog_path_cache = ""

local function hex_to_bytes(hex)
    local bytes = {}
    for i = 1, #hex, 2 do
        bytes[#bytes + 1] = tonumber(hex:sub(i, i+1), 16)
    end
    return bytes
end

local function bytes_to_hex(bytes)
    local hex = {}
    for i = 1, #bytes do
        hex[i] = string.format("%02x", bytes[i])
    end
    return table.concat(hex)
end

-- Keylog format:
--   SESSION_ID  I2R_KEY  R2I_KEY  I2R_SRC_NODE  R2I_SRC_NODE
-- Source node IDs are the sender's operational node ID used in the nonce.
-- I2R_SRC_NODE = initiator's node ID (sender of I2R-encrypted messages)
-- R2I_SRC_NODE = responder's node ID (sender of R2I-encrypted messages)
-- Use hex (0x...) or decimal. Omit or use 0 to try without node ID.

local function parse_node_id(s)
    -- Parse node ID (decimal or 0x hex), returns 8-byte LE table
    local n
    if s and s:sub(1, 2) == "0x" then
        n = tonumber(s:sub(3), 16) or 0
    else
        n = tonumber(s) or 0
    end
    local bytes = {}
    for i = 1, 8 do
        bytes[i] = band(n, 0xFF)
        n = rshift(n, 8)
    end
    return bytes
end

local function load_keylog(path)
    if path == keylog_path_cache and #session_keys > 0 then return end
    session_keys = {}
    if not path or path == "" then return end

    local f = io.open(path, "r")
    if not f then return end

    for line in f:lines() do
        line = line:match("^%s*(.-)%s*$")
        if line ~= "" and line:sub(1, 1) ~= "#" then
            local parts = {}
            for part in line:gmatch("%S+") do
                parts[#parts + 1] = part
            end
            if #parts >= 3 then
                local i2r = hex_to_bytes(parts[2])
                local r2i = hex_to_bytes(parts[3])
                local i2r_src = parse_node_id(parts[4] or "0")
                local r2i_src = parse_node_id(parts[5] or "0")
                if #i2r == 16 and #r2i == 16 then
                    session_keys[#session_keys + 1] = {
                        i2r = i2r, r2i = r2i,
                        i2r_src = i2r_src, r2i_src = r2i_src,
                    }
                end
            end
        end
    end
    f:close()
    keylog_path_cache = path
end

----------------------------------------
-- TLV Decoder (returns human-readable string)
----------------------------------------
local function decode_tlv(data, max_depth)
    max_depth = max_depth or 10
    local pos = 1
    local lines = {}
    local indent = 0

    local function read_uint(size)
        if pos + size - 1 > #data then return nil end
        local val = 0
        for i = 0, size - 1 do
            val = val + lshift(data[pos + i], i * 8)
        end
        pos = pos + size
        return val
    end

    local function read_int(size)
        local val = read_uint(size)
        if not val then return nil end
        local max_pos = lshift(1, size * 8 - 1)
        if val >= max_pos then
            val = val - lshift(1, size * 8)
        end
        return val
    end

    local function read_bytes_raw(size)
        if pos + size - 1 > #data then return nil end
        local b = {}
        for i = 1, size do b[i] = data[pos + i - 1] end
        pos = pos + size
        return b
    end

    local safety = 0
    while pos <= #data and safety < 500 do
        safety = safety + 1
        local ctrl = data[pos]
        pos = pos + 1
        local tag_ctrl = band(rshift(ctrl, 5), 0x07)
        local elem_type = band(ctrl, 0x1F)

        -- Read tag
        local tag_str = ""
        if tag_ctrl == 0 then
            tag_str = ""
        elseif tag_ctrl == 1 then
            local t = read_uint(1)
            if not t then break end
            tag_str = string.format("Tag=%d ", t)
        elseif tag_ctrl == 2 or tag_ctrl == 4 then
            local t = read_uint(2)
            if not t then break end
            tag_str = string.format("Tag=0x%04x ", t)
        elseif tag_ctrl == 3 or tag_ctrl == 5 then
            local t = read_uint(4)
            if not t then break end
            tag_str = string.format("Tag=0x%08x ", t)
        elseif tag_ctrl == 6 then
            local v = read_uint(2); local p = read_uint(2); local t = read_uint(2)
            if not t then break end
            tag_str = string.format("Tag=%d:%d:%d ", v, p, t)
        elseif tag_ctrl == 7 then
            local v = read_uint(2); local p = read_uint(2); local t = read_uint(4)
            if not t then break end
            tag_str = string.format("Tag=%d:%d:%d ", v, p, t)
        end

        local prefix = string.rep("  ", indent)

        if elem_type == 0x15 then
            lines[#lines + 1] = prefix .. tag_str .. "{"
            indent = math.min(indent + 1, max_depth)
        elseif elem_type == 0x16 then
            lines[#lines + 1] = prefix .. tag_str .. "["
            indent = math.min(indent + 1, max_depth)
        elseif elem_type == 0x17 then
            lines[#lines + 1] = prefix .. tag_str .. "List("
            indent = math.min(indent + 1, max_depth)
        elseif elem_type == 0x18 then
            indent = math.max(0, indent - 1)
            prefix = string.rep("  ", indent)
            lines[#lines + 1] = prefix .. "}"
        elseif elem_type >= 0x00 and elem_type <= 0x03 then
            local size = lshift(1, elem_type)
            local val = read_int(size)
            if not val then break end
            lines[#lines + 1] = prefix .. tag_str .. tostring(val)
        elseif elem_type >= 0x04 and elem_type <= 0x07 then
            local size = lshift(1, elem_type - 0x04)
            local val = read_uint(size)
            if not val then break end
            if size <= 2 then
                lines[#lines + 1] = prefix .. tag_str .. string.format("0x%x (%d)", val, val)
            else
                lines[#lines + 1] = prefix .. tag_str .. string.format("0x%x", val)
            end
        elseif elem_type == 0x08 then
            lines[#lines + 1] = prefix .. tag_str .. "false"
        elseif elem_type == 0x09 then
            lines[#lines + 1] = prefix .. tag_str .. "true"
        elseif elem_type == 0x0A then
            pos = pos + 4
            lines[#lines + 1] = prefix .. tag_str .. "float32"
        elseif elem_type == 0x0B then
            pos = pos + 8
            lines[#lines + 1] = prefix .. tag_str .. "float64"
        elseif elem_type >= 0x0C and elem_type <= 0x0F then
            local len_size = lshift(1, elem_type - 0x0C)
            local slen = read_uint(len_size)
            if not slen or pos + slen - 1 > #data then break end
            local chars = {}
            for i = 1, math.min(slen, 64) do
                chars[i] = string.char(data[pos + i - 1])
            end
            pos = pos + slen
            local str_val = table.concat(chars)
            if slen > 64 then str_val = str_val .. "..." end
            lines[#lines + 1] = prefix .. tag_str .. '"' .. str_val .. '"'
        elseif elem_type >= 0x10 and elem_type <= 0x13 then
            local len_size = lshift(1, elem_type - 0x10)
            local blen = read_uint(len_size)
            if not blen or pos + blen - 1 > #data then break end
            local b = read_bytes_raw(blen)
            if not b then break end
            local hex_str = bytes_to_hex(b)
            if #hex_str > 64 then hex_str = hex_str:sub(1, 64) .. "..." end
            lines[#lines + 1] = prefix .. tag_str .. "h'" .. hex_str .. "'"
        elseif elem_type == 0x14 then
            lines[#lines + 1] = prefix .. tag_str .. "null"
        else
            lines[#lines + 1] = prefix .. "Unknown(0x" .. string.format("%02x", elem_type) .. ")"
            break
        end
    end
    return table.concat(lines, "\n")
end

----------------------------------------
-- Decryption result cache (per packet number)
----------------------------------------
local decrypt_cache = {}

----------------------------------------
-- Wireshark Protocol Definition
----------------------------------------
local matter_proto = Proto("matter_decrypt", "Matter Protocol")

local pf_msg_flags     = ProtoField.uint8("matterd.msg_flags", "Message Flags", base.HEX)
local pf_version       = ProtoField.uint8("matterd.version", "Version", base.DEC, nil, 0xF0)
local pf_s_flag        = ProtoField.bool("matterd.s_flag", "Source Node ID Present", 8, nil, 0x04)
local pf_dsiz          = ProtoField.uint8("matterd.dsiz", "DSIZ", base.DEC, DSIZ_NAMES, 0x03)
local pf_session_id    = ProtoField.uint16("matterd.session_id", "Session ID", base.HEX)
local pf_sec_flags     = ProtoField.uint8("matterd.security_flags", "Security Flags", base.HEX)
local pf_privacy       = ProtoField.bool("matterd.privacy", "Privacy", 8, nil, 0x01)
local pf_control       = ProtoField.bool("matterd.control", "Control", 8, nil, 0x02)
local pf_sess_type     = ProtoField.uint8("matterd.session_type", "Session Type", base.DEC, SESSION_TYPE_NAMES, 0x03)
local pf_msg_counter   = ProtoField.uint32("matterd.msg_counter", "Message Counter", base.DEC)
local pf_src_node      = ProtoField.uint64("matterd.src_node", "Source Node ID", base.HEX)
local pf_dst_node      = ProtoField.uint64("matterd.dst_node", "Destination Node ID", base.HEX)
local pf_dst_group     = ProtoField.uint16("matterd.dst_group", "Destination Group ID", base.HEX)

local pf_encrypted     = ProtoField.bytes("matterd.encrypted", "Encrypted Payload")
local pf_mic           = ProtoField.bytes("matterd.mic", "MIC Tag")

matter_proto.fields = {
    pf_msg_flags, pf_version, pf_s_flag, pf_dsiz,
    pf_session_id, pf_sec_flags, pf_privacy, pf_control, pf_sess_type,
    pf_msg_counter, pf_src_node, pf_dst_node, pf_dst_group,
    pf_encrypted, pf_mic,
}

local keylog_pref = Pref.string("keylog_file", "", "Path to Matter session key log file")
matter_proto.prefs.keylog_file = keylog_pref

----------------------------------------
-- Protocol Header Parser
----------------------------------------
local function parse_protocol_header(data, offset, tree)
    if offset + 6 > #data then return nil end

    local exchange_flags = data[offset]
    local opcode = data[offset + 1]
    local exchange_id = data[offset + 2] + lshift(data[offset + 3], 8)
    local protocol_id_raw = data[offset + 4] + lshift(data[offset + 5], 8)
    local vendor_id = nil
    local next_offset = offset + 6

    -- Check V flag (vendor ID present) in exchange flags bit 4
    if band(exchange_flags, 0x10) ~= 0 then
        if next_offset + 2 > #data then return nil end
        vendor_id = protocol_id_raw
        protocol_id_raw = data[next_offset] + lshift(data[next_offset + 1], 8)
        next_offset = next_offset + 2
    end

    -- Check A flag (ack counter present) in exchange flags bit 1
    local ack_counter = nil
    if band(exchange_flags, 0x02) ~= 0 then
        if next_offset + 4 > #data then return nil end
        ack_counter = data[next_offset] + lshift(data[next_offset + 1], 8)
            + lshift(data[next_offset + 2], 16) + lshift(data[next_offset + 3], 24)
        next_offset = next_offset + 4
    end

    -- Determine opcode name
    local proto_name = PROTOCOL_IDS[protocol_id_raw] or string.format("0x%04x", protocol_id_raw)
    local opcode_name
    if protocol_id_raw == 0x0000 then
        opcode_name = SC_OPCODES[opcode]
    elseif protocol_id_raw == 0x0001 then
        opcode_name = IM_OPCODES[opcode]
    end
    opcode_name = opcode_name or string.format("0x%02x", opcode)

    -- Add to tree as text items (no tvb backing for decrypted data)
    local lines = {
        string.format("Exchange Flags: 0x%02x (I:%d A:%d R:%d S:%d V:%d)",
            exchange_flags,
            band(exchange_flags, 0x01),
            band(rshift(exchange_flags, 1), 1),
            band(rshift(exchange_flags, 2), 1),
            band(rshift(exchange_flags, 3), 1),
            band(rshift(exchange_flags, 4), 1)),
        string.format("Protocol Opcode: 0x%02x (%s)", opcode, opcode_name),
        string.format("Exchange ID: 0x%04x", exchange_id),
    }
    if vendor_id then
        lines[#lines + 1] = string.format("Protocol Vendor ID: 0x%04x", vendor_id)
    end
    lines[#lines + 1] = string.format("Protocol ID: 0x%04x (%s)", protocol_id_raw, proto_name)
    if ack_counter then
        lines[#lines + 1] = string.format("Acknowledged Counter: %d", ack_counter)
    end

    tree:append_text(string.format(" [%s: %s]", proto_name, opcode_name))
    local ph_text = "Protocol Header: " .. proto_name .. " " .. opcode_name .. "\n    " .. table.concat(lines, "\n    ")
    tree:add(ph_text)

    return next_offset, proto_name, opcode_name
end

----------------------------------------
-- Main Dissector Function
----------------------------------------
function matter_proto.dissector(tvb, pinfo, tree)
    local length = tvb:len()
    if length < 8 then return 0 end

    -- Load keys from preferences
    load_keylog(matter_proto.prefs.keylog_file)

    pinfo.cols.protocol = "Matter"

    local subtree = tree:add(matter_proto, tvb(), "Matter Protocol")

    -- Parse Message Header
    local offset = 0

    -- Message Flags
    local msg_flags = tvb(offset, 1):uint()
    local flags_tree = subtree:add(pf_msg_flags, tvb(offset, 1))
    flags_tree:add(pf_version, tvb(offset, 1))
    flags_tree:add(pf_s_flag, tvb(offset, 1))
    flags_tree:add(pf_dsiz, tvb(offset, 1))
    offset = offset + 1

    local s_flag = band(rshift(msg_flags, 2), 1)
    local dsiz = band(msg_flags, 3)

    -- Session ID
    local session_id = tvb(offset, 2):le_uint()
    subtree:add_le(pf_session_id, tvb(offset, 2))
    offset = offset + 2

    -- Security Flags
    local sec_flags = tvb(offset, 1):uint()
    local sf_tree = subtree:add(pf_sec_flags, tvb(offset, 1))
    sf_tree:add(pf_privacy, tvb(offset, 1))
    sf_tree:add(pf_control, tvb(offset, 1))
    sf_tree:add(pf_sess_type, tvb(offset, 1))
    offset = offset + 1

    local session_type = band(sec_flags, 0x03)

    -- Message Counter
    local msg_counter = tvb(offset, 4):le_uint()
    subtree:add_le(pf_msg_counter, tvb(offset, 4))
    offset = offset + 4

    -- Source Node ID (if S flag)
    local src_node_offset = nil
    if s_flag == 1 then
        if offset + 8 > length then return offset end
        subtree:add_le(pf_src_node, tvb(offset, 8))
        src_node_offset = offset
        offset = offset + 8
    end

    -- Destination Node ID (based on DSIZ)
    if dsiz == 1 then
        if offset + 8 > length then return offset end
        subtree:add_le(pf_dst_node, tvb(offset, 8))
        offset = offset + 8
    elseif dsiz == 2 then
        if offset + 2 > length then return offset end
        subtree:add_le(pf_dst_group, tvb(offset, 2))
        offset = offset + 2
    end

    local header_len = offset
    local payload_len = length - header_len

    -- Determine if encrypted
    local is_encrypted = (session_id ~= 0)

    if is_encrypted and payload_len > 16 then
        -- Encrypted message
        local mic_offset = length - 16
        subtree:add(pf_encrypted, tvb(offset, mic_offset - offset))
        subtree:add(pf_mic, tvb(mic_offset, 16))

        -- Try decryption with loaded keys
        local cached = decrypt_cache[pinfo.number]
        if cached then
            local dec_tree = subtree:add( "Decrypted")
            dec_tree:add( "Key: " .. cached.key_name)
            parse_protocol_header(cached.plaintext, 1, dec_tree)

            -- Find TLV start (after protocol header)
            local tlv_text = decode_tlv(cached.plaintext, 8)
            if tlv_text and #tlv_text > 0 then
                dec_tree:add( "TLV:\n" .. tlv_text)
            end

            -- Update info column
            if cached.info then
                pinfo.cols.info = cached.info
            end
            return length
        end

        -- Build nonce prefix: sec_flags(1) | msg_counter(4, LE)
        local nonce_prefix = {}
        nonce_prefix[1] = sec_flags
        nonce_prefix[2] = band(msg_counter, 0xFF)
        nonce_prefix[3] = band(rshift(msg_counter, 8), 0xFF)
        nonce_prefix[4] = band(rshift(msg_counter, 16), 0xFF)
        nonce_prefix[5] = band(rshift(msg_counter, 24), 0xFF)

        -- Source node ID from header (if present)
        local hdr_src_node = {}
        if src_node_offset then
            for i = 0, 7 do
                hdr_src_node[i + 1] = tvb(src_node_offset + i, 1):uint()
            end
        end

        -- AAD is the message header
        local aad = str_to_bytes(tvb:raw(0, header_len))

        -- Ciphertext including MIC tag
        local ct_with_tag = str_to_bytes(tvb:raw(header_len, payload_len))

        -- Build nonce with a given 8-byte source node ID
        local function make_nonce(src_bytes)
            local n = {}
            for i = 1, 5 do n[i] = nonce_prefix[i] end
            for i = 1, 8 do n[5 + i] = src_bytes[i] or 0 end
            return n
        end

        for ki, kp in ipairs(session_keys) do
            -- For each key pair, try both keys with their respective source node IDs
            -- I2R: sender is initiator, nonce uses initiator's node ID (i2r_src)
            -- R2I: sender is responder, nonce uses responder's node ID (r2i_src)
            -- Also try with header source node and zero as fallbacks
            local attempts = {
                {key = kp.i2r, src = kp.i2r_src, name = "I2R"},
                {key = kp.r2i, src = kp.r2i_src, name = "R2I"},
            }
            -- Add fallback attempts with zero node ID if configured IDs fail
            if #hdr_src_node > 0 then
                table.insert(attempts, {key = kp.i2r, src = hdr_src_node, name = "I2R+hdr"})
                table.insert(attempts, {key = kp.r2i, src = hdr_src_node, name = "R2I+hdr"})
            end

            local pt = nil
            local key_name = nil
            for _, att in ipairs(attempts) do
                local nonce = make_nonce(att.src)
                pt = aes_ccm_decrypt(att.key, nonce, aad, ct_with_tag)
                if pt then
                    key_name = string.format("%s (key set #%d)", att.name, ki)
                    break
                end
            end

            if pt and key_name then
                -- Parse protocol header for info column
                local proto_off, proto_name, opcode_name = parse_protocol_header(pt, 1, subtree:add( "Decrypted (" .. key_name .. ")"))

                local info_str = nil
                if proto_name and opcode_name then
                    info_str = string.format("Matter %s: %s (Session 0x%04x, Counter %d)",
                        proto_name, opcode_name, session_id, msg_counter)
                    pinfo.cols.info = info_str
                end

                -- Show TLV
                if proto_off then
                    local tlv_data = {}
                    for i = proto_off, #pt do tlv_data[#tlv_data + 1] = pt[i] end
                    if #tlv_data > 0 then
                        local tlv_text = decode_tlv(tlv_data, 8)
                        if tlv_text and #tlv_text > 0 then
                            subtree:add( "TLV:\n" .. tlv_text)
                        end
                    end
                end

                -- Cache result
                decrypt_cache[pinfo.number] = {
                    plaintext = pt,
                    key_name = key_name,
                    info = info_str,
                }
                return length
            end
        end

        -- Decryption failed — show diagnostics
        if #session_keys > 0 then
            local diag = subtree:add("[Decryption failed - check source node IDs in keylog]")
            diag:add(string.format("AAD (%d bytes): %s", #aad, bytes_to_hex(aad)))
            diag:add(string.format("Header len: %d, Payload len: %d, S flag: %d, DSIZ: %d",
                header_len, payload_len, s_flag, dsiz))
            for ki, kp in ipairs(session_keys) do
                diag:add(string.format("Key #%d: I2R=%s (src=%s) R2I=%s (src=%s)",
                    ki, bytes_to_hex(kp.i2r), bytes_to_hex(kp.i2r_src),
                    bytes_to_hex(kp.r2i), bytes_to_hex(kp.r2i_src)))
            end
        else
            subtree:add("[No keys loaded - set keylog file in preferences]")
        end

        pinfo.cols.info = string.format("Matter Encrypted (Session 0x%04x, Counter %d)",
            session_id, msg_counter)
    else
        -- Unencrypted message (session establishment)
        if payload_len > 0 then
            local payload_bytes = str_to_bytes(tvb:raw(offset, payload_len))
            local proto_off, proto_name, opcode_name = parse_protocol_header(payload_bytes, 1, subtree)

            if proto_name and opcode_name then
                pinfo.cols.info = string.format("Matter %s: %s", proto_name, opcode_name)
            end

            if proto_off then
                local tlv_data = {}
                for i = proto_off, #payload_bytes do tlv_data[#tlv_data + 1] = payload_bytes[i] end
                if #tlv_data > 0 then
                    local tlv_text = decode_tlv(tlv_data, 8)
                    if tlv_text and #tlv_text > 0 then
                        subtree:add( "TLV:\n" .. tlv_text)
                    end
                end
            end
        end
    end

    return length
end

----------------------------------------
-- Register on UDP port 5540 (Matter default)
----------------------------------------
local udp_table = DissectorTable.get("udp.port")
udp_table:add(5540, matter_proto)

-- Also register on common development ports
udp_table:add(5541, matter_proto)
udp_table:add(5542, matter_proto)
