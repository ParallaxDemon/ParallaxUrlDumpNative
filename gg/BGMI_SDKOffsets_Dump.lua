--[[
===============================================================================
 Parallax GG Dump - BGMI / PUBG KR Global / BGMI Air
===============================================================================
 GameGuardian Lua script. Pure report generator: offsets + "SDK dump".

 Works on any selected GG target, including:
   com.tencent.ig        (PUBG Mobile Global)
   com.pubg.krmobile     (PUBG KR)
   com.pubg.imobile      (BGMI / BGMI Air)

 What it writes (one .txt):
   1) Target / GG / Android SDK info
   2) Device info from /system/build.prop
   3) libUE4.so + libanogs.so ranges, base addresses, relative offsets, ELF magic
   4) All loaded .so libraries with base + size
   5) Game API / endpoints: URLs found in dumped target-library memory and in
      UrlDump/*.txt produced by liburldump.so (if present)

 No memory is modified. This is a read-only dump for authorized testing only.
===============================================================================
--]]

local OUT_DIR = tostring(gg.EXT_STORAGE or "/mnt/sdcard") .. "/GG_Dump"
local DUMP_DIR = OUT_DIR .. "/mem"
local SCHEMES = { "https://", "http://", "wss://", "ws://" }

local g_urls = {}
local g_url_list = {}
local g_report_lines = {}

local function say(s)
    g_report_lines[#g_report_lines + 1] = tostring(s)
end

local function hx(n)
    n = tonumber(n)
    if not n then return "?" end
    return string.format("0x%X", n)
end

local function hx_lower(n)
    n = tonumber(n)
    if not n then return "?" end
    return string.format("%x", n)
end

local function safe(fn, default)
    local ok, res = pcall(fn)
    if ok then return res end
    return default
end

local function ensure_dirs()
    os.execute("mkdir -p '" .. OUT_DIR .. "' 2>/dev/null")
    os.execute("mkdir -p '" .. DUMP_DIR .. "' 2>/dev/null")
end

local function list_files(dir, list_path)
    if not dir then return end
    os.execute("ls -1 '" .. dir .. "' > '" .. list_path .. "' 2>/dev/null")
end

local function read_file(path)
    local f = io.open(path, "rb")
    if not f then return nil end
    local data = f:read("*a")
    f:close()
    return data
end

local function read_dword(addr)
    if not addr or addr <= 0 then return nil end
    local ok, res = pcall(function()
        return gg.getValues({ { address = addr, flags = gg.TYPE_DWORD } })
    end)
    if ok and res and res[1] and res[1].value ~= nil then
        return tonumber(res[1].value)
    end
    return nil
end

local function add_url(raw)
    if type(raw) ~= "string" then return end
    local u = raw:gsub("^%s+", ""):gsub("%s+$", "")
    while true do
        local last = u:sub(-1)
        if last == "." or last == "," or last == ";" or last == ")" or
           last == "]" or last == "}" or last == "\"" or last == "'" then
            u = u:sub(1, -2)
        else
            break
        end
    end
    if #u < 8 or #u > 512 then return end
    if not g_urls[u] then
        g_urls[u] = true
        g_url_list[#g_url_list + 1] = u
    end
end

local function is_url_byte(b)
    if not b or b <= 0x20 then return false end
    if b == 0x22 or b == 0x27 or b == 0x3C or b == 0x3E or b == 0x5C then return false end
    if b == 0x28 or b == 0x29 or b == 0x5B or b == 0x5D or b == 0x7B or b == 0x7D then return false end
    if b == 0x3B or b == 0x2C then return false end
    return true
end

local function scan_data(data)
    if type(data) ~= "string" or #data == 0 then return end
    local n = #data

    -- ASCII / UTF-8
    for _, scheme in ipairs(SCHEMES) do
        local from = 1
        while true do
            local i, j = string.find(data, scheme, from, true)
            if not i then break end
            local max_k = math.min(n, i + 512)
            local k = j + 1
            while k <= max_k and is_url_byte(data:byte(k)) do k = k + 1 end
            add_url(data:sub(i, k - 1))
            from = (k > j) and k or (j + 1)
        end
    end

    -- UTF-16LE (Java/Kotlin strings)
    for _, scheme in ipairs(SCHEMES) do
        local parts = {}
        for ch in scheme:gmatch(".") do parts[#parts + 1] = ch .. "\0" end
        local pat = table.concat(parts)
        local from = 1
        while true do
            local i, j = string.find(data, pat, from, true)
            if not i then break end
            local max_k = math.min(n, j + 1024)
            local u = scheme
            local p = j + 1
            while p + 1 <= max_k do
                local low, high = data:byte(p), data:byte(p + 1)
                if high ~= 0 or not is_url_byte(low) then break end
                u = u .. string.char(low)
                p = p + 2
            end
            add_url(u)
            from = (p > j) and p or (j + 2)
        end
    end
end

local function scan_file(path)
    local f = io.open(path, "rb")
    if not f then return end
    local tail = ""
    while true do
        local chunk = f:read(1024 * 1024)
        if not chunk then break end
        local data = tail .. chunk
        scan_data(data)
        tail = (#data > 64) and data:sub(-64) or data
    end
    f:close()
end

local function scan_url_dump_text(path)
    local f = io.open(path, "r")
    if not f then return end
    for line in f:lines() do
        if line:find("https://", 1, true) or line:find("http://", 1, true) or
           line:find("wss://", 1, true) or line:find("ws://", 1, true) then
            add_url(line)
        end
    end
    f:close()
end

local function each_file_in_list(list_path, dir, ext, callback)
    local f = io.open(list_path, "r")
    if not f then return end
    for line in f:lines() do
        line = line:gsub("%s+$", "")
        if line ~= "" and line:sub(-#ext) == ext then
            callback(dir .. "/" .. line)
        end
    end
    f:close()
end

local function collect_target_ranges()
    local all = safe(function() return gg.getRangesList() end, {}) or {}
    local target, libs = {}, {}
    local seen_lib = {}

    for _, r in ipairs(all) do
        local name = tostring(r.name or r.internalName or "")
        local low = name:lower()
        if low:find(".so", 1, true) then
            local base_name = low:match("([^/]+%.so)") or low
            if not seen_lib[base_name] then
                seen_lib[base_name] = true
                libs[#libs + 1] = {
                    name = base_name,
                    start = tonumber(r.start) or 0,
                    finish = tonumber(r["end"]) or 0,
                    state = tostring(r.state or "?"),
                    type = tostring(r.type or "?")
                }
            end
        end
        if low:find("libue4%.so", 1, true) or low:find("libanogs%.so", 1, true) then
            target[#target + 1] = r
        end
    end

    table.sort(libs, function(a, b) return a.start < b.start end)
    table.sort(target, function(a, b)
        local an = tostring(a.name or a.internalName or ""):lower()
        local bn = tostring(b.name or b.internalName or ""):lower()
        if an == bn then return (tonumber(a.start) or 0) < (tonumber(b.start) or 0) end
        return an < bn
    end)
    return target, libs
end

local function write_target_section(target)
    say("")
    say("=== [3] libUE4.so + libanogs.so offsets ===")
    if #target == 0 then
        say("No libUE4.so / libanogs.so ranges found. Is the game fully loaded?")
        return
    end

    local bases, dumped = {}, 0
    for _, r in ipairs(target) do
        local nm = tostring(r.name or r.internalName or "unknown")
        local key = nm:lower():find("libue4") and "libUE4.so" or "libanogs.so"
        local s = tonumber(r.start) or 0
        if not bases[key] or s < bases[key] then bases[key] = s end
    end

    for _, r in ipairs(target) do
        local nm = tostring(r.name or r.internalName or "unknown")
        local key = nm:lower():find("libue4") and "libUE4.so" or "libanogs.so"
        local s, e = tonumber(r.start) or 0, tonumber(r["end"]) or 0
        local rel = s - (bases[key] or s)
        say(string.format("%s base=%s range=%s-%s size=%s offset=+%s state=%s type=%s",
            key, hx(bases[key]), hx(s), hx(e), hx(e - s), hx(rel),
            tostring(r.state or "?"), tostring(r.type or "?")))
        say("    map=" .. nm)

        if e - 1 > s then
            local ok = safe(function()
                return gg.dumpMemory(s, e - 1, DUMP_DIR)
            end, nil)
            if ok == true or ok == nil then dumped = dumped + 1 end
        end
    end

    for key, base in pairs(bases) do
        local magic = read_dword(base)
        say(key .. " ELF magic @base = " .. (magic and hx(magic) or "unreadable") ..
            " (little-endian 0x464C457F expected)")
    end
    say("Dumped " .. dumped .. " target range(s) into " .. DUMP_DIR)

    -- Discover whatever filenames gg.dumpMemory actually created.
    local list_path = OUT_DIR .. "/mem_list.txt"
    list_files(DUMP_DIR, list_path)
    each_file_in_list(list_path, DUMP_DIR, ".bin", scan_file)
end

local function write_libs_section(libs)
    say("")
    say("=== [4] All loaded .so libraries (base + size) ===")
    if #libs == 0 then
        say("No .so mappings found.")
        return
    end
    for _, l in ipairs(libs) do
        say(string.format("%-40s base=%s size=%s state=%s type=%s",
            l.name, hx(l.start), hx(l.finish - l.start), l.state, l.type))
    end
end

local function write_device_section()
    say("")
    say("=== [2] Device info (/system/build.prop) ===")
    local wanted = {
        ["ro.product.model"] = true,
        ["ro.product.brand"] = true,
        ["ro.product.device"] = true,
        ["ro.product.name"] = true,
        ["ro.build.version.release"] = true,
        ["ro.build.version.sdk"] = true,
        ["ro.build.version.incremental"] = true,
        ["ro.build.display.id"] = true,
        ["ro.build.fingerprint"] = true,
        ["ro.product.cpu.abi"] = true,
        ["ro.product.cpu.abilist"] = true
    }
    local f = io.open("/system/build.prop", "r")
    if f then
        for line in f:lines() do
            local k, v = line:match("^([^#=]+)=(.*)$")
            if k and wanted[k] then say(k .. " = " .. v) end
        end
        f:close()
    else
        say("build.prop not readable")
    end

    local cpu = read_file("/proc/cpuinfo")
    if cpu then
        local hw = cpu:match("Hardware%s*:%s*([^\n]+)")
        if hw then say("CPU Hardware = " .. hw) end
    end
    local mem = read_file("/proc/meminfo")
    if mem then
        local total = mem:match("MemTotal:%s*([^\n]+)")
        if total then say("MemTotal = " .. total) end
    end
end

local function write_info_section(pkg, info, variant)
    say("=== [1] Target / GG / Android SDK ===")
    say("variant          = " .. variant)
    say("package          = " .. pkg)
    say("versionCode      = " .. tostring(info.versionCode or "?"))
    say("versionName      = " .. tostring(info.versionName or "?"))
    say("label            = " .. tostring(info.label or "?"))
    say("GG version       = " .. tostring(gg.VERSION or "?"))
    say("GG version int   = " .. tostring(gg.VERSION_INT or "?"))
    say("Android SDK int  = " .. tostring(gg.ANDROID_SDK_INT or "?"))
    say("locale           = " .. tostring(safe(function() return gg.getLocale() end, "?")))
    say("EXT_STORAGE      = " .. tostring(gg.EXT_STORAGE or "?"))
    say("EXT_FILES_DIR    = " .. tostring(gg.EXT_FILES_DIR or "?"))
    say("time             = " .. os.date("%Y-%m-%d %H:%M:%S"))
end

local function write_url_section(pkg)
    say("")
    say("=== [5] Game API / endpoints (URLs) ===")
    say("Sources: dumped libUE4.so/libanogs.so memory + UrlDump/*.txt")

    -- Also include the passive native dumper output if it exists.
    local files_dir = tostring(gg.EXT_FILES_DIR or
        (tostring(gg.EXT_STORAGE or "/mnt/sdcard") .. "/Android/data/" .. pkg .. "/files"))
    local url_dir = files_dir .. "/UrlDump"
    local url_list = OUT_DIR .. "/urldump_list.txt"
    list_files(url_dir, url_list)
    each_file_in_list(url_list, url_dir, ".txt", scan_url_dump_text)

    if #g_url_list == 0 then
        say("No URLs found. Let the game finish loading, then run again.")
    else
        for i, u in ipairs(g_url_list) do
            say(string.format("%03d %s", i, u))
        end
    end
end

local function main()
    ensure_dirs()

    local info = safe(function() return gg.getTargetInfo() end, {}) or {}
    local pkg = tostring(info.packageName or safe(function() return gg.getTargetPackage() end, nil) or "unknown")
    local known = {
        ["com.tencent.ig"] = "PUBG Mobile Global",
        ["com.pubg.krmobile"] = "PUBG KR",
        ["com.pubg.imobile"] = "BGMI / BGMI Air",
        ["com.pubg.air"] = "BGMI Air"
    }
    local variant = known[pkg] or "other (script is package-agnostic)"

    gg.toast("Parallax GG Dump: scanning " .. variant, true)

    write_info_section(pkg, info, variant)
    write_device_section()

    local target, libs = collect_target_ranges()
    write_target_section(target)
    write_libs_section(libs)
    write_url_section(pkg)

    say("")
    say("=== End of dump ===")
    say("Legal: use only on apps/games you own or are explicitly authorized to test.")

    local report_path = OUT_DIR .. "/" .. pkg .. "_dump_" .. os.date("%Y%m%d_%H%M%S") .. ".txt"
    local f = io.open(report_path, "w")
    if not f then
        gg.alert("Cannot write report. Check storage permission for GameGuardian.")
        return
    end
    f:write(table.concat(g_report_lines, "\n") .. "\n")
    f:close()

    gg.alert("Dump saved:\n" .. report_path .. "\n\nURLs found: " .. #g_url_list)
end

local ok, err = pcall(main)
if not ok then
    ensure_dirs()
    local err_path = OUT_DIR .. "/gg_dump_error.txt"
    local f = io.open(err_path, "w")
    if f then
        f:write("Parallax GG Dump error: " .. tostring(err) .. "\n")
        f:close()
    end
    gg.alert("Dump failed: " .. tostring(err))
end
