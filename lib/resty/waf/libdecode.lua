local string_gmatch = string.gmatch
local string_match  = string.match
local ffi = require "ffi"

ffi.cdef[[
int js_decode(unsigned char *input, long int input_len);
int css_decode(unsigned char *input, long int input_len);
int validate_url_encoding(const char *input, uint64_t input_length);
int validate_utf8_encoding(const char* str_c, size_t len, char* err_char);
int normalize_path_inplace(char *input, int input_len,
                                          int win, int *changed);
]]

local loadlib = function()
	local so_name = 'libdecode.so'
	local cpath = package.cpath

    for k, _ in string_gmatch(cpath, "[^;]+") do
        local so_path = string_match(k, "(.*/)")
        if so_path then
            -- "so_path" could be nil. e.g, the dir path component is "."
            so_path = so_path .. so_name

            -- Don't get me wrong, the only way to know if a file exist is
            -- trying to open it.
            local f = io.open(so_path)
            if f ~= nil then
                io.close(f)
                return ffi.load(so_path)
            end
        end
    end
end

local _M = loadlib()
return _M