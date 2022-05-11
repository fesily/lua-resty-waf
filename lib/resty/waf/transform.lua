local _M = {}

local base   = require "resty.waf.base"
local hdec   = require "resty.htmlentities"
local ffi    = require "ffi"
local logger = require "resty.waf.log"
local util   = require "resty.waf.util"
local regex = require "resty.waf.regex"

local ffi_cpy    = ffi.copy
local ffi_new    = ffi.new
local ffi_str    = ffi.string
local c_buf_type = ffi.typeof("char[?]")

local string_find   = string.find
local string_gsub   = string.gsub
local string_len    = string.len
local string_lower  = string.lower
local string_sub    = string.sub
local re_sub = regex.sub
local re_match = regex.match
local re_gsub = regex.gsub

_M.version = base.version

hdec.new() -- load the module on require

local decode_lib = require ("resty.waf.libdecode")

local function decode_buf_helper(value, len)
	local buf = ffi_new(c_buf_type, len)
	ffi_cpy(buf, value)
	return buf
end

_M.lookup = {
	base64_decode = function(waf, value)
		if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "Decoding from base64: " .. tostring(value)) end
		local t_val = ngx.decode_base64(tostring(value))
		if t_val then
			if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "Decode successful, decoded value is " .. t_val) end
			return t_val
		else
			if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "Decode unsuccessful, returning original value " .. value) end
			return value
		end
	end,
	base64_encode = function(waf, value)
		if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "Encoding to base64: " .. tostring(value)) end
		local t_val = ngx.encode_base64(value)
		if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "Encoded value is " .. t_val) end
		return t_val
	end,
	css_decode = function(waf, value)
		if not value then return end

		local len = #value
		local buf = decode_buf_helper(value, len)

		local n = decode_lib.css_decode(buf, len)

		return (ffi_str(buf, n))
	end,
	cmd_line = function(waf, value)
		local str = tostring(value)
		str = re_gsub(str, [=[[\\'"^]]=], '',  waf._pcre_flags)
		str = re_gsub(str, [=[\s+/]=],    '/', waf._pcre_flags)
		str = re_gsub(str, [=[\s+[(]]=],  '(', waf._pcre_flags)
		str = re_gsub(str, [=[[,;]]=],    ' ', waf._pcre_flags)
		str = re_gsub(str, [=[\s+]=],     ' ', waf._pcre_flags)
		return string_lower(str)
	end,
	compress_whitespace = function(waf, value)
		return re_gsub(value, [=[\s+]=], ' ', waf._pcre_flags)
	end,
	hex_decode = function(waf, value)
		return util.hex_decode(value)
	end,
	hex_encode = function(waf, value)
		return util.hex_encode(value)
	end,
	html_decode = function(waf, value)
		local str = hdec.decode(value)
		if waf._debug == true then ngx.log(waf._debug_log_level, '[', waf.transaction_id, '] ', "html decoded value is " .. str) end
		return str
	end,
	js_decode = function(waf, value)
		if not value then return end

		local len = #value
		local buf = decode_buf_helper(value, len)

		local n = decode_lib.js_decode(buf, len)

		return (ffi_str(buf, n))
	end,
	length = function(waf, value)
		return string_len(tostring(value))
	end,
	lowercase = function(waf, value)
		return string_lower(tostring(value))
	end,
	md5 = function(waf, value)
		return ngx.md5_bin(value)
	end,
	normalise_path = function(waf, value)
		while (re_match(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], waf._pcre_flags)) do
			value = re_gsub(value, [=[[^/][^/]*/\.\./|/\./|/{2,}]=], '/', waf._pcre_flags)
		end
		return value
	end,
	normalise_path_win = function(waf, value)
		value = string_gsub(value, [[\]], [[/]])
		return _M.lookup['normalise_path'](waf, value)
	end,
	remove_comments = function(waf, value)
		return re_gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], '', waf._pcre_flags)
	end,
	remove_comments_char = function(waf, value)
		return re_gsub(value, [=[\/\*|\*\/|--|#]=], '', waf._pcre_flags)
	end,
	remove_nulls = function(waf, value)
		return re_gsub(value, [[\0]], '', waf._pcre_flags)
	end,
	remove_whitespace = function(waf, value)
		return re_gsub(value, [=[\s+]=], '', waf._pcre_flags)
	end,
	replace_comments = function(waf, value)
		return re_gsub(value, [=[\/\*(\*(?!\/)|[^\*])*\*\/]=], ' ', waf._pcre_flags)
	end,
	replace_nulls = function(waf, value)
		return re_gsub(value, [[\0]], ' ', waf._pcre_flags)
	end,
	sha1 = function(waf, value)
		return ngx.sha1_bin(value)
	end,
	sql_hex_decode = function(waf, value)
		if string_find(value, '0x', 1, true) then
			value = string_sub(value, 3)
			return util.hex_decode(value)
		else
			return value
		end
	end,
	trim = function(waf, value)
		return re_gsub(value, [=[^\s*|\s+$]=], '')
	end,
	trim_left = function(waf, value)
		return re_sub(value, [=[^\s+]=], '')
	end,
	trim_right = function(waf, value)
		return re_sub(value, [=[\s+$]=], '')
	end,
	uri_decode = function(waf, value)
		return ngx.unescape_uri(value)
	end,
}

return _M
