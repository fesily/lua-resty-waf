local _M = {}

local actions = require "resty.waf.actions"
local base    = require "resty.waf.base"
local logger  = require "resty.waf.log"
local util    = require "resty.waf.util"

_M.version = base.version

_M.lookup = {
	---@param waf WAF
	ignore_ruleset = function(waf, value)
		waf._ignore_ruleset[#waf._ignore_ruleset + 1] = value
		waf.need_merge = true
	end,
	---@param waf WAF
	add_ruleset = function(waf, value)
		waf._add_ruleset[#waf._add_ruleset + 1] = value
		waf.need_merge = true
	end,
	---@param waf WAF
	add_ruleset_string = function(waf, value, ruleset)
		waf._add_ruleset_string[value] = ruleset
		waf.need_merge = true
	end,
	---@param waf WAF
	ignore_rule = function(waf, value)
		waf._ignore_rule[value] = true
	end,
	---@param waf WAF
	disable_pcre_optimization = function(waf, value)
		logger.deprecate(waf, 'PCRE flags will force JIT/cache', '0.12')
		if value == true then
			waf._pcre_flags = 'i'
		end
	end,
	---@param waf WAF
	storage_zone = function(waf, value)
		if not ngx.shared[value] then
			logger.fatal_fail("Attempted to set lua-resty-waf storage zone as " .. tostring(value) .. ", but that lua_shared_dict does not exist")
		end
		waf._storage_zone = value
	end,
	---@param waf WAF
	allowed_content_types = function(waf, value)
		waf._allowed_content_types[value] = true
	end,
	---@param waf WAF
	res_body_mime_types = function(waf, value)
		waf._res_body_mime_types[value] = true
	end,
	---@param waf WAF
	event_log_ngx_vars = function(waf, value)
		waf._event_log_ngx_vars[value] = true
	end,
	---@param waf WAF
	nameservers = function(waf, value)
		waf._nameservers[#waf._nameservers + 1] = value
	end,
	---@param waf WAF
	hook_action = function(waf, value, hook)
		if not util.table_has_key(value, actions.disruptive_lookup) then
			logger.fatal_fail(value .. " is not a valid action to override")
		end

		if type(hook) ~= "function" then
			logger.fatal_fail("hook_action must be defined as a function")
		end

		waf._hook_actions[value] = hook
	end,
    block_mode = function(waf, value)
        if not value then
            waf._hook_actions["DENY"] = function()end
        end
    end
}

return _M
