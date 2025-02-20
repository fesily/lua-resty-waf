use Test::Nginx::Socket::Lua;
use Cwd qw(cwd);

my $pwd = cwd();

our $HttpConfig = qq{
	lua_package_path "$pwd/lib/?.lua;;";
	lua_package_cpath "$pwd/lib/?.lua;;";
};

repeat_each(3);
plan tests => repeat_each() * 3 * blocks();

no_shuffle();
run_tests();

__DATA__

=== TEST 1: sanity
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local greater = require "resty.waf.operators"
        }
    }
--- request
    GET /t
--- response_body
--- error_code: 200
--- no_error_log
[error]

=== TEST 2: integer greater
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater(2, 1)
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 3: integer equals
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater(1, 1)
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]

=== TEST 4: integer less
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater(1, 2)
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]

=== TEST 5: table integer greater
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater({0, 1, 2}, 1)
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
true
--- error_code: 200
--- no_error_log
[error]

=== TEST 6: table integer equals
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = (op.greater({-1, 0, 1}, 1))
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]

=== TEST 7: table integer less
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater({-1, 0, 1}, 2)
			ngx.say(greater)
        }
    }
--- request
    GET /t
--- response_body
false
--- error_code: 200
--- no_error_log
[error]

=== TEST 8: return values
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater(1, 0)
			ngx.say(greater)
			ngx.say(value)
        }
    }
--- request
    GET /t
--- response_body
true
nil
--- error_code: 200
--- no_error_log
[error]

=== TEST 9: return value types
--- http_config eval: $::HttpConfig
--- config
    location = /t {
        content_by_lua_block {
			local op = require "resty.waf.operators"
			local greater, value = op.greater(1, 0)
			ngx.say(type(greater))
			ngx.say(type(value))
        }
    }
--- request
    GET /t
--- response_body
boolean
nil
--- error_code: 200
--- no_error_log
[error]

