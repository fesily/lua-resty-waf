---@class WAF.Collections
---@field TX string
---@field IP string
---@field GLOBAL string
---@field REQBODY_PROCESSOR string
---@field RULE WAF.Rule
---@field REMOTE_ADDR string
---@field HTTP_VERSION string
---@field METHOD string
---@field URI string
---@field URI_ARGS table
---@field QUERY_STRING string
---@field ARGS_COMBINED_SIZE integer
---@field COOKIES string
---@field REQUEST_URI string
---@field REQUEST_URI_RAW string
---@field REQUEST_BASENAME string|string[]|'false'
---@field REQUEST_HEADERS table<string,string|string[]>
---@field REQUEST_ARGS string
---@field REQUEST_BODY string|table|nil
---@field REQUEST_LINE string
---@field PROTOCOL string
---@field NGX_VAR table
---@field MATCHED_VARS table
---@field MATCHED_VAR_NAMES table
---@field MATCHED_VAR string
---@field MATCHED_VAR_NAME string
---@field SCORE_THRESHOLD string
---@field TIME string
---@field TIME_DAY string
---@field TIME_EPOCH integer
---@field TIME_HOUR string
---@field TIME_MIN string
---@field TIME_MON string
---@field TIME_SEC string
---@field TIME_YEAR string
---@field RESPONSE_HEADERS table<string,string|string[]>
---@field RESPONSE_BODY string
---@field STATUS ngx.http.status_code
---@field FILES table
---@field FILES_COMBINED_SIZE integer
---@field FILES_NAMES table
---@field FILES_SIZES table
---@field FILES_TMP_CONTENT table

---@class WAF.Data
---@field col string
---@field key string
---@field value any

---@class WAF.Variable
---@field length integer?
---@field type string
---@field storage boolean?
---@field parse string[]?
---@field unconditional boolean?
---@field ignore any[]?
---@field collection_key string

---@class WAF.Rule.Options
---@field nolog boolean?
---@field parsepattern boolean?
---@field transform string|string[]|nil

---@class WAF.Rule
---@field id integer
---@field offset_match integer
---@field offset_nomatch integer
---@field actions {disrupt:string,nondisrupt:{action:string,data:WAF.Data|any}[]}
---@field operator string
---@field opts WAF.Rule.Options
---@field pattern string|string[]
---@field msg string
---@field severity string
---@field ver string[]
---@field vars WAF.Variable[]
---@field tag string[]
---@field op_negated boolean
---@field skip_after string?
---@field skip integer?