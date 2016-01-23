-- 使用openssl的bignum库，仅添加部分常用函数，基于十进制
-- 需要安装openssl-dev
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_cast = ffi.cast
local ffi_gc = ffi.gc
local ffi_copy = ffi.copy
local ffi_str = ffi.string
local C = ffi.C
local setmetatable = setmetatable


local _M = { _VERSION = '0.01' }

local mt = { __index = _M }


ffi.cdef[[
unsigned int strlen(char *s);

typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;

BN_CTX *BN_CTX_new(void);
void    BN_CTX_free(BN_CTX *c);

BIGNUM *BN_new(void);
void BN_free(BIGNUM *a);

int BN_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
int BN_mul(BIGNUM *r, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
int BN_sqr(BIGNUM *r, BIGNUM *a, BN_CTX *ctx);
int BN_exp(BIGNUM *r, BIGNUM *a, BIGNUM *p, BN_CTX *ctx);
int BN_div(BIGNUM *dv, BIGNUM *rem, const BIGNUM *a, const BIGNUM *d, BN_CTX *ctx);

int BN_set_bit(BIGNUM *a, int n);
int BN_clear_bit(BIGNUM *a, int n);
int BN_lshift(BIGNUM *r, const BIGNUM *a, int n);
int BN_rshift(BIGNUM *r, BIGNUM *a, int n);

int BN_dec2bn(BIGNUM **a, const char *str);
int BN_hex2bn(BIGNUM **a, const char *str);
char *BN_bn2dec(const BIGNUM *a);
char *BN_bn2hex(const BIGNUM *a);
]]


local function err()
    local code = C.ERR_get_error()

    local err = C.ERR_reason_error_string(code)

    return nil, ffi_str(err)
end

local big_list = ffi_new("BIGNUM *[?]", 4)
big_list[0] = C.BN_new()
big_list[1] = C.BN_new()
big_list[2] = C.BN_new()
big_list[3] = C.BN_new()

function _M.new(self)
    local ctx = C.BN_CTX_new()
    if ffi_cast("void *", ctx) == nil then
        return err()
    end
    ffi_gc(ctx, C.BN_CTX_free)
    return setmetatable({ ctx = ctx }, mt)
end

--r = a + b
-- bn:add(a, b)
function _M.add(self, a, b)
    C.BN_dec2bn(big_list + 0, tostring(a))
    C.BN_dec2bn(big_list + 1, tostring(b))
    
    C.BN_add(big_list[2], big_list[0], big_list[1])
    local r = C.BN_bn2dec(big_list[2])
    local len = C.strlen(r)
    return ffi.string(r, len)
end

--r = a - b
-- bn:sub(a, b)
function _M.sub(self, a, b)
    C.BN_dec2bn(big_list + 0, tostring(a))
    C.BN_dec2bn(big_list + 1, tostring(b))
    
    C.BN_sub(big_list[2], big_list[0], big_list[1])
    local r = C.BN_bn2dec(big_list[2])
    local len = C.strlen(r)
    return ffi.string(r, len)
end

--r = a * b
-- bn:mul(a, b)
function _M.mul(self, a, p)
    C.BN_dec2bn(big_list + 0, tostring(a))
    C.BN_dec2bn(big_list + 1, tostring(p))
    
    C.BN_mul(big_list[2], big_list[0], big_list[1], self.ctx)
    local r = C.BN_bn2dec(big_list[2])
    local len = C.strlen(r)
    return ffi.string(r, len)
end

--d = a / b, r = a % b
-- bn:div(a, b)
function _M.div(self, a, b)
    C.BN_dec2bn(big_list + 0, tostring(a))
    C.BN_dec2bn(big_list + 1, tostring(b))
    C.BN_div(big_list[3], big_list[2], big_list[0], big_list[1], self.ctx)
    local r = C.BN_bn2dec(big_list[2])
    local d = C.BN_bn2dec(big_list[3])
    local len_r = C.strlen(r)
    local len_d = C.strlen(d)
    return ffi.string(d, len_d), ffi.string(r, len_r)
end

-- r = a ^ p
-- bn:pow(a, p)
function _M.pow(self, a, p)
    C.BN_dec2bn(big_list + 0, tostring(a))
    C.BN_dec2bn(big_list + 1, tostring(p))
    
    C.BN_exp(big_list[2], big_list[0], big_list[1], self.ctx)
    local r = C.BN_bn2dec(big_list[2])
    local len = C.strlen(r)
    return ffi.string(r, len)
end

-- r = a ^ 2
-- bn:sqr(a)  性能优于pow
function _M.sqr(self, a)
    C.BN_dec2bn(big_list + 0, tostring(a))

    C.BN_sqr(big_list[1], big_list[0], self.ctx)
    local r = C.BN_bn2dec(big_list[1])
    local len = C.strlen(r)
    return ffi.string(r, len)
end

--  大数十进制转十六进制
-- bn:dec2hex(a)
function _M.dec2hex(self, a)
    C.BN_dec2bn(big_list + 0, tostring(a))

    local ret = C.BN_bn2hex(big_list[0])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

--  大数十六进制转十进制
-- bn:hex2dec(a)
function _M.hex2dec(self, a)
    C.BN_hex2bn(big_list + 0, tostring(a))

    local ret = C.BN_bn2dec(big_list[0])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

-- 将a中的第n位设置为1
-- bn:set_bit(a, n)
function _M.set_bit(self, a, n)
    C.BN_dec2bn(big_list + 0, tostring(a))

    C.BN_set_bit(big_list[0], n)
    local ret = C.BN_bn2dec(big_list[0])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

-- 将a中的第n为设置为0
-- bn:clear_bit(a, n)
function _M.clear_bit(self, a, n)
    C.BN_dec2bn(big_list + 0, tostring(a))

    C.BN_clear_bit(big_list[0], n)
    local ret = C.BN_bn2dec(big_list[0])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

-- a左移n位，结果存于r
-- bn:lshift(a, n)
function _M.lshift(self, a, n)
    C.BN_dec2bn(big_list + 0, tostring(a))

    C.BN_lshift(big_list[1], big_list[0], n)
    local ret = C.BN_bn2dec(big_list[1])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

--  a右移n位，结果存于r
-- bn:rshift(a, n)
function _M.rshift(self, a, n)
    C.BN_dec2bn(big_list + 0, tostring(a))

    C.BN_rshift(big_list[1], big_list[0], n)
    local ret = C.BN_bn2dec(big_list[1])
    local len = C.strlen(ret)
    return ffi.string(ret, len)
end

return _M
