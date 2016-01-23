#名称
=================

用于ngx_resty的大数运算库

描述
=================
当前resty仅支持最大51位整数，而是用c中的double long也仅支持64位整数，当如果需要计算一些大数运算时，将出现一些瓶颈。
本库直接使用openssl中的bignumber库进行封装，使用本库，需要在服务器上安装openssl和openssl-dev等相关库

使用
=================
1.在代码中引用本库，并创建实例

```lua
    local lib_bn = require "resty.bn"
    local bn     = lib_bn:new()
```

2.可以直接调用库中函数，函数暂只包括大数的：
> 相加(add)

```lua
    local a = "998123124234634536345"
    local b = "6998123121543524234634536345"
    local r = bn:add(a, b) -- r = a + b
```

> 相减(sub)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local r = bn:sub(a, b) -- r = a - b
```

> 相乘(mul)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local r = bn:mul(a, b) -- r = a * b
```

> 相除(div，包括模)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local d, rem = bn:div(a, b) -- d = a / b, rem = a % b
```

> 乘方(pow)

```lua
    local a = "2998123435452423461524236552423"
    local b = "65"
    local r = bn:pow(a, b) -- r = a ^ b
```

> 十进制转十六机制(dec2hex)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn:dec2hex(a)
```

> 十六进制转十进制(hex2dec)

```lua
    local a = "a123ef0080912d12"
    local b = bn:hex2dec(a)
```

> 位运算左移(lshift)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn:lshift(a, 10)
```

> 位运算右移(rshift)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn:rshift(a, 10)
```
