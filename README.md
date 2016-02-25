##����

����ngx_resty�Ĵ��������

##����

��ǰresty��֧�����51λ������������c�е�double longҲ��֧��64λ�������������Ҫ����һЩ��������ʱ��������һЩƿ����
����ֱ��ʹ��openssl�е�bignumber����з�װ��ʹ�ñ��⣬��Ҫ�ڷ������ϰ�װopenssl��openssl-dev����ؿ�.����ʹ��whereis openssl�鿴�Ƿ��а�װ��ؿ⣬һ����/usr/include/openssl/����ῴ����Ӧ��ͷ�ļ�-bn.h

##ʹ��

1.�ڴ��������ñ��⣬������ʵ��

```lua
    local bn = require "resty.bn"
```

2.����ֱ�ӵ��ÿ��к�����������ֻ���������ģ�
> ���(add)

```lua
    local a = "998123124234634536345"
    local b = "6998123121543524234634536345"
    local r = bn.add(a, b) -- r = a + b
```

> ���(sub)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local r = bn.sub(a, b) -- r = a - b
```

> ���(mul)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local r = bn.mul(a, b) -- r = a * b
```

> ���(div������ģ)

```lua
    local a = "2998123435452423461524236552423"
    local b = "6998123121543524234634536345"
    local d, rem = bn.div(a, b) -- d = a / b, rem = a % b
```

> �˷�(pow)

```lua
    local a = "2998123435452423461524236552423"
    local b = "65"
    local r = bn.pow(a, b) -- r = a ^ b
```

> ʮ����תʮ������(dec2hex)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn.dec2hex(a)
```

> ʮ������תʮ����(hex2dec)

```lua
    local a = "a123ef0080912d12"
    local b = bn.hex2dec(a)
```

> λ��������(lshift)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn.lshift(a, 10)
```

> λ��������(rshift)

```lua
    local a = "2998123435452423461524236552423"
    local b = bn.rshift(a, 10)
```
