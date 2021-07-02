## How to run test

```bash
( . ./env.sh ; ./test.sh )
```

## Test result

```bash
++ which lua5.3
+ lua53=/usr/bin/lua5.3
++ which lua5.2
+ lua52=/usr/bin/lua5.2
++ which lua5.1
+ lua51=/usr/bin/lua5.1
++ which luajit
+ luajit=/usr/bin/luajit
+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/charclass_compiletime.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)
OK
+ /usr/bin/lua5.2 test/charclass_compiletime.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)
OK
+ /usr/bin/lua5.1 test/charclass_compiletime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ /usr/bin/luajit test/charclass_compiletime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/charclass_runtime.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)
OK
+ /usr/bin/lua5.2 test/charclass_runtime.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)
OK
+ /usr/bin/lua5.1 test/charclass_runtime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ /usr/bin/luajit test/charclass_runtime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/context_runtime.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)
OK
+ /usr/bin/lua5.2 test/context_runtime.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)
OK
+ /usr/bin/lua5.1 test/context_runtime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ /usr/bin/luajit test/context_runtime.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
OK
+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/test.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)

tests passed

+ /usr/bin/lua5.2 test/test.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)

tests passed

+ /usr/bin/lua5.1 test/test.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)

tests passed

+ /usr/bin/luajit test/test.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)

tests passed

+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/test_compat.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)
testing utf8 library
+
+
+
+
OK
+ /usr/bin/lua5.2 test/test_compat.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)
testing utf8 library
+
+
+
+
OK
+ /usr/bin/lua5.1 test/test_compat.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
testing utf8 library
+
+
+
+
OK
+ /usr/bin/luajit test/test_compat.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
testing utf8 library
+
+
+
+
OK
+ for test in test/charclass_compiletime.lua test/charclass_runtime.lua test/context_runtime.lua test/test.lua test/test_compat.lua test/test_pm.lua
+ /usr/bin/lua5.3 test/test_pm.lua
LUA_INIT_5_3	Lua 5.3	OK (init==utf8string)
testing pattern matching
+
+
+
+
OK
+ /usr/bin/lua5.2 test/test_pm.lua
LUA_INIT_5_2	Lua 5.2	OK (init==utf8string)
testing pattern matching
+
+
+
+
OK
+ /usr/bin/lua5.1 test/test_pm.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
testing pattern matching
+
+
+
+
OK
+ /usr/bin/luajit test/test_pm.lua
LUA_INIT	Lua 5.1	OK (init==utf8string)
testing pattern matching
+
+
+
+
OK
+ echo 'tests passed'
tests passed
```
