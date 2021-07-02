common='require"utf8string"==require"init" and "OK (init==utf8string)" or "FAILURE (init!=utf8string)"'
LUA_INIT='package.loaded.init=require"utf8string";print("LUA_INIT",_VERSION,'"$common"')'
LUA_INIT_5_1='package.loaded.init=require"utf8string";print("LUA_INIT_5_1",_VERSION,'"$common"')'
LUA_INIT_5_2='package.loaded.init=require"utf8string";print("LUA_INIT_5_2",_VERSION,'"$common"')'
LUA_INIT_5_3='package.loaded.init=require"utf8string";print("LUA_INIT_5_3",_VERSION,'"$common"')'
export LUA_INIT LUA_INIT_5_1 LUA_INIT_5_2 LUA_INIT_5_3

