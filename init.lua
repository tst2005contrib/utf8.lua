local module_path = (...):match("^(.-)[^.]+$") -- cut last module name part
local utf8 = {
  config = {},
  default = {
    debug = nil,
    logger = io.write,
    loadstring = (loadstring or load),
    unpack = (unpack or table.unpack),
    cache = {
      regex = setmetatable({},{
        __mode = 'kv'
      }),
      plain = setmetatable({},{
        __mode = 'kv'
      }),
    },
    locale = "C.UTF-8",
  },
  regex = {
    compiletime = {
      charclass = {},
      begins = {},
      ends = {},
      modifier = {},
    }
  },
  util = {},
}

function utf8:require(name)
  local full_module_path = module_path .. name
  if package.loaded[full_module_path] then
    return package.loaded[full_module_path]
  end

  local mod = require(full_module_path)
  if type(mod) == 'function' then
    mod = mod(self)
    package.loaded[full_module_path] = mod
  end
  return mod
end

function utf8:init()
  for k, v in pairs(self.default) do
    self.config[k] = self.config[k] or v
  end

  self:require "util"
  self:require "primitives.init"
  self:require "functions.lua53"

  return self
end

return utf8