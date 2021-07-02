local sources = {}

sources["utf8string.functions.lua53"] = [=[return function(utf8)

local utf8sub = utf8.sub
local utf8gensub = utf8.gensub
local unpack = utf8.config.unpack
local generate_matcher_function = utf8:require 'regex_parser'

function get_matcher_function(regex, plain)
  local res
  if utf8.config.cache then
    res = utf8.config.cache[plain and "plain" or "regex"][regex]
  end
  if res then
    return res
  end
  res = generate_matcher_function(regex, plain)
  if utf8.config.cache then
    utf8.config.cache[plain and "plain" or "regex"][regex] = res
  end
  return res
end

local function utf8find(str, regex, init, plain)
  local func = get_matcher_function(regex, plain)
  init = ((init or 1) < 0) and (utf8.len(str) + init + 1) or init
  local ctx, result, captures = func(str, init, utf8)
  if not ctx then return nil end

  utf8.debug('ctx:', ctx)
  utf8.debug('result:', result)
  utf8.debug('captures:', captures)

  return result.start, result.finish, unpack(captures)
end

local function utf8match(str, regex, init)
  local func = get_matcher_function(regex, false)
  init = ((init or 1) < 0) and (utf8.len(str) + init + 1) or init
  local ctx, result, captures = func(str, init, utf8)
  if not ctx then return nil end

  utf8.debug('ctx:', ctx)
  utf8.debug('result:', result)
  utf8.debug('captures:', captures)

  if #captures > 0 then return unpack(captures) end

  return utf8sub(str, result.start, result.finish)
end

local function utf8gmatch(str, regex)
  regex = (utf8sub(regex,1,1) ~= '^') and regex or '%' .. regex
  local func = get_matcher_function(regex, false)
  local ctx, result, captures
  local continue_pos = 1

  return function()
    ctx, result, captures = func(str, continue_pos, utf8)

    if not ctx then return nil end

    utf8.debug('ctx:', ctx)
    utf8.debug('result:', result)
    utf8.debug('captures:', captures)

    continue_pos = math.max(result.finish + 1, result.start + 1)
    if #captures > 0 then
      return unpack(captures)
    else
      return utf8sub(str, result.start, result.finish)
    end
  end
end

local function replace(repl, args)
  local ret = ''
  if type(repl) == 'string' then
    local ignore = false
    local num
    for _, c in utf8gensub(repl) do
      if not ignore then
        if c == '%' then
          ignore = true
        else
          ret = ret .. c
        end
      else
        num = tonumber(c)
        if num then
          ret = ret .. assert(args[num], "invalid capture index %" .. c)
        else
          ret = ret .. c
        end
        ignore = false
      end
    end
  elseif type(repl) == 'table' then
    ret = repl[args[1]] or args[0]
  elseif type(repl) == 'function' then
    ret = repl(unpack(args, 1)) or args[0]
  end
  return ret
end

local function utf8gsub(str, regex, repl, limit)
  limit = limit or -1
  local subbed = ''
  local prev_sub_finish = 1

  local func = get_matcher_function(regex, false)
  local ctx, result, captures
  local continue_pos = 1

  local n = 0
  while limit ~= n do
    ctx, result, captures = func(str, continue_pos, utf8)
    if not ctx then break end

    utf8.debug('ctx:', ctx)
    utf8.debug('result:', result)
    utf8.debug('result:', utf8sub(str, result.start, result.finish))
    utf8.debug('captures:', captures)

    continue_pos = math.max(result.finish + 1, result.start + 1)
    local args
    if #captures > 0 then
      args = {[0] = utf8sub(str, result.start, result.finish), unpack(captures)}
    else
      args = {[0] = utf8sub(str, result.start, result.finish)}
      args[1] = args[0]
    end

    subbed = subbed .. utf8sub(str, prev_sub_finish, result.start - 1)
    subbed = subbed .. replace(repl, args)
    prev_sub_finish = result.finish + 1
    n = n + 1

  end

  return subbed .. utf8sub(str, prev_sub_finish), n
end

-- attaching high-level functions
utf8.find    = utf8find
utf8.match   = utf8match
utf8.gmatch  = utf8gmatch
utf8.gsub    = utf8gsub

return utf8

end
]=]

sources["utf8string.primitives.dummy"] = [=[-- $Id: utf8.lua 179 2009-04-03 18:10:03Z pasta $
--
-- Provides UTF-8 aware string functions implemented in pure lua:
-- * utf8len(s)
-- * utf8sub(s, i, j)
-- * utf8reverse(s)
-- * utf8char(unicode)
-- * utf8unicode(s, i, j)
-- * utf8gensub(s, sub_len)
-- * utf8find(str, regex, init, plain)
-- * utf8match(str, regex, init)
-- * utf8gmatch(str, regex, all)
-- * utf8gsub(str, regex, repl, limit)
--
-- If utf8data.lua (containing the lower<->upper case mappings) is loaded, these
-- additional functions are available:
-- * utf8upper(s)
-- * utf8lower(s)
--
-- All functions behave as their non UTF-8 aware counterparts with the exception
-- that UTF-8 characters are used instead of bytes for all units.

--[[
Copyright (c) 2006-2007, Kyle Smith
All rights reserved.

Contributors:
	Alimov Stepan

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the author nor the names of its contributors may be
      used to endorse or promote products derived from this software without
      specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
--]]

-- ABNF from RFC 3629
--
-- UTF8-octets = *( UTF8-char )
-- UTF8-char   = UTF8-1 / UTF8-2 / UTF8-3 / UTF8-4
-- UTF8-1      = %x00-7F
-- UTF8-2      = %xC2-DF UTF8-tail
-- UTF8-3      = %xE0 %xA0-BF UTF8-tail / %xE1-EC 2( UTF8-tail ) /
--               %xED %x80-9F UTF8-tail / %xEE-EF 2( UTF8-tail )
-- UTF8-4      = %xF0 %x90-BF 2( UTF8-tail ) / %xF1-F3 3( UTF8-tail ) /
--               %xF4 %x80-8F 2( UTF8-tail )
-- UTF8-tail   = %x80-BF
--
return function(utf8)

local byte    = string.byte
local char    = string.char
local dump    = string.dump
local find    = string.find
local format  = string.format
local len     = string.len
local lower   = string.lower
local rep     = string.rep
local sub     = string.sub
local upper   = string.upper

local function utf8symbollen(byte)
  return not byte and 0 or (byte < 0x80 and 1) or (byte >= 0xF0 and 4) or (byte >= 0xE0 and 3) or (byte >= 0xC0 and 2) or 1
end

local head_table = utf8.config.int32array(256)
for i = 0, 255 do
  head_table[i] = utf8symbollen(i)
end
head_table[256] = 0

local function utf8charbytes(str, bs)
  return head_table[byte(str, bs) or 256]
end

local function utf8next(str, bs)
  return bs + utf8charbytes(str, bs)
end

-- returns the number of characters in a UTF-8 string
local function utf8len (str)
  local bs = 1
  local bytes = len(str)
  local length = 0

  while bs <= bytes do
    length = length + 1
    bs = utf8next(str, bs)
  end

  return length
end

-- functions identically to string.sub except that i and j are UTF-8 characters
-- instead of bytes
local function utf8sub (s, i, j)
  -- argument defaults
  j = j or -1

  local bs = 1
  local bytes = len(s)
  local length = 0

  local l = (i >= 0 and j >= 0) or utf8len(s)
  i = (i >= 0) and i or l + i + 1
  j = (j >= 0) and j or l + j + 1

  if i > j then
    return ""
  end

  local start, finish = 1, bytes

  while bs <= bytes do
    length = length + 1

    if length == i then
      start = bs
    end

    bs = utf8next(s, bs)

    if length == j then
      finish = bs - 1
      break
    end
  end

  if i > length then start = bytes + 1 end
  if j < 1 then finish = 0 end

  return sub(s, start, finish)
end

-- http://en.wikipedia.org/wiki/Utf8
-- http://developer.coronalabs.com/code/utf-8-conversion-utility
local function utf8char(...)
  local codes = {...}
  local result = {}

  for _, unicode in ipairs(codes) do

    if unicode <= 0x7F then
      result[#result + 1] = unicode
    elseif unicode <= 0x7FF then
      local b0 = 0xC0 + math.floor(unicode / 0x40);
      local b1 = 0x80 + (unicode % 0x40);
      result[#result + 1] = b0
      result[#result + 1] = b1
    elseif unicode <= 0xFFFF then
      local b0 = 0xE0 +  math.floor(unicode / 0x1000);
      local b1 = 0x80 + (math.floor(unicode / 0x40) % 0x40);
      local b2 = 0x80 + (unicode % 0x40);
      result[#result + 1] = b0
      result[#result + 1] = b1
      result[#result + 1] = b2
    elseif unicode <= 0x10FFFF then
      local code = unicode
      local b3= 0x80 + (code % 0x40);
      code       = math.floor(code / 0x40)
      local b2= 0x80 + (code % 0x40);
      code       = math.floor(code / 0x40)
      local b1= 0x80 + (code % 0x40);
      code       = math.floor(code / 0x40)
      local b0= 0xF0 + code;

      result[#result + 1] = b0
      result[#result + 1] = b1
      result[#result + 1] = b2
      result[#result + 1] = b3
    else
      error 'Unicode cannot be greater than U+10FFFF!'
    end

  end

  return char(utf8.config.unpack(result))
end


local shift_6  = 2^6
local shift_12 = 2^12
local shift_18 = 2^18

local utf8unicode
utf8unicode = function(str, ibs, jbs)
  if ibs > jbs then return end

  local ch,bytes

  bytes = utf8charbytes(str, ibs)
  if bytes == 0 then return end

  local unicode

  if bytes == 1 then unicode = byte(str, ibs, ibs) end
  if bytes == 2 then
    local byte0,byte1 = byte(str, ibs, ibs + 1)
    if byte0 and byte1 then
      local code0,code1 = byte0-0xC0,byte1-0x80
      unicode = code0*shift_6 + code1
    else
      unicode = byte0
    end
  end
  if bytes == 3 then
    local byte0,byte1,byte2 = byte(str, ibs, ibs + 2)
    if byte0 and byte1 and byte2 then
      local code0,code1,code2 = byte0-0xE0,byte1-0x80,byte2-0x80
      unicode = code0*shift_12 + code1*shift_6 + code2
    else
      unicode = byte0
    end
  end
  if bytes == 4 then
    local byte0,byte1,byte2,byte3 = byte(str, ibs, ibs + 3)
    if byte0 and byte1 and byte2 and byte3 then
      local code0,code1,code2,code3 = byte0-0xF0,byte1-0x80,byte2-0x80,byte3-0x80
      unicode = code0*shift_18 + code1*shift_12 + code2*shift_6 + code3
    else
      unicode = byte0
    end
  end

  if ibs == jbs then
    return unicode
  else
    return unicode,utf8unicode(str, ibs+bytes, jbs)
  end
end

local function utf8byte(str, i, j)
  if #str == 0 then return end

  local ibs, jbs

  if i or j then
    i = i or 1
    j = j or i

    local str_len = utf8len(str)
    i = i < 0 and str_len + i + 1 or i
    j = j < 0 and str_len + j + 1 or j
    j = j > str_len and str_len or j

    if i > j then return end

    for p = 1, i - 1 do
      ibs = utf8next(str, ibs or 1)
    end

    if i == j then
      jbs = ibs
    else
      for p = 1, j - 1 do
        jbs = utf8next(str, jbs or 1)
      end
    end

    if not ibs or not jbs then
      return nil
    end
  else
    ibs, jbs = 1, 1
  end

  return utf8unicode(str, ibs, jbs)
end

local function utf8gensub(str, sub_len)
  sub_len = sub_len or 1
  local max_len = #str
  return function(skip_ptr, bs)
    bs = (bs and bs or 1) + (skip_ptr and (skip_ptr[1] or 0) or 0)

    local nbs = bs
    if bs > max_len then return nil end
    for i = 1, sub_len do
      nbs = utf8next(str, nbs)
    end

    return nbs, sub(str, bs, nbs - 1), bs
  end
end

local function utf8reverse (s)
  local result = ''
  for _, w in utf8gensub(s) do result = w .. result end
  return result
end

local function utf8validator(str, bs)
  bs = bs or 1

  if type(str) ~= "string" then
    error("bad argument #1 to 'utf8charbytes' (string expected, got ".. type(str).. ")")
  end
  if type(bs) ~= "number" then
    error("bad argument #2 to 'utf8charbytes' (number expected, got ".. type(bs).. ")")
  end

  local c = byte(str, bs)
  if not c then return end

  -- determine bytes needed for character, based on RFC 3629

  -- UTF8-1
  if c >= 0 and c <= 127 then
    return bs + 1
  elseif c >= 128 and c <= 193 then
    return bs + 1, bs, 1, c
      -- UTF8-2
  elseif c >= 194 and c <= 223 then
    local c2 = byte(str, bs + 1)
    if not c2 or c2 < 128 or c2 > 191 then
      return bs + 2, bs, 2, c2
    end

    return bs + 2
      -- UTF8-3
  elseif c >= 224 and c <= 239 then
    local c2 = byte(str, bs + 1)

    if not c2 then
      return bs + 2, bs, 2, c2
    end

    -- validate byte 2
    if c == 224 and (c2 < 160 or c2 > 191) then
      return bs + 2, bs, 2, c2
    elseif c == 237 and (c2 < 128 or c2 > 159) then
      return bs + 2, bs, 2, c2
    elseif c2 < 128 or c2 > 191 then
      return bs + 2, bs, 2, c2
    end

    local c3 = byte(str, bs + 2)
    if not c3 or c3 < 128 or c3 > 191 then
      return bs + 3, bs, 3, c3
    end

    return bs + 3
      -- UTF8-4
  elseif c >= 240 and c <= 244 then
    local c2 = byte(str, bs + 1)

    if not c2 then
      return bs + 2, bs, 2, c2
    end

    -- validate byte 2
    if c == 240 and (c2 < 144 or c2 > 191) then
      return bs + 2, bs, 2, c2
    elseif c == 244 and (c2 < 128 or c2 > 143) then
      return bs + 2, bs, 2, c2
    elseif c2 < 128 or c2 > 191 then
      return bs + 2, bs, 2, c2
    end

    local c3 = byte(str, bs + 2)
    if not c3 or c3 < 128 or c3 > 191 then
      return bs + 3, bs, 3, c3
    end

    local c4 = byte(str, bs + 3)
    if not c4 or c4 < 128 or c4 > 191 then
      return bs + 4, bs, 4, c4
    end

    return bs + 4
  else -- c > 245
    return bs + 1, bs, 1, c
  end
end

local function utf8validate(str, byte_pos)
  local result = {}
  for nbs, bs, part, code in utf8validator, str, byte_pos do
    if bs then
      result[#result + 1] = { pos = bs, part = part, code = code }
    end
  end
  return #result == 0, result
end

local function utf8codes(str)
  local max_len = #str
  local bs = 1
  return function(skip_ptr)
    if bs > max_len then return nil end
    local pbs = bs
    bs = utf8next(str, pbs)

    return pbs, utf8unicode(str, pbs, pbs), pbs
  end
end


--[[--
differs from Lua 5.3 utf8.offset in accepting any byte positions (not only head byte) for all n values

h - head, c - continuation, t - tail
hhhccthccthccthcthhh
        ^ start byte pos
searching current charracter head by moving backwards
hhhccthccthccthcthhh
      ^ head

n == 0: current position
n > 0: n jumps forward
n < 0: n more scans backwards
--]]--
local function utf8offset(str, n, bs)
  local l = #str
  if not bs then
    if n < 0 then
      bs = l + 1
    else
      bs = 1
    end
  end
  if bs <= 0 or bs > l + 1 then
    error("bad argument #3 to 'offset' (position out of range)")
  end

  if n == 0 then
    if bs == l + 1 then
      return bs
    end
    while true do
      local b = byte(str, bs)
      if (0 < b and b < 127)
      or (194 < b and b < 244) then
        return bs
      end
      bs = bs - 1
      if bs < 1 then
        return
      end
    end
  elseif n < 0 then
    bs = bs - 1
    repeat
      if bs < 1 then
        return
      end

      local b = byte(str, bs)
      if (0 < b and b < 127)
      or (194 < b and b < 244) then
        n = n + 1
      end
      bs = bs - 1
    until n == 0
    return bs + 1
  else
    while true do
      if bs > l then
        return
      end

      local b = byte(str, bs)
      if (0 < b and b < 127)
      or (194 < b and b < 244) then
        n = n - 1
        for i = 1, n do
          if bs > l then
            return
          end
          bs = utf8next(str, bs)
        end
        return bs
      end
      bs = bs - 1
    end
  end

end

utf8.len       = utf8len
utf8.sub       = utf8sub
utf8.reverse   = utf8reverse
utf8.char      = utf8char
utf8.unicode   = utf8unicode
utf8.byte      = utf8byte
utf8.next      = utf8next
utf8.gensub    = utf8gensub
utf8.validator = utf8validator
utf8.validate  = utf8validate
utf8.dump      = dump
utf8.format    = format
utf8.lower     = lower
utf8.upper     = upper
utf8.rep       = rep
utf8.raw = {}
for k,v in pairs(string) do
  utf8.raw[k] = v
end

utf8.charpattern = '[\0-\127\194-\244][\128-\191]*'
utf8.offset = utf8offset
if _VERSION == 'Lua 5.3' then
  local utf8_53 = require "utf8"
  utf8.codes = utf8_53.codes
  utf8.codepoint = utf8_53.codepoint
  utf8.len53 = utf8_53.len
else
  utf8.codes = utf8codes
  utf8.codepoint = utf8unicode
end

return utf8

end
]=]

sources["utf8string.primitives.init"] = [[return function(utf8)

local provided = utf8.config.primitives

if provided then
  if type(provided) == "table" then
    return provided
  elseif type(provided) == "function" then
    return provided(utf8)
  else
    return utf8:require(provided)
  end
end

if pcall(require, "tarantool") then
  return utf8:require "primitives.tarantool"
elseif pcall(require, "ffi") then
  return utf8:require "primitives.native"
else
  return utf8:require "primitives.dummy"
end

end
]]

sources["utf8string.primitives.native"] = [=[return function(utf8)

  local ffi = require("ffi")
  if ffi.os == "Windows" then
    os.setlocale(utf8.config.locale or "english_us.65001", "ctype")
    ffi.cdef[[
      short towupper(short c);
      short towlower(short c);
    ]]
  else
    os.setlocale(utf8.config.locale or "C.UTF-8", "ctype")
    ffi.cdef[[
      int towupper(int c);
      int towlower(int c);
    ]]
  end

utf8:require "primitives.dummy"

function utf8.lower(str)
  local bs = 1
  local nbs
  local bytes = utf8.raw.len(str)
  local res = {}

  while bs <= bytes do
    nbs = utf8.next(str, bs)
    local cp = utf8.unicode(str, bs, nbs)
    res[#res + 1] = ffi.C.towlower(cp)
    bs = nbs
  end

  return utf8.char(utf8.config.unpack(res))
end

function utf8.upper(str)
  local bs = 1
  local nbs
  local bytes = utf8.raw.len(str)
  local res = {}

  while bs <= bytes do
    nbs = utf8.next(str, bs)
    local cp = utf8.unicode(str, bs, nbs)
    res[#res + 1] = ffi.C.towupper(cp)
    bs = nbs
  end

  return utf8.char(utf8.config.unpack(res))
end

return utf8
end
]=]

sources["utf8string.primitives.tarantool"] = [[return function(utf8)

utf8:require "primitives.dummy"

local tnt_utf8 = utf8.config.tarantool_utf8 or require("utf8")

utf8.lower = tnt_utf8.lower
utf8.upper = tnt_utf8.upper
utf8.len = tnt_utf8.len
utf8.char = tnt_utf8.char

return utf8
end
]]

sources["utf8string.util"] = [[return function(utf8)

function utf8.util.copy(obj, deep)
  if type(obj) == 'table' then
    local result = {}
    if deep then
      for k,v in pairs(obj) do
        result[k] = utf8.util.copy(v, true)
      end
    else
      for k,v in pairs(obj) do
        result[k] = v
      end
    end
    return result
  else
    return obj
  end
end

local function dump(val, tab)
  tab = tab or ''

  if type(val) == 'table' then
    utf8.config.logger('{\n')
    for k,v in pairs(val) do
      utf8.config.logger(tab .. tostring(k) .. " = ")
      dump(v, tab .. '\t')
      utf8.config.logger("\n")
    end
    utf8.config.logger(tab .. '}\n')
  else
    utf8.config.logger(tostring(val))
  end
end

function utf8.util.debug(...)
  local t = {...}
  for _, v in ipairs(t) do
    if type(v) == "table" and not (getmetatable(v) or {}).__tostring then
      dump(v, '\t')
    else
      utf8.config.logger(tostring(v), " ")
    end
  end

  utf8.config.logger('\n')
end

function utf8.debug(...)
  if utf8.config.debug then
    utf8.config.debug(...)
  end
end

function utf8.util.next(str, bs)
  local nbs1 = utf8.next(str, bs)
  local nbs2 = utf8.next(str, nbs1)
  return utf8.raw.sub(str, nbs1, nbs2 - 1), nbs1
end

return utf8.util

end
]]

sources["utf8string.begins.compiletime.parser"] = [[return function(utf8)

utf8.config.begins = utf8.config.begins or {
  utf8:require "begins.compiletime.vanilla"
}

function utf8.regex.compiletime.begins.parse(regex, c, bs, ctx)
  for _, m in ipairs(utf8.config.begins) do
    local functions, move = m.parse(regex, c, bs, ctx)
    utf8.debug("begins", _, c, bs, move, functions)
    if functions then
      return functions, move
    end
  end
end

end
]]

sources["utf8string.begins.compiletime.vanilla"] = [=[return function(utf8)

local matchers = {
  sliding = function()
    return [[
    add(function(ctx) -- sliding
      while ctx.pos <= ctx.len do
        local clone = ctx:clone()
        -- debug('starting from', clone, "start_pos", clone.pos)
        clone.result.start = clone.pos
        clone:next_function()
        clone:get_function()(clone)

        ctx:next_char()
      end
      ctx:terminate()
    end)
]]
  end,
  fromstart = function(ctx)
    return [[
    add(function(ctx) -- fromstart
        if ctx.byte_pos > ctx.len then
          return
        end
        ctx.result.start = ctx.pos
        ctx:next_function()
        ctx:get_function()(ctx)
        ctx:terminate()
    end)
]]
  end,
}

local function default()
  return matchers.sliding()
end

local function parse(regex, c, bs, ctx)
  if bs ~= 1 then return end

  local functions
  local skip = 0

  if c == '^' then
    functions = matchers.fromstart()
    skip = 1
  else
    functions = matchers.sliding()
  end

  return functions, skip
end

return {
  parse = parse,
  default = default,
}

end
]=]

sources["utf8string.charclass.compiletime.builder"] = [=[return function(utf8)

local byte = utf8.byte
local unpack = utf8.config.unpack

local builder = {}
local mt = {__index = builder}

utf8.regex.compiletime.charclass.builder = builder

function builder.new()
  return setmetatable({}, mt)
end

function builder:invert()
  self.inverted = true
  return self
end

function builder:internal() -- is it enclosed in []
  self.internal = true
  return self
end

function builder:with_codes(...)
  local codes = {...}
  self.codes = self.codes or {}

  for _, v in ipairs(codes) do
    table.insert(self.codes, type(v) == "number" and v or byte(v))
  end

  table.sort(self.codes)
  return self
end

function builder:with_ranges(...)
  local ranges = {...}
  self.ranges = self.ranges or {}

  for _, v in ipairs(ranges) do
    table.insert(self.ranges, v)
  end

  return self
end

function builder:with_classes(...)
  local classes = {...}
  self.classes = self.classes or {}

  for _, v in ipairs(classes) do
    table.insert(self.classes, v)
  end

  return self
end

function builder:without_classes(...)
  local not_classes = {...}
  self.not_classes = self.not_classes or {}

  for _, v in ipairs(not_classes) do
    table.insert(self.not_classes, v)
  end

  return self
end

function builder:include(b)
  if not b.inverted then
    if b.codes then
      self:with_codes(unpack(b.codes))
    end
    if b.ranges then
      self:with_ranges(unpack(b.ranges))
    end
    if b.classes then
      self:with_classes(unpack(b.classes))
    end
    if b.not_classes then
      self:without_classes(unpack(b.not_classes))
    end
  else
    self.includes = self.includes or {}
    self.includes[#self.includes + 1] = b
  end
  return self
end

function builder:build()
  if self.codes and #self.codes == 1 and not self.inverted and not self.ranges and not self.classes and not self.not_classes and not self.includes then
    return "{test = function(self, cc) return cc == " .. self.codes[1] .. " end}"
  else
    local codes_list = table.concat(self.codes or {}, ', ')
    local ranges_list = ''
    for i, r in ipairs(self.ranges or {}) do ranges_list = ranges_list .. (i > 1 and ', {' or '{') .. tostring(r[1]) .. ', ' .. tostring(r[2]) .. '}' end
    local classes_list = ''
    if self.classes then classes_list = "'" .. table.concat(self.classes, "', '") .. "'" end
    local not_classes_list = ''
    if self.not_classes then not_classes_list = "'" .. table.concat(self.not_classes, "', '") .. "'" end

    local subs_list = ''
    for i, r in ipairs(self.includes or {}) do subs_list = subs_list .. (i > 1 and ', ' or '') .. r:build() .. '' end

    local src = [[cl.new():with_codes(
        ]] .. codes_list .. [[
      ):with_ranges(
        ]] .. ranges_list .. [[
      ):with_classes(
        ]] .. classes_list .. [[
      ):without_classes(
        ]] .. not_classes_list .. [[
      ):with_subs(
        ]] .. subs_list .. [[
      )]]

    if self.inverted then
      src = src .. ':invert()'
    end

    return src
  end
end

return builder

end
]=]

sources["utf8string.charclass.compiletime.parser"] = [[return function(utf8)

utf8.config.compiletime_charclasses = utf8.config.compiletime_charclasses or {
  utf8:require "charclass.compiletime.vanilla",
  utf8:require "charclass.compiletime.range",
  utf8:require "charclass.compiletime.stub",
}

function utf8.regex.compiletime.charclass.parse(regex, c, bs, ctx)
  utf8.debug("parse charclass():", regex, c, bs, regex[bs])
  for _, p in ipairs(utf8.config.compiletime_charclasses) do
    local charclass, nbs = p(regex, c, bs, ctx)
    if charclass then
      ctx.prev_class = charclass:build()
      utf8.debug("cc", ctx.prev_class, _, c, bs, nbs)
      return charclass, nbs
    end
  end
end

end
]]

sources["utf8string.charclass.compiletime.range"] = [[return function(utf8)

local cl = utf8.regex.compiletime.charclass.builder

local next = utf8.util.next

return function(str, c, bs, ctx)
  if not ctx.internal then return end

  local nbs = bs

  local r1, r2

  local c, nbs = c, bs
  if c == '%' then
    c, nbs = next(str, nbs)
    r1 = c
  else
    r1 = c
  end

  utf8.debug("range r1", r1, nbs)

  c, nbs = next(str, nbs)
  if c ~= '-' then return end

  c, nbs = next(str, nbs)
  if c == '%' then
    c, nbs = next(str, nbs)
    r2 = c
  elseif c ~= '' and c ~= ']' then
    r2 = c
  end

  utf8.debug("range r2", r2, nbs)

  if r1 and r2 then
    return cl.new():with_ranges{utf8.byte(r1), utf8.byte(r2)}, utf8.next(str, nbs) - bs
  else
    return
  end
end

end
]]

sources["utf8string.charclass.compiletime.stub"] = [[return function(utf8)

local cl = utf8.regex.compiletime.charclass.builder

return function(str, c, bs, ctx)
  return cl.new():with_codes(c), utf8.next(str, bs) - bs
end

end
]]

sources["utf8string.charclass.compiletime.vanilla"] = [=[return function(utf8)

local cl = utf8:require "charclass.compiletime.builder"

local next = utf8.util.next

local token = 1

local function parse(str, c, bs, ctx)
  local tttt = token
  token = token + 1

  local class
  local nbs = bs
  utf8.debug("cc_parse", tttt, str, c, nbs, next(str, nbs))

  if c == '%' then
    c, nbs = next(str, bs)
    if c == '' then
      error("malformed pattern (ends with '%')")
    end
    local _c = utf8.raw.lower(c)
    local matched
    if _c == 'a' then
      matched = ('alpha')
    elseif _c == 'c' then
      matched = ('cntrl')
    elseif _c == 'd' then
      matched = ('digit')
    elseif _c == 'g' then
      matched = ('graph')
    elseif _c == 'l' then
      matched = ('lower')
    elseif _c == 'p' then
      matched = ('punct')
    elseif _c == 's' then
      matched = ('space')
    elseif _c == 'u' then
      matched = ('upper')
    elseif _c == 'w' then
      matched = ('alnum')
    elseif _c == 'x' then
      matched = ('xdigit')
    end

    if matched then
      if _c ~= c then
        class = cl.new():without_classes(matched)
      else
        class = cl.new():with_classes(matched)
      end
    elseif _c == 'z' then
      class = cl.new():with_codes(0)
      if _c ~= c then
        class = class:invert()
      end
    else
      class = cl.new():with_codes(c)
    end
  elseif c == '[' and not ctx.internal then
    local old_internal = ctx.internal
    ctx.internal = true
    class = cl.new()
    local firstletter = true
    while true do
      local prev_nbs = nbs
      c, nbs = next(str, nbs)
      utf8.debug("next", tttt, c, nbs)
      if c == '^' and firstletter then
        class:invert()
        local nc, nnbs = next(str, nbs)
        if nc == ']' then
          class:with_codes(nc)
          nbs = nnbs
        end
      elseif c == ']' then
        if firstletter then
          class:with_codes(c)
        else
          utf8.debug('] on pos', tttt, nbs)
          break
        end
      elseif c == '' then
        error "malformed pattern (missing ']')"
      else
        local sub_class, skip = utf8.regex.compiletime.charclass.parse(str, c, nbs, ctx)
        nbs = prev_nbs + skip
        utf8.debug("include", tttt, bs, prev_nbs, nbs, skip)
        class:include(sub_class)
      end
      firstletter = false
    end
    ctx.internal = old_internal
  elseif c == '.' then
    if not ctx.internal then
      class = cl.new():invert()
    else
      class = cl.new():with_codes(c)
    end
  end

  return class, utf8.next(str, nbs) - bs
end

return parse

end

--[[
    x: (where x is not one of the magic characters ^$()%.[]*+-?) represents the character x itself.
    .: (a dot) represents all characters.
    %a: represents all letters.
    %c: represents all control characters.
    %d: represents all digits.
    %g: represents all printable characters except space.
    %l: represents all lowercase letters.
    %p: represents all punctuation characters.
    %s: represents all space characters.
    %u: represents all uppercase letters.
    %w: represents all alphanumeric characters.
    %x: represents all hexadecimal digits.
    %x: (where x is any non-alphanumeric character) represents the character x. This is the standard way to escape the magic characters. Any non-alphanumeric character (including all punctuation characters, even the non-magical) can be preceded by a '%' when used to represent itself in a pattern.
    [set]: represents the class which is the union of all characters in set. A range of characters can be specified by separating the end characters of the range, in ascending order, with a '-'. All classes %x described above can also be used as components in set. All other characters in set represent themselves. For example, [%w_] (or [_%w]) represents all alphanumeric characters plus the underscore, [0-7] represents the octal digits, and [0-7%l%-] represents the octal digits plus the lowercase letters plus the '-' character.

    You can put a closing square bracket in a set by positioning it as the first character in the set. You can put a hyphen in a set by positioning it as the first or the last character in the set. (You can also use an escape for both cases.)

    The interaction between ranges and classes is not defined. Therefore, patterns like [%a-z] or [a-%%] have no meaning.
    [^set]: represents the complement of set, where set is interpreted as above.

For all classes represented by single letters (%a, %c, etc.), the corresponding uppercase letter represents the complement of the class. For instance, %S represents all non-space characters.
]]
]=]

sources["utf8string.charclass.runtime.base"] = [[return function(utf8)

local class = {}
local mt = {__index = class}

local utf8gensub = utf8.gensub

function class.new()
  return setmetatable({}, mt)
end

function class:invert()
  self.inverted = true
  return self
end

function class:with_codes(...)
  local codes = {...}
  self.codes = self.codes or {}

  for _, v in ipairs(codes) do
    table.insert(self.codes, v)
  end

  table.sort(self.codes)
  return self
end

function class:with_ranges(...)
  local ranges = {...}
  self.ranges = self.ranges or {}

  for _, v in ipairs(ranges) do
    table.insert(self.ranges, v)
  end

  return self
end

function class:with_classes(...)
  local classes = {...}
  self.classes = self.classes or {}

  for _, v in ipairs(classes) do
    table.insert(self.classes, v)
  end

  return self
end

function class:without_classes(...)
  local not_classes = {...}
  self.not_classes = self.not_classes or {}

  for _, v in ipairs(not_classes) do
    table.insert(self.not_classes, v)
  end

  return self
end

function class:with_subs(...)
  local subs = {...}
  self.subs = self.subs or {}

  for _, v in ipairs(subs) do
    table.insert(self.subs, v)
  end

  return self
end

function class:in_codes(item)
  if not self.codes or #self.codes == 0 then return nil end

  local head, tail = 1, #self.codes
  local mid = math.floor((head + tail)/2)
  while (tail - head) > 1 do
    if self.codes[mid] > item then
      tail = mid
    else
      head = mid
    end
    mid = math.floor((head + tail)/2)
  end
  if self.codes[head] == item then
    return true, head
  elseif self.codes[tail] == item then
    return true, tail
  else
    return false
  end
end

function class:in_ranges(char_code)
  if not self.ranges or #self.ranges == 0 then return nil end

  for _,r in ipairs(self.ranges) do
    if r[1] <= char_code and char_code <= r[2] then
      return true
    end
  end
  return false
end

function class:in_classes(char_code)
  if not self.classes or #self.classes == 0 then return nil end

  for _, class in ipairs(self.classes) do
    if self:is(class, char_code) then
      return true
    end
  end
  return false
end

function class:in_not_classes(char_code)
  if not self.not_classes or #self.not_classes == 0 then return nil end

  for _, class in ipairs(self.not_classes) do
    if self:is(class, char_code) then
      return true
    end
  end
  return false
end

function class:is(class, char_code)
  error("not implemented")
end

function class:in_subs(char_code)
  if not self.subs or #self.subs == 0 then return nil end

  for _, c in ipairs(self.subs) do
    if not c:test(char_code) then
      return false
    end
  end
  return true
end

function class:test(char_code)
  local result = self:do_test(char_code)
  -- utf8.debug('class:test', result, "'" .. (char_code and utf8.char(char_code) or 'nil') .. "'", char_code)
  return result
end

function class:do_test(char_code)
  if not char_code then return false end
  local in_not_classes = self:in_not_classes(char_code)
  if in_not_classes then
    return not not self.inverted
  end
  local in_codes = self:in_codes(char_code)
  if in_codes then
    return not self.inverted
  end
  local in_ranges = self:in_ranges(char_code)
  if in_ranges then
    return not self.inverted
  end
  local in_classes = self:in_classes(char_code)
  if in_classes then
    return not self.inverted
  end
  local in_subs = self:in_subs(char_code)
  if in_subs then
    return not self.inverted
  end
  if (in_codes == nil)
  and (in_ranges == nil)
  and (in_classes == nil)
  and (in_subs == nil)
  and (in_not_classes == false) then
    return not self.inverted
  else
    return not not self.inverted
  end
end

return class

end
]]

sources["utf8string.charclass.runtime.dummy"] = [[return function(utf8)

local base = utf8:require "charclass.runtime.base"

local dummy = setmetatable({}, {__index = base})
local mt = {__index = dummy}

function dummy.new()
  return setmetatable({}, mt)
end

function dummy:with_classes(...)
  local classes = {...}
  for _, c in ipairs(classes) do
    if c == 'alpha' then self:with_ranges({65, 90}, {97, 122})
    elseif c == 'cntrl' then self:with_ranges({0, 31}):with_codes(127)
    elseif c == 'digit' then self:with_ranges({48, 57})
    elseif c == 'graph' then self:with_ranges({1, 8}, {14, 31}, {33, 132}, {134, 159}, {161, 5759}, {5761, 8191}, {8203, 8231}, {8234, 8238}, {8240, 8286}, {8288, 12287})
    elseif c == 'lower' then self:with_ranges({97, 122})
    elseif c == 'punct' then self:with_ranges({33, 47}, {58, 64}, {91, 96}, {123, 126})
    elseif c == 'space' then self:with_ranges({9, 13}):with_codes(32, 133, 160, 5760):with_ranges({8192, 8202}):with_codes(8232, 8233, 8239, 8287, 12288)
    elseif c == 'upper' then self:with_ranges({65, 90})
    elseif c == 'alnum' then self:with_ranges({48, 57}, {65, 90}, {97, 122})
    elseif c == 'xdigit' then self:with_ranges({48, 57}, {65, 70}, {97, 102})
    end
  end
  return self
end

function dummy:without_classes(...)
  local classes = {...}
  if #classes > 0 then
    return self:with_subs(dummy.new():with_classes(...):invert())
  else
    return self
  end
end

return dummy

end
]]

sources["utf8string.charclass.runtime.init"] = [[return function(utf8)

local provided = utf8.config.runtime_charclasses

if provided then
  if type(provided) == "table" then
    return provided
  elseif type(provided) == "function" then
    return provided(utf8)
  else
    return utf8:require(provided)
  end
end

local ffi = pcall(require, "ffi")
if not ffi then
  return utf8:require "charclass.runtime.dummy"
else
  return utf8:require "charclass.runtime.native"
end

end
]]

sources["utf8string.charclass.runtime.native"] = [=[return function(utf8)

os.setlocale(utf8.config.locale, "ctype")

local ffi = require("ffi")
ffi.cdef[[
  int iswalnum(int c);
  int iswalpha(int c);
  int iswascii(int c);
  int iswblank(int c);
  int iswcntrl(int c);
  int iswdigit(int c);
  int iswgraph(int c);
  int iswlower(int c);
  int iswprint(int c);
  int iswpunct(int c);
  int iswspace(int c);
  int iswupper(int c);
  int iswxdigit(int c);
]]

local base = utf8:require "charclass.runtime.base"

local native = setmetatable({}, {__index = base})
local mt = {__index = native}

function native.new()
  return setmetatable({}, mt)
end

function native:is(class, char_code)
  if class == 'alpha' then return ffi.C.iswalpha(char_code) ~= 0
  elseif class == 'cntrl' then return ffi.C.iswcntrl(char_code) ~= 0
  elseif class == 'digit' then return ffi.C.iswdigit(char_code) ~= 0
  elseif class == 'graph' then return ffi.C.iswgraph(char_code) ~= 0
  elseif class == 'lower' then return ffi.C.iswlower(char_code) ~= 0
  elseif class == 'punct' then return ffi.C.iswpunct(char_code) ~= 0
  elseif class == 'space' then return ffi.C.iswspace(char_code) ~= 0
  elseif class == 'upper' then return ffi.C.iswupper(char_code) ~= 0
  elseif class == 'alnum' then return ffi.C.iswalnum(char_code) ~= 0
  elseif class == 'xdigit' then return ffi.C.iswxdigit(char_code) ~= 0
  end
end

return native

end
]=]

sources["utf8string.context.compiletime"] = [[return function(utf8)

local begins = utf8.config.begins
local ends = utf8.config.ends

return {
  new = function()
    return {
      prev_class = nil,
      begins = begins[1].default(),
      ends = ends[1].default(),
      funcs = {},
      internal = false, -- hack for ranges, flags if parser is in []
    }
  end
}

end
]]

sources["utf8string.context.runtime"] = [=[return function(utf8)

local utf8unicode = utf8.unicode
local utf8sub = utf8.sub
local sub = utf8.raw.sub
local byte = utf8.raw.byte
local utf8len = utf8.len
local utf8next = utf8.next
local rawgsub = utf8.raw.gsub
local utf8offset = utf8.offset
local utf8char = utf8.char

local util = utf8.util

local ctx = {}
local mt = {
  __index = ctx,
  __tostring = function(self)
    return rawgsub([[str: '${str}', char: ${pos} '${char}', func: ${func_pos}]], "${(.-)}", {
      str = self.str,
      pos = self.pos,
      char = self:get_char(),
      func_pos = self.func_pos,
    })
  end
}

function ctx.new(obj)
  obj = obj or {}
  local res = setmetatable({
    pos = obj.pos or 1,
    byte_pos = obj.pos or 1,
    str = assert(obj.str, "str is required"),
    len = obj.len,
    rawlen = obj.rawlen,
    bytes = obj.bytes,
    offsets = obj.offsets,
    starts = obj.starts or nil,
    functions = obj.functions or {},
    func_pos = obj.func_pos or 1,
    ends = obj.ends or nil,
    result = obj.result and util.copy(obj.result) or {},
    captures = obj.captures and util.copy(obj.captures, true) or {active = {}},
    modified = false,
  }, mt)
  if not res.bytes then
    local str = res.str
    local l = #str
    local bytes = utf8.config.int32array(l)
    local offsets = utf8.config.int32array(l)
    local c, bs, i = nil, 1, 1
    while bs <= l do
      bytes[i] = utf8unicode(str, bs, bs)
      offsets[i] = bs
      bs = utf8.next(str, bs)
      i = i + 1
    end
    res.bytes = bytes
    res.offsets = offsets
    res.byte_pos = res.pos
    res.len = i
    res.rawlen = l
  end

  return res
end

function ctx:clone()
  return self:new()
end

function ctx:next_char()
  self.pos = self.pos + 1
  self.byte_pos = self.pos
end

function ctx:prev_char()
  self.pos = self.pos - 1
  self.byte_pos = self.pos
end

function ctx:get_char()
  if self.len <= self.pos then return "" end
  return utf8char(self.bytes[self.pos])
end

function ctx:get_charcode()
  if self.len <= self.pos then return nil end
  return self.bytes[self.pos]
end

function ctx:next_function()
  self.func_pos = self.func_pos + 1
end

function ctx:get_function()
  return self.functions[self.func_pos]
end

function ctx:done()
  utf8.debug('done', self)
  coroutine.yield(self, self.result, self.captures)
end

function ctx:terminate()
  utf8.debug('terminate', self)
  coroutine.yield(nil)
end

return ctx

end
]=]

sources["utf8string.ends.compiletime.parser"] = [[return function(utf8)

utf8.config.ends = utf8.config.ends or {
  utf8:require "ends.compiletime.vanilla"
}

function utf8.regex.compiletime.ends.parse(regex, c, bs, ctx)
  for _, m in ipairs(utf8.config.ends) do
    local functions, move = m.parse(regex, c, bs, ctx)
    utf8.debug("ends", _, c, bs, move, functions)
    if functions then
      return functions, move
    end
  end
end

end
]]

sources["utf8string.ends.compiletime.vanilla"] = [=[return function(utf8)

local matchers = {
  any = function()
    return [[
  add(function(ctx) -- any
    ctx.result.finish = ctx.pos - 1
    ctx:done()
  end)
]]
  end,
  toend = function(ctx)
    return [[
  add(function(ctx) -- toend
    ctx.result.finish = ctx.pos - 1
    ctx.modified = true
    if ctx.pos == utf8len(ctx.str) + 1 then ctx:done() end
  end)
]]
  end,
}

local len = utf8.raw.len

local function default()
  return matchers.any()
end

local function parse(regex, c, bs, ctx)
  local functions
  local skip = 0

  if bs == len(regex) and c == '$' then
    functions = matchers.toend()
    skip = 1
  end

  return functions, skip
end

return {
  parse = parse,
  default = default,
}

end
]=]

sources["utf8string.modifier.compiletime.frontier"] = [=[return function(utf8)

local matchers = {
  frontier = function(class, name)
    local class_name = 'class' .. name
    return [[
  local ]] .. class_name .. [[ = ]] .. class .. [[

  add(function(ctx) -- frontier
    ctx:prev_char()
    local prev_charcode = ctx:get_charcode() or 0
    ctx:next_char()
    local charcode = ctx:get_charcode() or 0
    -- debug("frontier pos", ctx.pos, "prev_charcode", prev_charcode, "charcode", charcode)
    if ]] .. class_name .. [[:test(prev_charcode) then return end
    if ]] .. class_name .. [[:test(charcode) then
      ctx:next_function()
      return ctx:get_function()(ctx)
    end
  end)
]]
  end,
  simple = utf8:require("modifier.compiletime.simple").simple,
}

local function parse(regex, c, bs, ctx)
  local functions, nbs, class

  if c == '%' then
    if utf8.raw.sub(regex, bs + 1, bs + 1) ~= 'f' then return end
    if utf8.raw.sub(regex, bs + 2, bs + 2) ~= '[' then error("missing '[' after '%f' in pattern") end

    functions = {}
    if ctx.prev_class then
      table.insert(functions, matchers.simple(ctx.prev_class, tostring(bs)))
      ctx.prev_class = nil
    end
    class, nbs = utf8.regex.compiletime.charclass.parse(regex, '[', bs + 2, ctx)
    nbs = nbs + 2
    table.insert(functions, matchers.frontier(class:build(), tostring(bs)))
  end

  return functions, nbs
end

return {
  parse = parse,
}

end
]=]

sources["utf8string.modifier.compiletime.parser"] = [[return function(utf8)

utf8.config.modifier = utf8.config.modifier or {
  utf8:require "modifier.compiletime.vanilla",
  utf8:require "modifier.compiletime.frontier",
  utf8:require "modifier.compiletime.stub",
}

function utf8.regex.compiletime.modifier.parse(regex, c, bs, ctx)
  for _, m in ipairs(utf8.config.modifier) do
    local functions, move = m.parse(regex, c, bs, ctx)
    utf8.debug("mod", _, c, bs, move, functions and utf8.config.unpack(functions))
    if functions then
      ctx.prev_class = nil
      return functions, move
    end
  end
end

end
]]

sources["utf8string.modifier.compiletime.simple"] = [=[return function(utf8)

local matchers = {
  simple = function(class, name)
    local class_name = 'class' .. name
    return [[
  local ]] .. class_name .. [[ = ]] .. class .. [[

  add(function(ctx) -- simple
    -- debug(ctx, 'simple', ']] .. class_name .. [[')
    if ]] .. class_name .. [[:test(ctx:get_charcode()) then
      ctx:next_char()
      ctx:next_function()
      return ctx:get_function()(ctx)
    end
  end)
]]
  end,
}

return matchers

end
]=]

sources["utf8string.modifier.compiletime.stub"] = [[return function(utf8)

local matchers = utf8:require("modifier.compiletime.simple")

local function parse(regex, c, bs, ctx)
  local functions

  if ctx.prev_class then
    functions = { matchers.simple(ctx.prev_class, tostring(bs)) }
    ctx.prev_class = nil
  end

  return functions, 0
end

local function check(ctx)
  if ctx.prev_class then
    table.insert(ctx.funcs, matchers.simple(ctx.prev_class, tostring(ctx.pos)))
    ctx.prev_class = nil
  end
end

return {
  parse = parse,
  check = check,
}

end
]]

sources["utf8string.modifier.compiletime.vanilla"] = [=[return function(utf8)

local utf8unicode = utf8.byte
local sub = utf8.raw.sub

local matchers = {
  star = function(class, name)
    local class_name = 'class' .. name
    return [[
  local ]] .. class_name .. [[ = ]] .. class .. [[

  add(function(ctx) -- star
    -- debug(ctx, 'star', ']] .. class_name .. [[')
    local clone = ctx:clone()
    while ]] .. class_name .. [[:test(clone:get_charcode()) do
      clone:next_char()
    end
    local pos = clone.pos
    while pos >= ctx.pos do
      clone.pos = pos
      clone.func_pos = ctx.func_pos
      clone:next_function()
      clone:get_function()(clone)
      if clone.modified then
        clone = ctx:clone()
      end
      pos = pos - 1
    end
  end)
]]
  end,
  minus = function(class, name)
    local class_name = 'class' .. name
    return [[
  local ]] .. class_name .. [[ = ]] .. class .. [[

  add(function(ctx) -- minus
    -- debug(ctx, 'minus', ']] .. class_name .. [[')

    local clone = ctx:clone()
    local pos
    repeat
      pos = clone.pos
      clone:next_function()
      clone:get_function()(clone)
      if clone.modified then
        clone = ctx:clone()
        clone.pos = pos
      else
        clone.pos = pos
        clone.func_pos = ctx.func_pos
      end
      local match = ]] .. class_name .. [[:test(clone:get_charcode())
      clone:next_char()
    until not match
  end)
]]
  end,
  question = function(class, name)
    local class_name = 'class' .. name
    return [[
  local ]] .. class_name .. [[ = ]] .. class .. [[

  add(function(ctx) -- question
    -- debug(ctx, 'question', ']] .. class_name .. [[')
    local saved = ctx:clone()
    if ]] .. class_name .. [[:test(ctx:get_charcode()) then
      ctx:next_char()
      ctx:next_function()
      ctx:get_function()(ctx)
    end
    ctx = saved
    ctx:next_function()
    return ctx:get_function()(ctx)
  end)
]]
  end,
  capture_start = function(number)
    return [[
  add(function(ctx)
    ctx.modified = true
    -- debug(ctx, 'capture_start', ']] .. tostring(number) .. [[')
    table.insert(ctx.captures.active, { id = ]] .. tostring(number) .. [[, start = ctx.pos })
    ctx:next_function()
    return ctx:get_function()(ctx)
  end)
]]
  end,
  capture_finish = function(number)
    return [[
  add(function(ctx)
    ctx.modified = true
    -- debug(ctx, 'capture_finish', ']] .. tostring(number) .. [[')
    local cap = table.remove(ctx.captures.active)
    cap.finish = ctx.pos
    local b, e = ctx.offsets[cap.start], ctx.offsets[cap.finish]
    if cap.start < 1 then
      b = 1
    elseif cap.start >= ctx.len then
      b = ctx.rawlen + 1
    end
    if cap.finish < 1 then
      e = 1
    elseif cap.finish >= ctx.len then
      e = ctx.rawlen + 1
    end
    ctx.captures[cap.id] = rawsub(ctx.str, b, e - 1)
    -- debug('capture#' .. tostring(cap.id), '[' .. tostring(cap.start).. ',' .. tostring(cap.finish) .. ']' , 'is', ctx.captures[cap.id])
    ctx:next_function()
    return ctx:get_function()(ctx)
  end)
]]
  end,
  capture_position = function(number)
    return [[
  add(function(ctx)
    ctx.modified = true
    -- debug(ctx, 'capture_position', ']] .. tostring(number) .. [[')
    ctx.captures[ ]] .. tostring(number) .. [[ ] = ctx.pos
    ctx:next_function()
    return ctx:get_function()(ctx)
  end)
]]
  end,
  capture = function(number)
    return [[
  add(function(ctx)
    -- debug(ctx, 'capture', ']] .. tostring(number) .. [[')
    local cap = ctx.captures[ ]] .. tostring(number) .. [[ ]
    local len = utf8len(cap)
		local check = utf8sub(ctx.str, ctx.pos, ctx.pos + len - 1)
    -- debug("capture check:", cap, check)
		if cap == check then
			ctx.pos = ctx.pos + len
			ctx:next_function()
      return ctx:get_function()(ctx)
		end
  end)
]]
  end,
  balancer = function(pair, name)
    local class_name = 'class' .. name
    return [[

  add(function(ctx) -- balancer
    local d, b = ]] .. tostring(utf8unicode(pair[1])) .. [[, ]] .. tostring(utf8unicode(pair[2])) .. [[
    if ctx:get_charcode() ~= d then return end
    local balance = 0
    repeat
      local c = ctx:get_charcode()
      if c == nil then return end

      if c == d then
        balance = balance + 1
      elseif c == b then
        balance = balance - 1
      end
      -- debug("balancer: balance=", balance, ", d=", d, ", b=", b, ", charcode=", ctx:get_charcode())
      ctx:next_char()
    until balance == 0 or (balance == 2 and d == b)
    ctx:next_function()
    return ctx:get_function()(ctx)
  end)
]]
  end,
  simple = utf8:require("modifier.compiletime.simple").simple,
}

local next = utf8.util.next

local function parse(regex, c, bs, ctx)
  local functions, nbs = nil, bs
  if c == '%' then
    c, nbs = next(regex, bs)
    utf8.debug("next", c, bs)
    if c == '' then
      error("malformed pattern (ends with '%')")
    end
    if utf8.raw.find('123456789', c, 1, true) then
      functions = { matchers.capture(tonumber(c)) }
      nbs = utf8.next(regex, nbs)
    elseif c == 'b' then
      local d, b
      d, nbs = next(regex, nbs)
      b, nbs = next(regex, nbs)
      assert(d ~= '' and b ~= '', "unbalanced pattern")
      functions = { matchers.balancer({d, b}, tostring(bs)) }
      nbs = utf8.next(regex, nbs)
    end

    if functions and ctx.prev_class then
      table.insert(functions, 1, matchers.simple(ctx.prev_class, tostring(bs)))
    end
  elseif c == '*' and ctx.prev_class then
    functions = {
      matchers.star(
        ctx.prev_class,
        tostring(bs)
      )
    }
    nbs = bs + 1
  elseif c == '+' and ctx.prev_class then
    functions = {
      matchers.simple(
        ctx.prev_class,
        tostring(bs)
      ),
      matchers.star(
        ctx.prev_class,
        tostring(bs)
      )
    }
    nbs = bs + 1
  elseif c == '-' and ctx.prev_class then
    functions = {
      matchers.minus(
        ctx.prev_class,
        tostring(bs)
      )
    }
    nbs = bs + 1
  elseif c == '?' and ctx.prev_class then
    functions = {
      matchers.question(
        ctx.prev_class,
        tostring(bs)
      )
    }
    nbs = bs + 1
  elseif c == '(' then
    ctx.capture = ctx.capture or {balance = 0, id = 0}
    ctx.capture.id = ctx.capture.id + 1
    local nc = next(regex, nbs)
    if nc == ')' then
      functions = {matchers.capture_position(ctx.capture.id)}
      nbs = bs + 2
    else
      ctx.capture.balance = ctx.capture.balance + 1
      functions = {matchers.capture_start(ctx.capture.id)}
      nbs = bs + 1
    end
    if ctx.prev_class then
      table.insert(functions, 1, matchers.simple(ctx.prev_class, tostring(bs)))
    end
  elseif c == ')' then
    ctx.capture = ctx.capture or {balance = 0, id = 0}
    functions = { matchers.capture_finish(ctx.capture.id) }

    ctx.capture.balance = ctx.capture.balance - 1
    assert(ctx.capture.balance >= 0, 'invalid capture: "(" missing')

    if ctx.prev_class then
      table.insert(functions, 1, matchers.simple(ctx.prev_class, tostring(bs)))
    end
    nbs = bs + 1
  end

  return functions, nbs - bs
end

local function check(ctx)
  if ctx.capture then assert(ctx.capture.balance == 0, 'invalid capture: ")" missing') end
end

return {
  parse = parse,
  check = check,
}

end
]=]

sources["utf8string.regex_parser"] = [=[return function(utf8)

utf8:require "modifier.compiletime.parser"
utf8:require "charclass.compiletime.parser"
utf8:require "begins.compiletime.parser"
utf8:require "ends.compiletime.parser"

local gensub = utf8.gensub
local sub = utf8.sub

local parser_context = utf8:require "context.compiletime"

return function(regex, plain)
  utf8.debug("regex", regex)
  local ctx = parser_context:new()

  local skip = {0}
  for nbs, c, bs in gensub(regex, 0), skip do
    repeat -- continue
      skip[1] = 0

      c = utf8.raw.sub(regex, bs, utf8.next(regex, bs) - 1)

      local functions, move = utf8.regex.compiletime.begins.parse(regex, c, bs, ctx)
      if functions then
        ctx.begins = functions
        skip[1] = move
      end
      if skip[1] ~= 0 then break end

      local functions, move = utf8.regex.compiletime.ends.parse(regex, c, bs, ctx)
      if functions then
        ctx.ends = functions
        skip[1] = move
      end
      if skip[1] ~= 0 then break end

      local functions, move = utf8.regex.compiletime.modifier.parse(regex, c, bs, ctx)
      if functions then
        for _, f in ipairs(functions) do
          ctx.funcs[#ctx.funcs + 1] = f
        end
        skip[1] = move
      end
      if skip[1] ~= 0 then break end

      local charclass, move = utf8.regex.compiletime.charclass.parse(regex, c, bs, ctx)
      if charclass then skip[1] = move end
    until true -- continue
  end

  for _, m in ipairs(utf8.config.modifier) do
    if m.check then m.check(ctx) end
  end

  local src = [[
  return function(str, init, utf8)
      local ctx = utf8:require("context.runtime").new({str = str, pos = init or 1})
      local cl = utf8:require("charclass.runtime.init")
      local utf8sub = utf8.sub
      local rawsub = utf8.raw.sub
      local utf8len = utf8.len
      local utf8next = utf8.next
      local debug = utf8.debug
      local function add(fun)
          ctx.functions[#ctx.functions + 1] = fun
      end
  ]] .. ctx.begins
  for _, v in ipairs(ctx.funcs) do src = src .. v end
  src = src .. ctx.ends .. [[
      return coroutine.wrap(ctx:get_function())(ctx)
  end
  ]]

  utf8.debug(regex, src)

  return assert(utf8.config.loadstring(src, (plain and "plain " or "") .. regex))()
end

end
]=]

local compat_load
do if pcall(load, '') then -- check if it's lua 5.2+ or LuaJIT's with a compatible load
	compat_load = load
else
	local loadstring = assert(loadstring)
	local type = assert(type)
	local setfenv = assert(setfenv)
	local byte = assert(string.byte)
	local find = assert(string.find)

	local native_load = load
	function compat_load(str,src,mode,env)
		local chunk,err
		if type(str) == 'string' then
			if byte(1) == 27 and not find((mode or 'bt'),'b') then
				return nil,"attempt to load a binary chunk"
			end
			chunk,err = loadstring(str,src)
		else
			chunk,err = native_load(str,src)
		end
		if chunk and env then setfenv(chunk,env) end
		return chunk,err
	end
end end
local function preloadgeneric(modname, p)
	local src = sources[modname]
	if not src then return nil end
	sources[modname]=nil
	return assert(compat_load(src, "@"..modname, "t", _G))(modname,p)
end
package.preload["utf8string.functions.lua53"] = preloadgeneric
package.preload["utf8string.primitives.dummy"] = preloadgeneric
package.preload["utf8string.primitives.init"] = preloadgeneric
package.preload["utf8string.primitives.native"] = preloadgeneric
package.preload["utf8string.primitives.tarantool"] = preloadgeneric
package.preload["utf8string.util"] = preloadgeneric
package.preload["utf8string.begins.compiletime.parser"] = preloadgeneric
package.preload["utf8string.begins.compiletime.vanilla"] = preloadgeneric
package.preload["utf8string.charclass.compiletime.builder"] = preloadgeneric
package.preload["utf8string.charclass.compiletime.parser"] = preloadgeneric
package.preload["utf8string.charclass.compiletime.range"] = preloadgeneric
package.preload["utf8string.charclass.compiletime.stub"] = preloadgeneric
package.preload["utf8string.charclass.compiletime.vanilla"] = preloadgeneric
package.preload["utf8string.charclass.runtime.base"] = preloadgeneric
package.preload["utf8string.charclass.runtime.dummy"] = preloadgeneric
package.preload["utf8string.charclass.runtime.init"] = preloadgeneric
package.preload["utf8string.charclass.runtime.native"] = preloadgeneric
package.preload["utf8string.context.compiletime"] = preloadgeneric
package.preload["utf8string.context.runtime"] = preloadgeneric
package.preload["utf8string.ends.compiletime.parser"] = preloadgeneric
package.preload["utf8string.ends.compiletime.vanilla"] = preloadgeneric
package.preload["utf8string.modifier.compiletime.frontier"] = preloadgeneric
package.preload["utf8string.modifier.compiletime.parser"] = preloadgeneric
package.preload["utf8string.modifier.compiletime.simple"] = preloadgeneric
package.preload["utf8string.modifier.compiletime.stub"] = preloadgeneric
package.preload["utf8string.modifier.compiletime.vanilla"] = preloadgeneric
package.preload["utf8string.regex_parser"] = preloadgeneric

local module_path = ...
module_path = module_path:match("^(.-)init$") or (module_path .. '.')

local ffi_enabled, ffi = pcall(require, 'ffi')

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
    locale = nil,
    int32array = function(size)
      if ffi_enabled then
        return ffi.new("uint32_t[?]", size + 1)
      else
        return {}
      end
    end
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
