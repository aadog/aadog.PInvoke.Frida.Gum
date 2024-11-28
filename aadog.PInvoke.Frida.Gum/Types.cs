#pragma warning disable CS8981 // 该类型名称仅包含小写 ascii 字符。此类名称可能会成为该语言的保留值。
global using gboolean = int;
global using guint = uint;
global using gchar = byte;
global using guint64 = ulong;
global using gint = int;
global using GQuark = uint;
global using GumProcessId = uint;
global using GumThreadId = uint;
#if x64
global using gsize=ulong;
global using gssize=long;
#else
global using gsize = uint;
global using gssize = int;
#endif
global using unsafe gpointer = void*;
global using unsafe GumAddress = void*;
global using unsafe GumReturnAddress = void*;
#pragma warning restore CS8981 // 该类型名称仅包含小写 ascii 字符。此类名称可能会成为该语言的保留值。