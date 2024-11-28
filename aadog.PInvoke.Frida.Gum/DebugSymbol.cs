using System.Runtime.InteropServices;
using aadog.PInvoke.LibGum;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class DebugSymbol
    {
        public IntPtr address;
        public string? module_name;
        public string? symbol_name;
        public string? file_name;
        public guint line_number;
        public guint column;
        const int GUM_MAX_PATH = 260;
        const int GUM_MAX_SYMBOL_NAME = 2048;

        public static unsafe DebugSymbol? fromAddress(IntPtr address)
        {
            var result = new DebugSymbol();
            var l1 = sizeof(GumAddress);
            var l2 = sizeof(gchar) * (GUM_MAX_PATH + 1);
            var l3 = sizeof(gchar) * (GUM_MAX_SYMBOL_NAME + 1);
            var l4 = sizeof(gchar) * (GUM_MAX_PATH + 1);
            var l5 = sizeof(guint);
            var l6 = sizeof(guint);
            void* px = NativeMemory.AllocZeroed((nuint)(l1 + l2 + l3 + l4 + l5 + l6));
            var s = LibGumFunctions.gum_symbol_name_from_address(address);
            var p = new IntPtr(px);
            LibGumFunctions.gum_symbol_details_from_address(address, ref p);
            var wp = new IntPtr(px);
            result.address = wp;
            var pl2 = IntPtr.Add(new IntPtr(px), l1);
            result.module_name = Marshal.PtrToStringUTF8(pl2, GUM_MAX_PATH + 1);
            var pl3 = IntPtr.Add(new IntPtr(pl2), l2);
            result.symbol_name = Marshal.PtrToStringUTF8(pl3, GUM_MAX_SYMBOL_NAME + 1);
            var pl4 = IntPtr.Add(new IntPtr(pl3), l3);
            result.file_name = Marshal.PtrToStringUTF8(pl4, GUM_MAX_PATH + 1);
            var pl5 = IntPtr.Add(new IntPtr(pl4), l4);
            result.line_number = (guint)Marshal.ReadInt32(pl5);
            var pl6 = IntPtr.Add(new IntPtr(pl5), l5);
            result.column = (guint)Marshal.ReadInt32(pl6);
            return result;
        }
    }
}
