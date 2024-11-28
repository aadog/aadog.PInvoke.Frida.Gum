using System.Runtime.InteropServices;
using System.Text;
using aadog.PInvoke.Base;
using aadog.PInvoke.LibGum;
using aadog.PInvoke.LibGum.Enums;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class Memory
    {
        IntPtr alloc(UIntPtr n)
        {
            return IntPtrExtension.ptr(NativeMemory.AllocZeroed(n));
        }
        void free(IntPtr p)
        {
            NativeMemory.Free(p.ToPointer());
        }
        void dup(IntPtr p,UIntPtr byteCount)
        {
            NativeMemory.Fill(p.ToPointer(),n,0x0);
        }
        void copy(IntPtr source,IntPtr dest, UIntPtr byteCount)
        {
            NativeMemory.Copy(source.ToPointer(), dest.ToPointer(), byteCount);
        }

        bool protect(IntPtr address, gsize size, GumPageProtection protection)
        {
            return LibGumFunctions.gum_try_mprotect(address, size, protection) != 0;
        }


        public static IntPtr allocUtf8String(string str)
        {
            var bt = Encoding.UTF8.GetBytes(str);
            var l = (gsize)bt.Length + 1;
            void* p = NativeMemory.AllocZeroed(l);
            fixed (void* pB = &bt[0])
                NativeMemory.Copy(pB, p, (nuint)bt.Length);
            return IntPtrExtension.ptr(p);
        }
        public static IntPtr allocUtf16String(string str)
        {
            var bt = Encoding.Unicode.GetBytes(str);
            var l = (gsize)bt.Length +1;
            void* p = NativeMemory.AllocZeroed(l);
            fixed (void* pB = &bt[0])
                NativeMemory.Copy(pB, p, (nuint)bt.Length);
            return IntPtrExtension.ptr(p);
        }
        public static IntPtr allocAnsiString(string str)
        {
            var bt = Encoding.ASCII.GetBytes(str);
            var l = (gsize)bt.Length + 1;
            void* p = NativeMemory.AllocZeroed(l);
            fixed (void* pB = &bt[0])
                NativeMemory.Copy(pB, p, (nuint)bt.Length);
            return IntPtrExtension.ptr(p);
        }



    }
}
