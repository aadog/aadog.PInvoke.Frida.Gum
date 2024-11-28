using aadog.PInvoke.LibGum.Enums;
using aadog.PInvoke.LibGum;
using System.Runtime.InteropServices;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class Thread
    {
        public static void sleep(int millisecondsTimeout)
        {
            System.Threading.Thread.Sleep(millisecondsTimeout);
        }

        public delegate void ThreadDelegate(string msg);
        public static List<IntPtr> backtrace(GumCpuContext* context, Backtracer backtracer, ThreadDelegate fn)
        {
            GumBacktracer* t = null;
            if (backtracer == Backtracer.ACCURATE)
            {
                t = LibGumFunctions.gum_backtracer_make_accurate();
            }
            else
            {
                t = LibGumFunctions.gum_backtracer_make_fuzzy();
            }
            fn($"GumBacktracer:{new IntPtr(t)}");
            void* px = NativeMemory.AllocZeroed((uint)(sizeof(guint) + sizeof(void*) * 128));
            void* px1 = NativeMemory.AllocZeroed((uint)(sizeof(guint) + sizeof(void*) * 128));
            Marshal.WriteIntPtr(IntPtr.Add(new IntPtr(px), sizeof(guint)), new IntPtr(px1));
            LibGumFunctions.gum_backtracer_generate(t, context, new IntPtr(px));
            var pl1 = new IntPtr(px);
            GumReturnAddressArray addressArray = new()
            {
                len = (guint)Marshal.ReadInt32(pl1),
            };

            var retAddresses = new List<IntPtr>();
            var ptr = IntPtr.Add(pl1, sizeof(guint));
            for (int i = 0; i < addressArray.len; i++)
            {
                ptr = IntPtr.Add(ptr, i * sizeof(void*));
                retAddresses.Add(ptr);
            }
            NativeMemory.Free(px);
            return retAddresses;
        }
    }
}
