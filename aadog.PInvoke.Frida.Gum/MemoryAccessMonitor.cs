using aadog.PInvoke.LibGum.Enums;
using aadog.PInvoke.LibGum;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class MemoryAccessMonitor : IDisposable
    {
        private GumMemoryAccessMonitor* _accessMonitor;


        public MemoryAccessMonitor(GumPageProtection protection, GumMemoryRange range, LibGumFunctions.GumMemoryAccessNotify accessNotify, IntPtr data )
        {
            _accessMonitor = LibGumFunctions.gum_memory_access_monitor_new(&range, 1, protection, 1, accessNotify, data, null);
        }

        public int enable()
        {
            GError* error = null;
            var ret = LibGumFunctions.gum_memory_access_monitor_enable(_accessMonitor, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }

            return ret;
        }
        public void disable()
        {
            LibGumFunctions.gum_memory_access_monitor_disable(_accessMonitor);
        }


        public uint RefCount()
        {
            // return _accessMonitor->parent.ref_count;
            return 0;
        }
        public void Dispose()
        {
            LibGumFunctions.g_object_unref(_accessMonitor);
            GC.SuppressFinalize(this);
        }
    }
}
