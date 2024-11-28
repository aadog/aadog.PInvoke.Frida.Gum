using aadog.PInvoke.LibGum.Enums;
using aadog.PInvoke.LibGum;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ThreadDetails
    {
        public GumThreadId id;
        public string? name;
        public GumThreadState state;
        public GumCpuContext cpu_context;
        public gboolean setHardwareBreakpoint(guint breakpointId, IntPtr address)
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_set_hardware_breakpoint(this.id, breakpointId, address, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }
            return r;
        }
        public gboolean unsetHardwareBreakpoint(GumThreadId threadId, guint breakpointId)
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_unset_hardware_breakpoint(threadId, breakpointId, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }

            return r;
        }
        public gboolean setHardwareWatchpoint(guint breakpointId, IntPtr address, guint size, GumWatchConditions watchConditions)
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_set_hardware_watchpoint(this.id, breakpointId, address, size, watchConditions, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }
            return r;
        }
        public gboolean unsetHardwareWatchpoint(guint breakpointId)
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_unset_hardware_watchpoint(this.id, breakpointId, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }

            return r;
        }
        public gboolean suspend()
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_suspend(this.id, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }

            return r;
        }
        public gboolean resume()
        {
            GError* error;
            var r = LibGumFunctions.gum_thread_resume(this.id, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                LibGumFunctions.g_error_free(error);
                throw new GumException(errorMessage);
            }

            return r;
        }
    }
}
