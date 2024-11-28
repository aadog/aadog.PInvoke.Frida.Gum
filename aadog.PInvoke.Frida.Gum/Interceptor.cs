using System.Collections.Concurrent;
using aadog.PInvoke.LibGum;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class Interceptor
    {
        public static ConcurrentDictionary<InvocationListener, bool> allListener =
            new ConcurrentDictionary<InvocationListener, bool>();

        public static InvocationListener attach(IntPtr target, ScriptInvocationListenerCallbacks callbacks, IntPtr data)
        {
            GumInvocationListener* listener =
                LibGumFunctions.gum_make_call_listener(callbacks.onEnter, callbacks.onLeave, data, null);
            LibGumFunctions.gum_interceptor_begin_transaction(Gum.interceptor);
            LibGumFunctions.gum_interceptor_attach(Gum.interceptor, target, listener, data);
            LibGumFunctions.gum_interceptor_end_transaction(Gum.interceptor);
            var l = new InvocationListener(listener);
            allListener.TryAdd(l, true);
            return l;
        }

        /*Reverts the previously replaced function at target.*/
        public static void revert(IntPtr target)
        {
            LibGumFunctions.gum_interceptor_revert(Gum.interceptor, target);
        }

        /*Ensure any pending changes have been committed to memory*/
        public static void flush()
        {
            LibGumFunctions.gum_interceptor_flush(Gum.interceptor);
        }

        public static void detachAll()
        {
            foreach (var l in allListener)
            {
                l.Key.detach();
            }

            ;
        }

        public static void replace(IntPtr target, IntPtr replacement, IntPtr data)
        {
            LibGumFunctions.gum_interceptor_begin_transaction(Gum.interceptor);
            IntPtr f = IntPtr.Zero;
            LibGumFunctions.gum_interceptor_replace(Gum.interceptor, target, replacement, data, ref f);
            LibGumFunctions.gum_interceptor_end_transaction(Gum.interceptor);
        }
    }
}