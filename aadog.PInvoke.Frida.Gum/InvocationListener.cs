using aadog.PInvoke.LibGum;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class InvocationListener(GumInvocationListener* listener) : IDisposable
    {
        public void detach()
        {
            LibGumFunctions.gum_interceptor_begin_transaction(Gum.interceptor);
            LibGumFunctions.gum_interceptor_detach(Gum.interceptor, listener);
            LibGumFunctions.gum_interceptor_end_transaction(Gum.interceptor);
            if (Interceptor.allListener.ContainsKey(this))
            {
                bool b;
                Interceptor.allListener.Remove(this, out b);
            }
        }

        public void Dispose()
        {
            LibGumFunctions.g_object_unref(listener);
        }
    }
}
