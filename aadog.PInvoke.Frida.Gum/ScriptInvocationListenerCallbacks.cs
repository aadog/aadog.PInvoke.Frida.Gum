
using aadog.PInvoke.LibGum;

namespace aadog.PInvoke.Frida.Gum
{
    public class ScriptInvocationListenerCallbacks
    {
        public unsafe LibGumFunctions.GumInvocationCallback? onEnter;
        public unsafe LibGumFunctions.GumInvocationCallback? onLeave;
    }
}
