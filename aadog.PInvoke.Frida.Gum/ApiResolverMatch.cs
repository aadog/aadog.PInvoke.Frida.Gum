using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ApiResolverMatch
    {
        public string? name;
        public IntPtr address;
        public gsize size;
    }
}
