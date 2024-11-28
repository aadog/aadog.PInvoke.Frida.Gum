using aadog.PInvoke.LibGum.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class RangeDetails
    {
        public IntPtr baseAddress;
        public gsize size;
        public GumPageProtection protection;
        public FileMapping? file;
    }
}
