using aadog.PInvoke.LibGum.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ModuleImportDetails
    {
        public GumImportType type;
        public required string name;
        public string? module;
        public IntPtr address;
        public IntPtr slot;
    }
}
