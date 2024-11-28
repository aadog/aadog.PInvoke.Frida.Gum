﻿using aadog.PInvoke.LibGum.Enums;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ModuleDependencyDetails
    {
        public required string name;
        public GumDependencyType type;
    }
}
