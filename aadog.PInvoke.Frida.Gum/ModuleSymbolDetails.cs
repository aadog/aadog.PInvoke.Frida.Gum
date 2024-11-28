using aadog.PInvoke.LibGum.Enums;
namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ModuleSymbolDetails
    {
        public bool isGlobal;
        public GumSymbolType type;
        public GumSymbolSection* section;
        public required string name;
        public IntPtr address;
        public int size;
    }
}
