namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ModuleSectionDetails
    {
        public required string id;
        public required string name;
        public IntPtr address;
        public gsize size;
    }
}
