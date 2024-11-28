using System.Diagnostics;
using aadog.PInvoke.Base;
using aadog.PInvoke.LibGum;
using aadog.PInvoke.LibGum.Enums;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class Module
    {
        public required string name;
        public required IntPtr baseAddress;
        public required gsize size;
        public required string path;
        public List<ModuleDependencyDetails> enumerateDependencies()
        {
            var l = new List<ModuleDependencyDetails>();
            LibGumFunctions.gum_module_enumerate_dependencies(name, (d, data) =>
            {
                var item = new ModuleDependencyDetails
                {
                    type = d->type,
                    name = d->name.readUtf8String()!,
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public List<ModuleImportDetails> enumerateImports()
        {
            var l = new List<ModuleImportDetails>();
            LibGumFunctions.gum_module_enumerate_imports(name, (d, data) =>
            {

                var item = new ModuleImportDetails
                {
                    type = d->type,
                    name = d->name.readUtf8String()!,
                    module = d->module.readUtf8String()!,
                    address = d->address,
                    slot = d->slot,
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public List<ModuleSectionDetails> enumerateSections()
        {
            var l = new List<ModuleSectionDetails>();
            LibGumFunctions.gum_module_enumerate_sections(name, (d, data) =>
            {

                var item = new ModuleSectionDetails
                {
                    address = d->address,
                    name = d->name.readUtf8String()!,
                    id = d->id.readUtf8String()!,
                    size = d->size
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public List<RangeDetails> enumerateRanges(GumPageProtection protection)
        {
            var l = new List<RangeDetails>();
            LibGumFunctions.gum_module_enumerate_ranges(name, protection, (d, data) =>
            {

                var item = new RangeDetails
                {
                    baseAddress = d->range->base_address,
                    size = d->range->size,
                    protection = d->protection,
                };
                if (d->file != null)
                {
                    item.file = new()
                    {
                        offset = d->file->offset,
                        size = d->file->size,
                    };
                    if (!d->file->path.isNull())
                    {
                        item.file.path = d->file->path.readUtf8String();
                    }
                }
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public List<ModuleExportDetails> enumerateExports()
        {
            var l = new List<ModuleExportDetails>();
            LibGumFunctions.gum_module_enumerate_exports(name, (d, data) =>
            {
                var item = new ModuleExportDetails
                {
                    type = d->type,
                    name = d->name.readUtf8String()!,
                    address = d->address,
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public List<ModuleSymbolDetails> enumerateSymbols()
        {
            var l = new List<ModuleSymbolDetails>();
            LibGumFunctions.gum_module_enumerate_symbols(name, (d, data) =>
            {
                var item = new ModuleSymbolDetails
                {
                    isGlobal = d->is_global != 0,
                    type = d->type,
                    section = d->section,
                    name = d->name.readUtf8String()!,
                    address = d->address,
                    size = d->size
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }

        public IntPtr getExportByName(string symbol_name)
        {
            var result = LibGumFunctions.gum_module_find_export_by_name(name, symbol_name);
            if (result.isNull())
            {
                throw new GumException($"export {symbol_name} not found");
            }

            return result;
        }
        public IntPtr findExportByName(string symbol_name)
        {
            return LibGumFunctions.gum_module_find_export_by_name(name, symbol_name);
        }
        public ModuleSymbolDetails getSymbolByName(string symbol_name)
        {
            var symbol = findSymbolByName(symbol_name);
            if (symbol == null)
            {
                throw new GumException($"export {symbol_name} not found");
            }
            return symbol;
        }
        public ModuleSymbolDetails? findSymbolByName(string symbol_name)
        {
            var symbols = this.enumerateSymbols();
            return symbols.Find(e => e.name == symbol_name);
            // var symbol = findSymbolByName(name, symbol_name);
            // if (symbol == null)
            // {
            //     return null;
            // }
            // return symbol;
        }
        // public static ModuleSymbolDetails? findSymbolByName(string? module_name, string symbol_name)
        // {
        //     var p=LibGumFunctions.gum_module_find_symbol_by_name(module_name, symbol_name);
        //     if (p.isNull())
        //     {
        //         return null;
        //     }
        //     //
        //     // var d = (GumSymbolDetails*)p.ToPointer();
        //     var item = new ModuleSymbolDetails
        //     {
        //         isGlobal = false,
        //         name = ""
        //         //     isGlobal = d->is_global != 0,
        //         //     type = d->type,
        //         //     section = d->section,
        //         //     name = d->name.readUtf8String()!,
        //         //     address = d->address,
        //         //     size = d->size
        //     };
        //     return item;
        // }
        public static IntPtr getExportByName(string? module_name, string symbol_name)
        {
            var result = LibGumFunctions.gum_module_find_export_by_name(module_name, symbol_name);
            return result;
            if (result.isNull())
            {
                throw new GumException($"export {symbol_name} not found");
            }

            return result;
        }
        public static IntPtr getBaseAddress(string name)
        {
            return LibGumFunctions.gum_module_find_base_address(name);
        }
        public static IntPtr findBaseAddress(string name)
        {
            return LibGumFunctions.gum_module_find_base_address(name);
        }
        public static Module load(string name)
        {
            GError* error = null;
            LibGumFunctions.gum_module_load(name, &error);
            var pErrorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (pErrorMessage != null)
            {
                throw new GumException(pErrorMessage);
            }

            return Process.getModuleByName(name);
        }
        public static IntPtr findExportByName(string? module_name, string symbol_name)
        {
            return LibGumFunctions.gum_module_find_export_by_name(module_name, symbol_name);
        }

    }
}
