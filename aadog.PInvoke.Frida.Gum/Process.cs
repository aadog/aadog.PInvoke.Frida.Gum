using aadog.PInvoke.Base;
using System.Runtime.InteropServices;
using aadog.PInvoke.LibGum;
using aadog.PInvoke.LibGum.Enums;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class Process
    {
        public static int pointerSize = sizeof(gpointer);
        public static uint id = LibGumFunctions.gum_process_get_id();
        public static Architecture arch = RuntimeInformation.ProcessArchitecture;
        public static string platform = RuntimeInformation.OSDescription;

        public static List<Module> enumerateModules()
        {
            var l = new List<Module>();
            LibGumFunctions.gum_process_enumerate_modules((d, data) =>
            {
                var name = d->name.readUtf8String()!;
                var path = d->path.readUtf8String()!;
                var item = new Module
                {
                    name = name,
                    path = path,
                    baseAddress = d->range->base_address,
                    size = d->range->size
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public static List<ThreadDetails> enumerateThreads()
        {
            var l = new List<ThreadDetails>();
            LibGumFunctions.gum_process_enumerate_threads((d, data) =>
            {
                var name = d->name.readUtf8String()!;
                var item = new ThreadDetails
                {
                    id = d->id,
                    name = name,
                    state = d->state,
                    cpu_context = d->cpu_context
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }

        public static List<RangeDetails> enumerateMallocRanges()
        {
            var l = new List<RangeDetails>();
            LibGumFunctions.gum_process_enumerate_malloc_ranges((details, data) =>
            {
                var item = new RangeDetails
                {
                    baseAddress = details->range->base_address,
                    size = details->range->size,
                };
                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public static List<RangeDetails> enumerateRanges(GumPageProtection prot)
        {
            var l = new List<RangeDetails>();
            LibGumFunctions.gum_process_enumerate_ranges(prot, (d, data) =>
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
                        item.file.path = d->file->path.readUtf8String()!;
                    }
                }

                l.Add(item);
                return 1;
            }, IntPtr.Zero);
            return l;
        }
        public static Module mainModule()
        {
            var d = LibGumFunctions.gum_process_get_main_module();
            var name = d->name.readUtf8String()!;
            var path = d->path.readUtf8String()!;
            var item = new Module
            {
                name = name,
                path = path,
                baseAddress = d->range->base_address,
                size = d->range->size
            };
            return item;
        }
        public static Module? findModuleByName(string name)
        {
            var modules = enumerateModules();
            var ex = Path.GetExtension(name);
            if (ex != "")
            {
                var a = name.ToLower();
                return modules.Find(e => e.name.ToLower() == a);
            }
            else
            {
                var a = Path.GetFileNameWithoutExtension(name).ToLower();
                return modules.Find(e => Path.GetFileNameWithoutExtension(e.name)!.ToLower() == a);
            }
        }
        public static Module getModuleByName(string name)
        {
            var modules = enumerateModules();
            var ex = Path.GetExtension(name);
            if (ex != "")
            {
                var a = name.ToLower();
                var m = modules.Find(e => e.name.ToLower() == a);
                if (m == null)
                {
                    throw new GumException($"not found module:{name}");
                }

                return m;
            }
            else
            {
                var a = Path.GetFileNameWithoutExtension(name).ToLower();
                var m = modules.Find(e => Path.GetFileNameWithoutExtension(e.name)!.ToLower() == a);
                if (m == null)
                {
                    throw new GumException($"not found module:{name}");
                }

                return m;
            }
        }
        public static Module getModuleByAddress(IntPtr address)
        {
            var modules = enumerateModules();
            foreach (var module in modules)
            {
                var a = module.baseAddress;
                var b = module.baseAddress.Add(module.size);
                if (address >= a && address < b)
                {
                    return module;
                }
            }
            throw new GumException($"not found module for :{new IntPtr(address)}");
        }

        public static Module? findModuleByAddress(IntPtr address)
        {
            var modules = enumerateModules();
            foreach (var module in modules)
            {
                var a = module.baseAddress;
                var b = module.baseAddress.Add(module.size);
                if (address >= a && address < b)
                {
                    return module;
                }
            }
            return null;
        }

        public static string getCurrentDir()
        {
            var dir_opsys = LibGumFunctions.g_get_current_dir();
            var dir_utf8 = LibGumFunctions.g_filename_display_name(dir_opsys);
            var result = dir_utf8.readUtf8String()!;
            LibGumFunctions.g_free(dir_utf8);
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getHomeDir()
        {
            var dir_opsys = LibGumFunctions.g_get_home_dir();
            var dir_utf8 = LibGumFunctions.g_filename_display_name(dir_opsys);
            var result = dir_utf8.readUtf8String()!;
            LibGumFunctions.g_free(dir_utf8);
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getTmpDir()
        {
            var dir_opsys = LibGumFunctions.g_get_tmp_dir();
            var dir_utf8 = LibGumFunctions.g_filename_display_name(dir_opsys);
            var result = dir_utf8.readUtf8String()!;
            LibGumFunctions.g_free(dir_utf8);
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getUserName()
        {
            var dir_opsys = LibGumFunctions.g_get_user_name();
            var result = dir_opsys.readUtf8String()!;
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getRealName()
        {
            var dir_opsys = LibGumFunctions.g_get_real_name();
            var result = dir_opsys.readUtf8String()!;
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getHostName()
        {
            var dir_opsys = LibGumFunctions.g_get_host_name();
            var result = dir_opsys.readUtf8String()!;
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static string getApplicationName()
        {
            var dir_opsys = LibGumFunctions.g_get_application_name();
            var result = dir_opsys.readUtf8String()!;
            LibGumFunctions.g_free(dir_opsys);
            return result;
        }
        public static GumThreadId getCurrentThreadId()
        {
            return LibGumFunctions.gum_process_get_current_thread_id();
        }
        public static bool isDebuggerAttached()
        {
            return LibGumFunctions.gum_process_is_debugger_attached() != 0;
        }
        public static RangeDetails? findRangeByAddress(IntPtr address)
        {
            RangeDetails? range = null;
            LibGumFunctions.gum_process_enumerate_ranges(GumPageProtection.GUM_PAGE_NO_ACCESS, (d, data) =>
            {
                var a = d->range->base_address;
                var b = d->range->base_address + d->range->size;
                if (address >= a && address < b)
                {
                    range = new RangeDetails
                    {
                        baseAddress = d->range->base_address,
                        size = d->range->size,
                        protection = d->protection,
                    };
                    if (d->file != null)
                    {
                        range.file = new()
                        {
                            offset = d->file->offset,
                            size = d->file->size,
                        };
                        if (!d->file->path.isNull())
                        {
                            range.file.path = Marshal.PtrToStringUTF8(new IntPtr(d->file->path));
                        }
                    }
                    return 0;
                }
                return 1;
            }, IntPtr.Zero);
            return range;
        }

        public static void setExceptionHandler(IntPtr handler, IntPtr user_data)
        {
            LibGumFunctions.gum_exceptor_add(Gum.exceptor, handler, user_data);
        }

        public static ThreadDetails getCurrentThread()
        {
            var tid = getCurrentThreadId();
            return Process.enumerateThreads().Find(e => e.id == tid)!;
        }
    }
}