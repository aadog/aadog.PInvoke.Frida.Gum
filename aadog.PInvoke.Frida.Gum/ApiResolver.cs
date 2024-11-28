using aadog.PInvoke.LibGum;
using aadog.PInvoke.Base;

namespace aadog.PInvoke.Frida.Gum
{
    public unsafe class ApiResolver(string apiResolverType)
    {
        public List<ApiResolverMatch> enumerateMatches(string query)
        {
            var result = new List<ApiResolverMatch>();
            GumApiResolver* apiResolver = LibGumFunctions.gum_api_resolver_make(apiResolverType);
            GError* error = null;
            LibGumFunctions.gum_api_resolver_enumerate_matches(apiResolver, query, (d, b) =>
            {
                result.Add(new()
                {
                    name = d->name.readUtf8String(),
                    size = (guint)d->size,
                    address = d->address
                });
                return 1;
            }, IntPtr.Zero, &error);
            var errorMessage = MarshalExt.ConvertLPErrorToString(error);
            if (errorMessage != null)
            {
                throw new GumException(errorMessage);
            }
            LibGumFunctions.g_object_unref(apiResolver);

            return result;
        }
    }
}
