using aadog.PInvoke.LibGum;
namespace aadog.PInvoke.Frida.Gum
{
    public static unsafe class Gum
    {
        public static GumExceptor* exceptor = null;
        public static GumInterceptor* interceptor = null;
        public static bool embed;

        public static void Init(bool isEmbed)
        {
            embed = isEmbed;
            if (embed)
            {
                LibGumFunctions.gum_init_embedded();
            }
            else
            {
                LibGumFunctions.gum_init();
            }

            exceptor = LibGumFunctions.gum_exceptor_obtain();
            interceptor = LibGumFunctions.gum_interceptor_obtain();
        }

        public static void DeInit()
        {
            LibGumFunctions.g_object_unref(exceptor);
            LibGumFunctions.g_object_unref(interceptor);
            if (embed)
            {
                LibGumFunctions.gum_deinit_embedded();
            }
            else
            {
                LibGumFunctions.gum_deinit();
            }
        }
    }
}
