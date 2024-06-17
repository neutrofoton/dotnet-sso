namespace TheIdentityServer.Data
{
    public class ConstantPermission
    {
        public static readonly string View = "view";
        public static readonly string Edit = "edit";
        public static readonly string Delete = "delete";
        public static readonly string Create = "create";
    }

    public class ConstantRole
    {
        public static readonly string Basic = "basic";
        public static readonly string User = "user";
        public static readonly string SystemAdmin = "system-administrator";
        public static readonly string TenantAdmin = "tenant-administrator";
    }

    public class Constant
    {
        public const string DefaultPassword = "P@ssw0rd";
    }
}
