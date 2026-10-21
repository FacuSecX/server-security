using Microsoft.Win32;
using System.Security.AccessControl;
using System.Security.Principal;

namespace FacuSecX.Monitor;

internal static class RegistryPermissionTests
{
    internal static int Run()
    {
        var path = @"Software\FacuSecX-RegistryTest-" + Guid.NewGuid().ToString("N");
        using var key = Registry.CurrentUser.CreateSubKey(path, RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryOptions.Volatile);
        var original = key.GetAccessControl();
        int passed = 0;
        try
        {
            var sid = WindowsIdentity.GetCurrent().User!;
            var security = new RegistrySecurity(); security.SetAccessRuleProtection(true, false); security.SetOwner(sid);
            security.AddAccessRule(new RegistryAccessRule(sid, RegistryRights.CreateSubKey, AccessControlType.Deny));
            security.AddAccessRule(new RegistryAccessRule(sid, RegistryRights.ReadKey | RegistryRights.SetValue, AccessControlType.Allow));
            key.SetAccessControl(security);
            try { using var legacy = Registry.CurrentUser.OpenSubKey(path, true); throw new IOException("The old broad registry request unexpectedly passed."); }
            catch (Exception error) when (error is UnauthorizedAccessException or System.Security.SecurityException) { passed++; }
            using var limited = State.OpenRegistry(Registry.CurrentUser, path, true);
            limited.SetValue("Enrolled", 1, RegistryValueKind.DWord); limited.Flush();
            if ((int)limited.GetValue("Enrolled")! != 1) throw new IOException("The minimum registry request failed.");
            passed++;
        }
        finally { key.SetAccessControl(original); key.Dispose(); Registry.CurrentUser.DeleteSubKeyTree(path, false); }
        return passed;
    }
}
