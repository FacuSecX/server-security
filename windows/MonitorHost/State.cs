using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace FacuSecX.Monitor;

internal static class State
{
    internal const string ServiceName = "FacuSecXMonitor";
    internal const string RegistryPath = @"SOFTWARE\FacuSecX\ServerSecurityMonitor\ProtectedV2";
    internal static readonly string DirectoryPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "FacuSecX", "ServerSecurityMonitor", "ProtectedV2");
    internal static readonly string InstallPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "FacuSecX", "ServerSecurityMonitor");
    internal static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    internal static string FilePath(string name) => Path.Combine(DirectoryPath, name);
    internal static RegistryKey OpenRegistry(RegistryKey root, string path, bool writable) =>
        root.OpenSubKey(path, writable ? RegistryKeyPermissionCheck.ReadWriteSubTree : RegistryKeyPermissionCheck.ReadSubTree,
            System.Security.AccessControl.RegistryRights.ReadKey | (writable ? System.Security.AccessControl.RegistryRights.SetValue : 0))
        ?? throw new InvalidOperationException("La instalación protegida no está registrada. Ejecutá su instalador.");
    internal static RegistryKey Registry(bool writable = false) => OpenRegistry(Microsoft.Win32.Registry.LocalMachine, RegistryPath, writable);
    internal static string Value(string name) { using var key = Registry(); return key.GetValue(name) as string ?? throw new InvalidOperationException("El registro de instalación está incompleto."); }
    internal static bool IsEnrolled { get { using var key = Registry(); return (int)(key.GetValue("Enrolled") ?? 0) == 1; } }
    private static void MarkEnrolled(RegistryKey key) { key.SetValue("Enrolled", 1, RegistryValueKind.DWord); key.Flush(); }
    internal static void MarkEnrolled() { using var key = Registry(true); MarkEnrolled(key); }
    internal static string PipeName => "FacuSecX.Monitor." + Value("InstallId");
    internal static byte[] Entropy(string purpose) => SHA256.HashData(Encoding.UTF8.GetBytes("FacuSecX.ProtectedV2/" + Value("InstallId") + "/" + purpose));

    internal static void CheckPath(string path)
    {
        for (var item = new DirectoryInfo(Path.GetDirectoryName(path)!); item != null; item = item.Parent)
            if (item.Exists && item.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException("La ruta protegida no admite enlaces ni redirecciones.");
        if (File.Exists(path) && ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0 || new FileInfo(path).Length > 2_097_152)) throw new IOException("Archivo protegido no válido.");
    }
    internal static JsonObject? Read(string name, string purpose)
    {
        var path = FilePath(name); CheckPath(path);
        if (!File.Exists(path)) return null;
        byte[] clear = ProtectedData.Unprotect(File.ReadAllBytes(path), Entropy(purpose), DataProtectionScope.LocalMachine);
        try { return JsonNode.Parse(clear)?.AsObject() ?? throw new IOException("Archivo protegido vacío."); }
        finally { CryptographicOperations.ZeroMemory(clear); }
    }
    internal static void Write(string name, string purpose, JsonObject value)
    {
        var path = FilePath(name); CheckPath(path);
        byte[] clear = Encoding.UTF8.GetBytes(value.ToJsonString());
        byte[] encrypted;
        try { encrypted = ProtectedData.Protect(clear, Entropy(purpose), DataProtectionScope.LocalMachine); }
        finally { CryptographicOperations.ZeroMemory(clear); }
        var temporary = path + "." + Convert.ToHexString(RandomNumberGenerator.GetBytes(12)) + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough)) { stream.Write(encrypted); stream.Flush(true); }
            if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
    internal static void ValidateAccounts(JsonObject accounts)
    {
        if (accounts["version"]?.GetValue<int>() != 1 || accounts["users"] is not JsonArray users || users.Count is < 1 or > 100) throw new IOException("Almacén de cuentas no válido.");
        var primary = users.OfType<JsonObject>().Where(x => x["primary"]?.GetValue<bool>() == true).ToArray();
        if (primary.Length != 1 || primary[0]["id"]?.GetValue<string>() != "primary-admin") throw new IOException("La identidad del administrador principal no es válida.");
        // The backend applies the full schema, password and permissions validation too.
        foreach (var user in users.OfType<JsonObject>())
            if (!System.Text.RegularExpressions.Regex.IsMatch(user["salt"]?.GetValue<string>() ?? "", "^[a-f0-9]{32}$") || !System.Text.RegularExpressions.Regex.IsMatch(user["hash"]?.GetValue<string>() ?? "", "^[a-f0-9]{64}$")) throw new IOException("Verificador de contraseña no válido.");
    }
    internal static string Mode()
    {
        try
        {
            var main = Read("accounts.dpapi", "accounts"); var checkpoint = Read("checkpoint.dpapi", "checkpoint");
            return Evaluate(IsEnrolled, main, checkpoint);
        }
        catch { return "recovery"; }
    }
    internal static string Evaluate(bool enrolled, JsonObject? main, JsonObject? checkpoint)
    {
        if (main == null && checkpoint == null && !enrolled) return "setup";
        if (!enrolled || main == null || checkpoint == null) return "recovery";
        try
        {
            ValidateAccounts(main["accounts"]!.AsObject()); ValidateAccounts(checkpoint["accounts"]!.AsObject());
            if (main["revision"]?.GetValue<long>() is not long revision || revision < 1 || revision != checkpoint["revision"]?.GetValue<long>() || !JsonNode.DeepEquals(main["accounts"], checkpoint["accounts"])) return "recovery";
            return "ready";
        }
        catch { return "recovery"; }
    }
    internal static void Save(JsonObject accounts, bool initialize = false)
    {
        ValidateAccounts(accounts);
        if (!initialize && Mode() != "ready") throw new IOException("Restaurá el almacén antes de modificar cuentas.");
        // Check the service's minimum registry rights before creating a snapshot.
        using var registration = Registry(true);
        var old = Read("checkpoint.dpapi", "checkpoint");
        var revision = (old?["revision"]?.GetValue<long>() ?? 0) + 1;
        var snapshot = new JsonObject { ["revision"] = revision, ["accounts"] = accounts.DeepClone() };
        // Checkpoint first: a failure between the two atomic writes enters recovery, never setup.
        Write("checkpoint.dpapi", "checkpoint", snapshot);
        MarkEnrolled(registration);
        Write("accounts.dpapi", "accounts", snapshot);
    }
    internal static void Recover()
    {
        if (Mode() != "recovery") throw new IOException("No hay una recuperación pendiente.");
        var checkpoint = Read("checkpoint.dpapi", "checkpoint") ?? throw new IOException("Falta el respaldo protegido. Restaurá una copia externa mediante el instalador.");
        ValidateAccounts(checkpoint["accounts"]!.AsObject());
        MarkEnrolled(); Write("accounts.dpapi", "accounts", checkpoint);
    }
    internal static bool Elevated => new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
    internal static SecurityIdentifier ServiceSid => (SecurityIdentifier)new NTAccount("NT SERVICE", ServiceName).Translate(typeof(SecurityIdentifier));
}
