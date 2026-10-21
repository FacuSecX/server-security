using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class SetupTransaction
{
    internal static string Revision()
    {
        string path = State.FilePath("ssh.pending.dpapi");
        if (!File.Exists(path)) path = State.FilePath("ssh.dpapi");
        State.CheckPath(path);
        return Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
    }
    internal static bool Healthy(JsonObject health, string installation, string revision) =>
        health["app"]?.GetValue<string>() == "storypulse-security" && health["protected_runtime"]?.GetValue<bool>() == true &&
        health["installation_ready"]?.GetValue<bool>() == true && health["installation_id"]?.GetValue<string>() == installation &&
        health["installation_revision"]?.GetValue<string>() == revision && health["installation_mode"]?.GetValue<string>() is "ready" or "setup";

    internal static int Commit(string[] args, bool commit = true)
    {
        if (!State.Elevated || WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid") ||
            !string.Equals(AppContext.BaseDirectory.TrimEnd('\\'), Path.Combine(State.InstallPath, "native"), StringComparison.OrdinalIgnoreCase)) throw new UnauthorizedAccessException();
        using var anchor = State.Registry(true);
        if ((int)(anchor.GetValue("Activated") ?? 0) == 1 || (int)(anchor.GetValue("SetupPending") ?? 0) != 1) throw new IOException("No hay una configuración pendiente de activar.");
        if (args.Length != 1 || !int.TryParse(args[0], out int port) || port is < 1 or > 65535) throw new IOException("Puerto local no válido.");
        using var client = new HttpClient(new HttpClientHandler { UseProxy = false, AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(25) };
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        async Task<string> Get(string path, int maximum)
        {
            using var response = await client.GetAsync("http://127.0.0.1:" + port + path, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
            if (response.StatusCode != HttpStatusCode.OK || response.Content.Headers.ContentLength > maximum) throw new IOException("El panel no respondió correctamente. Podés reanudar el asistente.");
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token); using var output = new MemoryStream();
            var buffer = new byte[8192]; int count;
            while ((count = await input.ReadAsync(buffer, timeout.Token)) > 0) { if (output.Length + count > maximum) throw new IOException("Respuesta del panel no válida."); output.Write(buffer, 0, count); }
            return Encoding.UTF8.GetString(output.ToArray());
        }
        var health = JsonNode.Parse(Get("/api/health", 16384).GetAwaiter().GetResult())!.AsObject();
        if (!Healthy(health, State.Value("InstallId"), Revision())) throw new IOException("La conexión o el acceso al panel todavía no se verificaron. Reanudá el asistente para corregirlos.");
        if (!Get("/login", 524288).GetAwaiter().GetResult().Contains("id=\"panelLogin\"", StringComparison.Ordinal) ||
            !Get("/auth.js", 524288).GetAwaiter().GetResult().Contains("/api/auth/login", StringComparison.Ordinal)) throw new IOException("La pantalla de acceso al panel no está disponible. La configuración no se activó.");

        if (!commit) return 0;
        if ((int)(anchor.GetValue("RefreshLegacy") ?? 0) == 1)
        {
            var legacy = State.Value("LegacyPath"); State.CheckPath(legacy);
            if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(legacy))) != State.Value("LegacyDigest")) throw new IOException("Las cuentas anteriores cambiaron. No se reemplazarán.");
            var accounts = State.Read("accounts.dpapi", "accounts")!["accounts"]!;
            var clear = Encoding.UTF8.GetBytes(accounts.ToJsonString()); byte[] encrypted;
            try { encrypted = ProtectedData.Protect(clear, Encoding.UTF8.GetBytes("FacuSecX.ServerSecurityMonitor.Accounts.v1"), DataProtectionScope.CurrentUser); }
            finally { CryptographicOperations.ZeroMemory(clear); }
            var temporary = legacy + "." + Guid.NewGuid().ToString("N") + ".tmp";
            try { using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { file.Write(encrypted); file.Flush(true); } File.Replace(temporary, legacy, null); }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
            anchor.SetValue("LegacyDigest", Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(legacy))));
            anchor.SetValue("RefreshLegacy", 0); anchor.Flush();
        }
        var pending = State.FilePath("ssh.pending.dpapi"); var active = State.FilePath("ssh.dpapi"); State.CheckPath(pending); State.CheckPath(active);
        if (File.Exists(pending)) { if (File.Exists(active)) File.Replace(pending, active, null); else File.Move(pending, active); }
        anchor.SetValue("Activated", 1); anchor.SetValue("SetupPending", 0); anchor.Flush();
        return 0;
    }
}
