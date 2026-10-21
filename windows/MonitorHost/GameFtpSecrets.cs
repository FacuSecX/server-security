using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FacuSecX.Monitor;

// Only the service backend can call these operations. Passwords never enter the
// public game inventory, remote account database, registry or process arguments.
internal static class GameFtpSecrets
{
    internal static string ScopeFor(string host, int port, string user, string fingerprint, string serverId = "")
    {
        if (serverId.Length != 0 && !ServerProfiles.ValidId(serverId)) throw new IOException("Perfil de servidor no válido.");
        var fields = new List<string> { host, port.ToString(System.Globalization.CultureInfo.InvariantCulture), user, fingerprint };
        if (serverId.Length != 0) fields.Add(serverId);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", fields)))).ToLowerInvariant();
    }

    internal static string ScopeForProfile(JsonObject profile)
    {
        var id = profile["id"]?.GetValue<string>();
        if (!ServerProfiles.ValidId(id) || profile["legacy"] is not JsonValue legacy || !legacy.TryGetValue<bool>(out var isLegacy)) throw new IOException("Perfil de servidor no válido.");
        var ssh = profile["settings"]!.AsObject();
        return ScopeFor(ssh["host"]!.GetValue<string>(), ssh["port"]?.GetValue<int>() ?? 22, ssh["user"]!.GetValue<string>(), ssh["fingerprint"]!.GetValue<string>(), isLegacy ? "" : id!);
    }

    internal static string Scope()
    {
        var active = new ServerProfiles().Active();
        if (active != null) return ScopeForProfile(active);
        var ssh = State.Read("ssh.dpapi", "ssh") ?? throw new IOException("Falta la conexión protegida.");
        return ScopeFor(ssh["host"]!.GetValue<string>(), ssh["port"]?.GetValue<int>() ?? 22, ssh["user"]!.GetValue<string>(), ssh["fingerprint"]!.GetValue<string>());
    }

    internal static void Validate(JsonObject entry)
    {
        if (entry.Count != 4 || !Regex.IsMatch(entry["scope"]?.GetValue<string>() ?? "", "^[a-f0-9]{64}$") ||
            !Regex.IsMatch(entry["id"]?.GetValue<string>() ?? "", "^[a-f0-9]{32}$") ||
            !Regex.IsMatch(entry["username"]?.GetValue<string>() ?? "", "^[a-z][a-z0-9_-]{2,31}$") ||
            !Regex.IsMatch(entry["password"]?.GetValue<string>() ?? "", "^[A-Za-z0-9_-]{32,128}$"))
            throw new IOException("Credencial FTP no válida.");
    }

    internal static JsonArray Load() => ReadEntries(State.Read("game-ftp.dpapi", "game-ftp"));

    internal static JsonArray ReadEntries(JsonObject? snapshot)
    {
        // A loaded array already belongs to its snapshot. Detach before Save/Clear
        // attach it to a new snapshot; otherwise a reinstall throws on the second write.
        var entries = snapshot?["entries"]?.DeepClone().AsArray() ?? new JsonArray();
        if (entries.Count > 32) throw new IOException("Almacén FTP no válido.");
        foreach (var entry in entries) Validate(entry!.AsObject());
        if (entries.Select(x => x!["scope"]!.GetValue<string>()).Distinct().Count() != entries.Count) throw new IOException("Credenciales FTP duplicadas.");
        return entries;
    }

    internal static void Save(JsonObject entry)
    {
        Validate(entry);
        if (entry["scope"]!.GetValue<string>() != Scope()) throw new UnauthorizedAccessException();
        var entries = Load();
        for (var i = entries.Count - 1; i >= 0; i--) if (entries[i]!["scope"]!.GetValue<string>() == Scope()) entries.RemoveAt(i);
        if (entries.Count >= 32) throw new IOException("Se alcanzó el límite de credenciales FTP.");
        entries.Add(entry.DeepClone());
        State.Write("game-ftp.dpapi", "game-ftp", new() { ["entries"] = entries });
    }

    internal static JsonObject Read(string scope, string id, string username)
    {
        if (scope != Scope()) throw new UnauthorizedAccessException();
        return Load().OfType<JsonObject>().SingleOrDefault(x => x["scope"]!.GetValue<string>() == scope && x["id"]!.GetValue<string>() == id && x["username"]!.GetValue<string>() == username)?.DeepClone().AsObject()
            ?? throw new IOException("La contraseña FTP no está guardada en esta instalación del panel.");
    }

    internal static void Clear(string scope, string? id)
    {
        if (scope != Scope()) throw new UnauthorizedAccessException();
        var entries = Load();
        for (var i = entries.Count - 1; i >= 0; i--) if (entries[i]!["scope"]!.GetValue<string>() == scope && (id == null || entries[i]!["id"]!.GetValue<string>() == id)) entries.RemoveAt(i);
        State.Write("game-ftp.dpapi", "game-ftp", new() { ["entries"] = entries });
    }
}
