using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FacuSecX.Monitor;

// One encrypted store for SSH profiles. Account enrollment stays in State's
// installation-wide account/checkpoint store and is never changed here.
internal sealed class ServerProfiles
{
    private readonly Func<JsonObject?> read;
    private readonly Action<JsonObject> write;
    internal ServerProfiles(Func<JsonObject?>? read = null, Action<JsonObject>? write = null)
    { this.read = read ?? (() => State.Read("servers.dpapi", "servers")); this.write = write ?? (value => State.Write("servers.dpapi", "servers", value)); }

    internal static bool ValidId(string? id) => Regex.IsMatch(id ?? "", "^[a-f0-9]{32}$");
    internal static string Id(JsonObject settings) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        settings["host"]!.GetValue<string>().ToLowerInvariant() + "\n" + settings["port"]!.GetValue<int>() + "\n" + settings["user"]!.GetValue<string>() + "\n" + settings["fingerprint"]!.GetValue<string>().TrimEnd('=')))).ToLowerInvariant()[..32];
    internal static string Label(string value)
    {
        value = value.Trim();
        if (value.Length is < 1 or > 80 || value.Any(char.IsControl)) throw new IOException("Ingresá un nombre de servidor de hasta 80 caracteres.");
        return value;
    }
    internal static void ValidateSettings(JsonObject value)
    {
        if (value.Count > 8 || SshSettings.Host(value["host"]!.GetValue<string>()) != value["host"]!.GetValue<string>() || value["port"]!.GetValue<int>() is < 1 or > 65535 || !Regex.IsMatch(value["user"]!.GetValue<string>(), "^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}[$]?$")) throw new IOException("Datos SSH no válidos.");
        string mode = value["mode"]!.GetValue<string>(), secret = value["secret"]!.GetValue<string>();
        if (mode is not ("password" or "key") || secret.Length > 1024 || secret.Any(char.IsControl) || mode == "password" && secret.Length == 0) throw new IOException("El método o la credencial SSH no son válidos.");
        string pin = value["fingerprint"]!.GetValue<string>();
        if (!Regex.IsMatch(pin, "^SHA256:[A-Za-z0-9+/]{43}$")) throw new IOException("Verificá la huella del servidor antes de guardar.");
        if (mode == "key")
        {
            var bytes = Convert.FromBase64String(value["privateKey"]!.GetValue<string>());
            try { if (bytes.Length is < 1 or > 262144) throw new IOException("Llave fuera de los límites permitidos."); using var stream = new MemoryStream(bytes); using var key = new Renci.SshNet.PrivateKeyFile(stream, secret); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
    }
    internal JsonObject Load()
    {
        var store = read() ?? new JsonObject { ["version"] = 1, ["active"] = "", ["profiles"] = new JsonArray() };
        if (store["version"]?.GetValue<int>() != 1 || store["profiles"] is not JsonArray rows || rows.Count > 100) throw new IOException("El registro de servidores no es válido. Se conserva para recuperación.");
        var ids = new HashSet<string>();
        if (rows.Count != rows.OfType<JsonObject>().Count()) throw new IOException("Hay una conexión dañada en el registro de servidores.");
        foreach (var row in rows.OfType<JsonObject>())
        {
            var id = row["id"]?.GetValue<string>();
            if (!ValidId(id) || !ids.Add(id!)) throw new IOException("Identidad de servidor no válida.");
            Label(row["label"]!.GetValue<string>()); ValidateSettings(row["settings"]!.AsObject());
            if (row["legacy"] is not JsonValue legacy || !legacy.TryGetValue<bool>(out _)) throw new IOException("El espacio de datos del servidor no es válido.");
            if (row["identity"] != null && !Regex.IsMatch(row["identity"]!.GetValue<string>(),"^[a-f0-9]{32}$")) throw new IOException("La identidad del sistema no es válida.");
        }
        string active = store["active"]!.GetValue<string>();
        if (rows.OfType<JsonObject>().Count(row => row["legacy"]!.GetValue<bool>()) > 1) throw new IOException("El historial original no puede pertenecer a dos servidores.");
        if (active.Length != 0 && !ids.Contains(active)) throw new IOException("Falta el servidor activo. No se usarán datos de otra conexión.");
        return store;
    }
    internal void Save(JsonObject value) { if (Encoding.UTF8.GetByteCount(value.ToJsonString()) > 1_800_000) throw new IOException("El almacén de conexiones alcanzó su capacidad. No se modificaron los perfiles anteriores."); write(value); }
    internal JsonObject? Active() { var data = Load(); return data["profiles"]!.AsArray().OfType<JsonObject>().SingleOrDefault(row => row["id"]!.GetValue<string>() == data["active"]!.GetValue<string>()); }
    internal JsonObject Get(string id) => Load()["profiles"]!.AsArray().OfType<JsonObject>().SingleOrDefault(row => row["id"]!.GetValue<string>() == id)?.DeepClone().AsObject() ?? throw new IOException("No se encontró la conexión seleccionada.");
    internal JsonObject Listing()
    {
        var store = Load();
        return new JsonObject { ["active"] = store["active"]!.DeepClone(), ["profiles"] = new JsonArray(store["profiles"]!.AsArray().OfType<JsonObject>().Select(row => (JsonNode)new JsonObject {
            ["id"] = row["id"]!.DeepClone(), ["label"] = row["label"]!.DeepClone(), ["host"] = row["settings"]!["host"]!.DeepClone(), ["port"] = row["settings"]!["port"]!.DeepClone(), ["user"] = row["settings"]!["user"]!.DeepClone(), ["lastConnected"] = row["lastConnected"]?.DeepClone() }).ToArray()) };
    }
    internal JsonObject WithActive(JsonObject profile)
    {
        var store = Load(); var rows = store["profiles"]!.AsArray(); string id = profile["id"]!.GetValue<string>();
        int index = rows.ToList().FindIndex(row => row!["id"]!.GetValue<string>() == id);
        if (index < 0 && rows.Count >= 100) throw new IOException("Ya hay 100 servidores guardados.");
        if (index < 0) rows.Add(profile.DeepClone()); else rows[index] = profile.DeepClone();
        store["active"] = id; return store;
    }
    internal void MigrateLegacy()
    {
        if (read() != null) { Load(); return; }
        using var registry = State.Registry(); if ((int)(registry.GetValue("Activated") ?? 0) != 1) return;
        var settings = State.Read("ssh.dpapi", "ssh") ?? throw new IOException("Falta la conexión existente. No se creará otra cuenta."); ValidateSettings(settings);
        string id = Id(settings);
        Save(WithActive(new JsonObject { ["id"] = id, ["label"] = settings["host"]!.DeepClone(), ["settings"] = settings.DeepClone(), ["legacy"] = true }));
    }
    internal static JsonObject PublicSettings(JsonObject profile)
    {
        var s = profile["settings"]!.AsObject();
        return new JsonObject { ["host"] = s["host"]!.DeepClone(), ["port"] = s["port"]!.DeepClone(), ["user"] = s["user"]!.DeepClone(), ["hostKeyFingerprint"] = s["fingerprint"]!.DeepClone(), ["authMode"] = "key", ["keyPath"] = "", ["plinkPath"] = Path.Combine(State.InstallPath, "native", "FacuSecX.SshBridge.exe") };
    }
}

internal sealed class ServerSelectionProof
{
    private readonly Func<DateTime> now;
    private readonly Func<string> publicKey, algorithm;
    private string? token;
    private byte[] message = [];
    private DateTime expires;
    internal ServerSelectionProof(Func<string>? publicKey = null, Func<string>? algorithm = null, Func<DateTime>? now = null)
    { this.publicKey = publicKey ?? (() => State.Value("OwnerPublicKey")); this.algorithm = algorithm ?? (() => State.Value("OwnerAlgorithm")); this.now = now ?? (() => DateTime.UtcNow); }
    internal JsonObject Issue(string installation, JsonObject profile)
    {
        token = Guid.NewGuid().ToString("N"); expires = now().AddMinutes(2);
        var digest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(profile.ToJsonString())));
        message = Encoding.UTF8.GetBytes("FacuSecX/ServerSelection/v1\n" + installation + "\n" + token + "\n" + digest + "\n" + Convert.ToHexString(RandomNumberGenerator.GetBytes(32)));
        return new JsonObject { ["token"] = token, ["message"] = Convert.ToBase64String(message) };
    }
    internal void Consume(string candidate, string signature)
    {
        bool current = token == candidate && now() < expires; token = null;
        if (!current || !HelloProof.Check(publicKey(), message, Convert.FromBase64String(signature), algorithm())) throw new UnauthorizedAccessException("Windows Hello no autorizó esta conexión. No se guardaron cambios.");
    }
}
