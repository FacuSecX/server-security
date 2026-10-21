using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Renci.SshNet;

namespace FacuSecX.Monitor;

internal sealed class SshTransport : IDisposable
{
    private readonly Func<JsonObject> settingsProvider;
    private readonly Func<string, bool>? trustFirstKey;
    internal SshTransport(Func<JsonObject>? settingsProvider = null, Func<string, bool>? trustFirstKey = null)
    {
        this.settingsProvider = settingsProvider ?? PendingSettings;
        this.trustFirstKey = trustFirstKey;
    }
    internal static JsonObject PendingSettings()
    {
        using var anchor = State.Registry();
        bool pending = (int)(anchor.GetValue("Activated") ?? 0) != 1 && (int)(anchor.GetValue("SetupPending") ?? 0) == 1;
        if (pending) return State.Read("ssh.pending.dpapi", "ssh") ?? State.Read("ssh.dpapi", "ssh") ?? throw new IOException("Falta configurar la conexión SSH protegida.");
        var profile = new ServerProfiles().Active();
        var settings = profile?["settings"]?.DeepClone().AsObject() ?? State.Read("ssh.dpapi", "ssh") ?? throw new IOException("Falta configurar la conexión SSH protegida.");
        if (profile?["identity"] != null) settings["machineId"] = profile["identity"]!.DeepClone();
        return settings;
    }
    private readonly SemaphoreSlim connectionLock = new(1, 1);
    private SshClient? client;
    private PrivateKeyFile? key;
    internal async Task<SshClient> Connect(CancellationToken cancellation)
    {
        await connectionLock.WaitAsync(cancellation);
        try
        {
            if (client?.IsConnected == true) return client;
            client?.Dispose(); key?.Dispose();
            var settings = settingsProvider();
            var host = settings["host"]!.GetValue<string>(); var user = settings["user"]!.GetValue<string>(); var port = settings["port"]!.GetValue<int>();
            AuthenticationMethod method;
            if (settings["mode"]!.GetValue<string>() == "key")
            {
                var bytes = Convert.FromBase64String(settings["privateKey"]!.GetValue<string>());
                try { using var stream = new MemoryStream(bytes); key = new PrivateKeyFile(stream, settings["secret"]!.GetValue<string>()); }
                finally { CryptographicOperations.ZeroMemory(bytes); }
                method = new PrivateKeyAuthenticationMethod(user, key);
            }
            else if (settings["mode"]!.GetValue<string>() == "password") method = new PasswordAuthenticationMethod(user, settings["secret"]!.GetValue<string>());
            else throw new IOException("Método de autenticación SSH no válido.");
            var connection = new ConnectionInfo(host, port, user, method) { Timeout = TimeSpan.FromSeconds(15) };
            client = new SshClient(connection) { KeepAliveInterval = TimeSpan.FromSeconds(15) };
            var pin = settings["fingerprint"]!.GetValue<string>().TrimEnd('=');
            client.HostKeyReceived += (_, args) => {
                var actual = "SHA256:" + Convert.ToBase64String(SHA256.HashData(args.HostKey)).TrimEnd('=');
                args.CanTrust = pin.Length != 0 ? string.Equals(actual, pin, StringComparison.Ordinal) : trustFirstKey?.Invoke(actual) == true;
                if (args.CanTrust && pin.Length == 0) settings["fingerprint"] = actual;
            };
            await client.ConnectAsync(cancellation);
            try { if (settings["machineId"] != null) {
                using var identity = client.CreateCommand("cat /etc/machine-id"); identity.CommandTimeout = TimeSpan.FromSeconds(10); await identity.ExecuteAsync(cancellation);
                if (identity.ExitStatus != 0 || identity.Result.Trim() != settings["machineId"]!.GetValue<string>()) { client.Disconnect(); throw new IOException("La identidad del servidor cambió. No se cargarán datos de otro sistema."); }
            } } catch { client.Disconnect(); throw; }
            return client;
        }
        finally { connectionLock.Release(); }
    }
    internal async Task<int> Run(string commandText, byte[] input, Func<JsonObject, Task> send, CancellationToken cancellation)
    {
        if (commandText.Length is < 1 or > 1_500_000 || commandText.Contains('\0') || input.Length > 18_000_000) throw new IOException("Comando SSH fuera de los límites permitidos.");
        var connection = await Connect(cancellation);
        using var command = connection.CreateCommand(commandText); command.CommandTimeout = TimeSpan.FromMinutes(60);
        var execution = command.ExecuteAsync(cancellation);
        async Task Forward(Stream stream, string kind)
        {
            var buffer = new byte[32_768];
            while (true) { int length = await stream.ReadAsync(buffer, cancellation); if (length == 0) break; await send(new() { ["stream"] = kind, ["data"] = Convert.ToBase64String(buffer, 0, length) }); }
        }
        // SSH.NET exposes stdin once command execution has started.
        using (var stdin = command.CreateInputStream()) { if (input.Length != 0) await stdin.WriteAsync(input, cancellation); }
        await Task.WhenAll(execution, Forward(command.OutputStream, "stdout"), Forward(command.ExtendedOutputStream, "stderr"));
        return command.ExitStatus ?? 1;
    }
    public void Dispose() { client?.Dispose(); key?.Dispose(); connectionLock.Dispose(); }
}
