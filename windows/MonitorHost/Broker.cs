using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal sealed class Broker : IDisposable
{
    private readonly HelloProof hello = new();
    private SshTransport ssh = new();
    private readonly ServerProfiles profiles = new();
    private readonly ServerSelectionProof serverProof = new();
    private readonly SemaphoreSlim serversLock = new(1,1);
    private JsonObject? preparedServer;
    private readonly Func<JsonObject, CancellationToken, Task<int>>? selectServer;
    private volatile bool switching;
    private int activeSsh;
    private readonly Func<CancellationToken, Task>? disconnect;
    private readonly Func<JsonObject>? runtimeStatus;
    private readonly Action? closeService;
    internal static bool IsDesktopOperation(string op) => op is "runtime-status" or "runtime-disconnect" or "runtime-close";
    internal Broker(Func<JsonObject, CancellationToken, Task<int>>? selectServer = null, Func<CancellationToken, Task>? disconnect = null, Func<JsonObject>? runtimeStatus = null, Action? closeService = null)
    { this.selectServer = selectServer; this.disconnect = disconnect; this.runtimeStatus = runtimeStatus; this.closeService = closeService; }
    private void CheckServer(JsonObject request)
    {
        if (switching || (request["server"]?.GetValue<string>() ?? "") != (profiles.Active()?["id"]?.GetValue<string>() ?? "")) throw new IOException("La conexión cambió. Volvé a ingresar al panel del servidor seleccionado.");
    }
    internal async Task ResetSsh(CancellationToken cancellation)
    {
        switching = true;
        for (int i=0; Volatile.Read(ref activeSsh) != 0 && i<100; i++) await Task.Delay(100,cancellation);
        if (Volatile.Read(ref activeSsh) != 0) throw new IOException("La consulta anterior sigue finalizando. Volvé a intentar en unos segundos.");
        ssh.Dispose(); ssh = new(); reports.Clear();
    }
    internal void ResumeSsh() { switching = false; }
    private readonly SemaphoreSlim vaultLock = new(1, 1);
    private long agentSeen;
    private readonly System.Collections.Concurrent.ConcurrentQueue<JsonObject> reports = new();
    internal async Task Listen(CancellationToken cancellation)
    {
        while (!cancellation.IsCancellationRequested)
        {
            var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.NetworkSid, null), PipeAccessRights.FullControl, AccessControlType.Deny));
            security.AddAccessRule(new PipeAccessRule(State.ServiceSid, PipeAccessRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(State.Value("OwnerSid")), PipeAccessRights.ReadWrite, AccessControlType.Allow));
            security.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl, AccessControlType.Allow));
            var pipe = NamedPipeServerStreamAcl.Create(State.PipeName, PipeDirection.InOut, 16, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 65_536, 65_536, security);
            try { await pipe.WaitForConnectionAsync(cancellation); _ = Serve(pipe, cancellation); }
            catch { pipe.Dispose(); if (!cancellation.IsCancellationRequested) throw; }
        }
    }
    private async Task Serve(NamedPipeServerStream pipe, CancellationToken stopping)
    {
        using (pipe)
        using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(stopping))
        {
            timeout.CancelAfter(TimeSpan.FromMinutes(61)); var cancellation = timeout.Token;
            var writeLock = new SemaphoreSlim(1, 1);
            bool requestIsProfile = false;
            async Task Send(JsonObject value) { await writeLock.WaitAsync(cancellation); try { await Wire.Write(pipe, value, cancellation); } finally { writeLock.Release(); } }
            try
            {
                string? caller = null;
                pipe.RunAsClient(() => { using var identity = WindowsIdentity.GetCurrent(true); caller = identity?.User?.Value; });
                bool backend = caller == State.ServiceSid.Value;
                bool owner = caller == State.Value("OwnerSid");
                if (!backend && !owner) throw new UnauthorizedAccessException();
                timeout.CancelAfter(TimeSpan.FromSeconds(5));
                var request = await Wire.Read(pipe, cancellation, backend ? 25_000_000 : 400_000);
                timeout.CancelAfter(backend ? TimeSpan.FromMinutes(61) : TimeSpan.FromSeconds(110));
                _ = Task.Run(async () => { try { var probe = new byte[1]; await pipe.ReadExactlyAsync(probe, cancellation); timeout.Cancel(); } catch (EndOfStreamException) { try { timeout.Cancel(); } catch { } } catch { } }, cancellation);
                var op = request["op"]?.GetValue<string>() ?? "";
                bool profileOperation = op is "servers-list" or "server-prepare" or "server-commit";
                bool desktopOperation = IsDesktopOperation(op);
                requestIsProfile = profileOperation || desktopOperation;
                if (!backend && op is not ("agent-poll" or "agent-sign") && !profileOperation && !desktopOperation) throw new UnauthorizedAccessException("La operación sólo está disponible para el servicio protegido.");
                if ((profileOperation || desktopOperation) && !owner) throw new UnauthorizedAccessException();
                JsonObject result;
                switch (op)
                {
                    case "runtime-status":
                        result = runtimeStatus?.Invoke() ?? throw new IOException("El controlador del panel no está disponible."); break;
                    case "runtime-close":
                    case "runtime-disconnect":
                        await serversLock.WaitAsync(cancellation);
                        try {
                            preparedServer = null;
                            if (disconnect == null) throw new IOException("El controlador del panel no está disponible.");
                            await disconnect(cancellation);
                            result = new() { ["running"] = false };
                        } finally { serversLock.Release(); }
                        break;
                    case "servers-list": result = profiles.Listing(); break;
                    case "server-prepare":
                        await serversLock.WaitAsync(cancellation);
                        try {
                            preparedServer = null;
                            JsonObject candidate;
                            if (request["id"] != null) candidate = profiles.Get(request["id"]!.GetValue<string>());
                            else {
                                var settings = request["settings"]!.DeepClone().AsObject(); ServerProfiles.ValidateSettings(settings);
                                string id = Guid.NewGuid().ToString("N");
                                candidate = new JsonObject { ["id"] = id, ["label"] = ServerProfiles.Label(request["label"]!.GetValue<string>()), ["settings"] = settings, ["legacy"] = false };
                            }
                            using var probe = new SshTransport(() => candidate["settings"]!.AsObject());
                            using var probeTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation); probeTimeout.CancelAfter(TimeSpan.FromSeconds(35));
                            await SshSettings.Check(probe,probeTimeout.Token);
                            var client = await probe.Connect(probeTimeout.Token);
                            using var identityCommand = client.CreateCommand("cat /etc/machine-id"); identityCommand.CommandTimeout = TimeSpan.FromSeconds(10); await identityCommand.ExecuteAsync(probeTimeout.Token);
                            string identity = identityCommand.Result.Trim();
                            if (identityCommand.ExitStatus != 0 || !System.Text.RegularExpressions.Regex.IsMatch(identity,"^[a-f0-9]{32}$")) throw new IOException("No se pudo comprobar la identidad del sistema del servidor. La conexión no se guardó.");
                            if (candidate["identity"] != null && candidate["identity"]!.GetValue<string>() != identity) throw new IOException("El sistema de este servidor cambió. Agregalo como una conexión nueva con su huella SSH actual para conservar separado el historial anterior.");
                            if (request["id"] == null) {
                                var prior = profiles.Load()["profiles"]!.AsArray().OfType<JsonObject>().SingleOrDefault(row => ServerProfiles.Id(row["settings"]!.AsObject()) == ServerProfiles.Id(candidate["settings"]!.AsObject()) && (row["identity"] == null || row["identity"]!.GetValue<string>() == identity));
                                if (prior != null) { candidate["id"] = prior["id"]!.DeepClone(); candidate["legacy"] = prior["legacy"]!.DeepClone(); }
                            }
                            candidate["identity"] = identity; candidate["lastConnected"] = DateTime.UtcNow.ToString("O");
                            preparedServer = candidate; result = serverProof.Issue(State.Value("InstallId"),candidate);
                        } finally { serversLock.Release(); }
                        break;
                    case "server-commit":
                        await serversLock.WaitAsync(cancellation);
                        try {
                            var candidate = preparedServer ?? throw new IOException("Volvé a comprobar la conexión antes de continuar."); preparedServer = null;
                            serverProof.Consume(request["token"]!.GetValue<string>(),request["signature"]!.GetValue<string>());
                            if (selectServer == null) throw new IOException("El selector no está disponible en este proceso.");
                            int serverPort = await selectServer(candidate,cancellation);
                            result = new JsonObject { ["server"] = candidate["id"]!.DeepClone(), ["port"] = serverPort };
                        } finally { serversLock.Release(); }
                        break;
                    case "agent-poll":
                        Interlocked.Exchange(ref agentSeen, DateTime.UtcNow.Ticks); result = hello.Poll();
                        if (result["pending"]?.GetValue<bool>() != true && reports.TryDequeue(out var report)) result = report;
                        break;
                    case "agent-sign": result = new() { ["accepted"] = hello.Reply(request["id"]!.GetValue<string>(), request["signature"]!.GetValue<string>()) }; break;
                    case "hello-check": result = new() { ["available"] = DateTime.UtcNow.Ticks - Interlocked.Read(ref agentSeen) < TimeSpan.FromSeconds(10).Ticks, ["verified"] = false, ["result"] = 0 }; break;
                    case "hello-verify":
                        if (DateTime.UtcNow.Ticks - Interlocked.Read(ref agentSeen) > TimeSpan.FromSeconds(10).Ticks) throw new IOException("Abrí el panel desde su acceso directo para iniciar Windows Hello.");
                        var verified = await hello.Verify(request["purpose"]!.GetValue<string>(), cancellation);
                        result = new() { ["available"] = true, ["verified"] = verified, ["result"] = verified ? 0 : 6 }; break;
                    case "vault-status": result = new() { ["mode"] = State.Mode(), ["protected"] = true }; break;
                    case "vault-load": result = new() { ["accounts"] = State.Mode() == "ready" ? State.Read("accounts.dpapi", "accounts")!["accounts"]!.DeepClone() : null }; break;
                    case "vault-backup": result = new() { ["accounts"] = State.Read("checkpoint.dpapi", "checkpoint")?["accounts"]?.DeepClone() }; break;
                    case "vault-save": case "vault-enroll": case "vault-recover":
                        await vaultLock.WaitAsync(cancellation);
                        try
                        {
                            if (op == "vault-enroll") { if (State.Mode() != "setup") throw new IOException("La instalación ya tiene propietario."); hello.ConsumePermit("setup"); State.Save(request["accounts"]!.AsObject(), true); }
                            else if (op == "vault-recover") { hello.ConsumePermit("recovery"); State.Recover(); }
                            else State.Save(request["accounts"]!.AsObject());
                            result = new() { ["ok"] = true };
                        }
                        finally { vaultLock.Release(); }
                        break;
                    case "game-ftp-save": case "game-ftp-clear":
                        if (State.Mode() != "ready") throw new UnauthorizedAccessException("Restaurá el acceso local antes de administrar credenciales FTP.");
                        await vaultLock.WaitAsync(cancellation);
                        try
                        {
                            if (op == "game-ftp-save") GameFtpSecrets.Save(request["entry"]!.AsObject());
                            else GameFtpSecrets.Clear(request["scope"]!.GetValue<string>(), request["id"]?.GetValue<string>());
                            result = new() { ["saved"] = true };
                        }
                        finally { vaultLock.Release(); }
                        break;
                    case "game-ftp-load":
                        if (State.Mode() != "ready") throw new UnauthorizedAccessException();
                        hello.ConsumePermit("game-ftp");
                        result = new() { ["entry"] = GameFtpSecrets.Read(request["scope"]!.GetValue<string>(), request["id"]!.GetValue<string>(), request["username"]!.GetValue<string>()) };
                        break;
                    case "ssh-check":
                        if (State.Mode() != "ready") throw new UnauthorizedAccessException("Completá la configuración o recuperación local antes de conectarte.");
                        Interlocked.Increment(ref activeSsh);
                        try { CheckServer(request); await ssh.Connect(cancellation); result = new() { ["connected"] = true }; }
                        finally { Interlocked.Decrement(ref activeSsh); }
                        break;
                    case "installation-check":
                        using (var anchor = State.Registry())
                            if ((int)(anchor.GetValue("Activated") ?? 0) == 1 || (int)(anchor.GetValue("SetupPending") ?? 0) != 1) throw new UnauthorizedAccessException();
                        string revision = SetupTransaction.Revision();
                        var mode = State.Mode();
                        if (mode is not ("ready" or "setup")) throw new IOException("El almacén necesita recuperación.");
                        using (var checkTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation))
                        {
                            checkTimeout.CancelAfter(TimeSpan.FromSeconds(20));
                            await SshSettings.Check(ssh, checkTimeout.Token);
                        }
                        if (revision != SetupTransaction.Revision()) throw new IOException("La configuración cambió durante la comprobación.");
                        result = new() { ["ready"] = true, ["mode"] = mode, ["installation"] = State.Value("InstallId"), ["revision"] = revision }; break;
                    case "open-report":
                        var reportPath = Path.GetFullPath(request["path"]!.GetValue<string>());
                        var activeProfile = profiles.Active();
                        var scopedRoot = activeProfile == null || activeProfile["legacy"]?.GetValue<bool>() == true ? State.DirectoryPath : Path.Combine(State.DirectoryPath,"servers",activeProfile["id"]!.GetValue<string>());
                        var reportRoot = Path.Combine(scopedRoot, "Informes", "SSH", "archivos") + Path.DirectorySeparatorChar;
                        if (!reportPath.StartsWith(reportRoot, StringComparison.OrdinalIgnoreCase) || Path.GetExtension(reportPath) != ".txt" || !System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(reportPath), "^ssh_reporte_[A-Za-z0-9_-]+\\.txt$") || reports.Count >= 4) throw new UnauthorizedAccessException();
                        var info = new FileInfo(reportPath);
                        if (!info.Exists || info.Length > 16 * 1024 * 1024 || info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException();
                        if (DateTime.UtcNow.Ticks - Interlocked.Read(ref agentSeen) > TimeSpan.FromSeconds(10).Ticks) throw new IOException("Abrí el panel desde el acceso directo para recibir el informe.");
                        reports.Enqueue(new() { ["pending"] = true, ["kind"] = "report", ["name"] = info.Name, ["content"] = Convert.ToBase64String(File.ReadAllBytes(reportPath)) });
                        result = new() { ["queued"] = true }; break;
                    case "ssh":
                        if (State.Mode() != "ready") throw new UnauthorizedAccessException("El acceso al servidor permanece bloqueado.");
                        Interlocked.Increment(ref activeSsh);
                        try { CheckServer(request); var status = await ssh.Run(request["command"]!.GetValue<string>(), Convert.FromBase64String(request["input"]?.GetValue<string>() ?? ""), Send, cancellation); result = new() { ["exitCode"] = status }; }
                        finally { Interlocked.Decrement(ref activeSsh); }
                        break;
                    default: throw new IOException("Operación protegida no válida.");
                }
                result["ok"] = true; await Send(result);
                if (op == "runtime-close") closeService?.Invoke();
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // Never send raw SSH/library errors (which may contain usernames or key paths).
                try { await Send(new() { ["ok"] = false, ["error"] = ex is UnauthorizedAccessException ? "Operación no autorizada. Confirmá la conexión con Windows Hello." : ex is IOException && requestIsProfile ? ex.Message : "No se pudo completar la operación protegida. Verificá la identidad, el respaldo y la conexión." }); } catch { }
            }
            finally { writeLock.Dispose(); }
        }
    }
    public void Dispose() { ssh.Dispose(); vaultLock.Dispose(); }
}

internal static class Wire
{
    internal static async Task<JsonObject> Read(Stream stream, CancellationToken cancellation, int maximum = 25_000_000)
    {
        var header = new byte[4]; await stream.ReadExactlyAsync(header, cancellation);
        var length = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(header);
        if (length < 2 || length > maximum) throw new IOException("Solicitud demasiado grande.");
        var data = new byte[length]; await stream.ReadExactlyAsync(data, cancellation);
        return JsonNode.Parse(data)?.AsObject() ?? throw new IOException("Solicitud no válida.");
    }
    internal static async Task Write(Stream stream, JsonObject value, CancellationToken cancellation)
    {
        var data = Encoding.UTF8.GetBytes(value.ToJsonString());
        if (data.Length > 25_000_000) throw new IOException("Respuesta demasiado grande.");
        var header = new byte[4]; System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(header, data.Length);
        await stream.WriteAsync(header, cancellation); await stream.WriteAsync(data, cancellation); await stream.FlushAsync(cancellation);
    }
    internal static async Task<JsonObject> Call(JsonObject request, CancellationToken cancellation)
    {
        using var pipe = new NamedPipeClientStream(".", State.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000, cancellation);
        PipeIdentity.Verify(pipe);
        await Write(pipe, request, cancellation);
        return await Read(pipe, cancellation);
    }
}
