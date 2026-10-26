using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Principal;
using System.ServiceProcess;
using System.Text;
using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class Program
{
    [STAThread]
    internal static int Main(string[] args)
    {
        try
        {
            var name = Path.GetFileNameWithoutExtension(Environment.ProcessPath) ?? "";
            if (name.EndsWith(".SshBridge", StringComparison.OrdinalIgnoreCase)) return SshBridge(args).GetAwaiter().GetResult();
            switch (args.FirstOrDefault())
            {
                case "service": ServiceBase.Run(new MonitorService()); return 0;
                case "agent": RequireDesktopService(); Branding.Initialize(); HelloAgent.Run(); return 0;
                case "servers": Branding.Initialize(); return ServerPicker.Run();
                case "prepare": Branding.Initialize(); return Setup.Run(args.Skip(1).ToArray());
                case "prepare-resume": Branding.Initialize(); return Setup.Run(args.Skip(1).ToArray(), true);
                case "commit-setup": return SetupTransaction.Commit(args.Skip(1).ToArray());
                case "verify-setup": return SetupTransaction.Commit(args.Skip(1).ToArray(), false);
                case "rpc":
                    using (var limit = new CancellationTokenSource(TimeSpan.FromSeconds(110)))
                    { var input = Console.In.ReadToEnd(); if (input.Length > 2_000_000) throw new IOException(); var result = Wire.Call(JsonNode.Parse(input)!.AsObject(), limit.Token).GetAwaiter().GetResult(); Console.Out.Write(result.ToJsonString()); return result["ok"]?.GetValue<bool>() == true ? 0 : 1; }
                case "launch":
                    if (WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid")) throw new UnauthorizedAccessException("Este acceso está vinculado al propietario del panel.");
                    RequireDesktopService(); Branding.Initialize(); HelloAgent.Run(true); return 0;
                default: throw new IOException("Acción no válida.");
            }
        }
        catch (Exception ex)
        {
            if (args.FirstOrDefault() == "rpc") Console.Out.Write("{\"ok\":false,\"error\":\"No se pudo acceder al servicio protegido.\"}");
            else if (Environment.UserInteractive && args.FirstOrDefault() is "launch" or "prepare" or "prepare-resume" or "servers") MessageBox.Show(ex.Message, Branding.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
            else Console.Error.WriteLine("No se pudo completar la operación protegida.");
            return 1;
        }
    }
    private static void RequireDesktopService()
    {
        if (WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid")) throw new UnauthorizedAccessException("Esta instalación pertenece a otro usuario de Windows.");
        ServiceLifetime.EnsureRunning();
    }
    private static async Task<int> SshBridge(string[] args)
    {
        var metadata = Environment.GetEnvironmentVariable("SSM_SERVER_META");
        var json = !string.IsNullOrEmpty(metadata) ? JsonNode.Parse(metadata)!["ssh"]! : JsonNode.Parse(File.ReadAllText(Path.Combine(State.InstallPath, "panel", "config.json")))!["ssh"]!;
        string serverId = Environment.GetEnvironmentVariable("SSM_SERVER_ID") ?? "";
        bool check = false; string? command = null; bool target = false;
        for (int i = 0; i < args.Length; i++)
        {
            string item = args[i];
            if (item is "-batch" or "-noagent" or "-agent" or "-ssh" or "-share" or "-no-trivial-auth" or "-T") continue;
            if (item == "-shareexists") { check = true; continue; }
            if (item is "-P" or "-hostkey")
            {
                string expected = item == "-P" ? (json["port"]?.GetValue<int>() ?? 22).ToString() : json["hostKeyFingerprint"]!.GetValue<string>();
                if (++i == args.Length || args[i] != expected) throw new UnauthorizedAccessException(); continue;
            }
            if (item == "-N") { check = true; continue; }
            if (!target && item == json["user"]!.GetValue<string>() + "@" + json["host"]!.GetValue<string>()) { target = true; continue; }
            if (target && command == null) { command = item; continue; }
            throw new UnauthorizedAccessException("Parámetros SSH no válidos.");
        }
        if (!target || (!check && command == null)) throw new UnauthorizedAccessException();
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMinutes(60));
        using var pipe = new NamedPipeClientStream(".", State.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(5000, cancellation.Token);
        PipeIdentity.Verify(pipe);
        using var input = new MemoryStream();
        if (!check) { await Console.OpenStandardInput().CopyToAsync(input, cancellation.Token); if (input.Length > 18_000_000) throw new IOException(); }
        await Wire.Write(pipe, check ? new() { ["op"] = "ssh-check", ["server"] = serverId } : new() { ["op"] = "ssh", ["server"] = serverId, ["command"] = command, ["input"] = Convert.ToBase64String(input.ToArray()) }, cancellation.Token);
        while (true)
        {
            var response = await Wire.Read(pipe, cancellation.Token);
            if (response["stream"] != null)
            {
                var destination = response["stream"]!.GetValue<string>() == "stdout" ? Console.OpenStandardOutput() : Console.OpenStandardError();
                await destination.WriteAsync(Convert.FromBase64String(response["data"]!.GetValue<string>()), cancellation.Token); continue;
            }
            return response["ok"]?.GetValue<bool>() == true ? response["exitCode"]?.GetValue<int>() ?? 0 : 1;
        }
    }
}

internal sealed class MonitorService : ServiceBase
{
    private CancellationTokenSource? cancellation;
    private Broker? broker;
    private Process? node;
    private Microsoft.Win32.SafeHandles.SafeFileHandle? nodeJob;
    private string switchToken = "";
    private bool transitioning;
    private readonly ServerProfiles profiles = new();
    internal MonitorService() { ServiceName = State.ServiceName; CanStop = true; }
    protected override void OnStart(string[] args)
    {
        if (WindowsIdentity.GetCurrent().User?.Value != State.ServiceSid.Value) throw new UnauthorizedAccessException("Identidad del servicio no válida.");
        if (!string.Equals(AppContext.BaseDirectory.TrimEnd('\\'), Path.Combine(State.InstallPath, "native"), StringComparison.OrdinalIgnoreCase)) throw new IOException("Ubicación del servicio no válida.");
        ServiceLifetime.Attach();
        profiles.MigrateLegacy();
        cancellation = new(); broker = new(SelectServer, Disconnect, RuntimeStatus, Stop);
        _ = Task.Run(async () => { try { await broker.Listen(cancellation.Token); } catch { if (!cancellation.IsCancellationRequested) Stop(); } });
        if (State.Read("runtime.dpapi", "runtime")?["closed"]?.GetValue<bool>() != true) StartNode();
    }
    private JsonObject RuntimeStatus() => new() { ["running"] = node != null && !node.HasExited, ["port"] = Port(), ["label"] = profiles.Active()?["label"]?.DeepClone() ?? JsonValue.Create("") };
    private async Task SuspendNode(CancellationToken token)
    {
        using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(8) };
        using var request = new System.Net.Http.HttpRequestMessage(System.Net.Http.HttpMethod.Post,"http://127.0.0.1:"+Port()+"/api/connection/suspend"); request.Headers.Add("X-SSM-Switch",switchToken);
        using var response = await client.SendAsync(request,token);
        if (!response.IsSuccessStatusCode) throw new IOException("Hay una operación del panel en curso. Esperá a que termine antes de cambiar o cerrar la conexión.");
    }
    private RuntimeLifecycle Lifecycle() => new(() => node != null && !node.HasExited, SuspendNode, StopNode, token => broker!.ResetSsh(token), () => State.Write("runtime.dpapi", "runtime", new() { ["closed"] = true }));
    private async Task Disconnect(CancellationToken token)
    {
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(token,cancellation!.Token); limit.CancelAfter(TimeSpan.FromSeconds(30));
        transitioning = true;
        try { await Lifecycle().Disconnect(limit.Token); }
        finally { transitioning = false; }
    }
    private int Port() => JsonNode.Parse(File.ReadAllText(Path.Combine(State.InstallPath,"panel","config.json")))!["listenPort"]?.GetValue<int>() ?? 8766;
    private void StartNode()
    {
        var runtime = Path.Combine(State.InstallPath, "node", "node.exe"); var panel = Path.Combine(State.InstallPath, "panel");
        var start = new ProcessStartInfo(runtime) { WorkingDirectory = panel, UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        start.ArgumentList.Add(Path.Combine(panel, "server.mjs"));
        foreach (var name in new[] { "NODE_OPTIONS", "NODE_PATH", "SERVER_MONITOR_SSH_PASSWORD", "STORYPULSE_PORT", "SSM_SERVER_META", "SSM_SERVER_ID", "SSM_MIGRATION_CHECK", "SSM_SWITCH_TOKEN" }) start.Environment.Remove(name);
        start.Environment["SSM_PROTECTED_ROOT"] = State.DirectoryPath;
        start.Environment["SSM_PROTECTED_HOST"] = Path.Combine(State.InstallPath, "native", "FacuSecX.MonitorHost.exe");
        switchToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(); start.Environment["SSM_SWITCH_TOKEN"] = switchToken;
        using (var anchor = State.Registry()) if ((int)(anchor.GetValue("Activated") ?? 0) != 1) start.Environment["SSM_MIGRATION_CHECK"] = "1";
        var profile = profiles.Active();
        if (profile != null) {
            start.Environment["SSM_SERVER_ID"] = profile["id"]!.GetValue<string>();
            start.Environment["SSM_SERVER_META"] = new JsonObject { ["id"] = profile["id"]!.DeepClone(), ["label"] = profile["label"]!.DeepClone(), ["legacy"] = profile["legacy"]?.DeepClone() ?? JsonValue.Create(false), ["ssh"] = ServerProfiles.PublicSettings(profile) }.ToJsonString();
        }
        var process = Process.Start(start) ?? throw new IOException("No se pudo iniciar el panel protegido.");
        try { nodeJob = ServiceLifetime.OwnChild(process); node = process; }
        catch { try { process.Kill(); } finally { process.Dispose(); } throw; }
        process.OutputDataReceived += (_, _) => { }; process.ErrorDataReceived += (_, _) => { }; process.BeginOutputReadLine(); process.BeginErrorReadLine();
        process.EnableRaisingEvents = true; process.Exited += (_, _) => { if (cancellation?.IsCancellationRequested == false && !transitioning && ReferenceEquals(node,process)) { ExitCode = 1; Stop(); } };
    }
    private void StopNode()
    {
        var process = node; node = null;
        var owned = nodeJob; nodeJob = null; owned?.Dispose();
        if (process == null) return;
        try { if (!process.HasExited) { if (owned == null) process.Kill(); if (!process.WaitForExit(10000)) throw new IOException("El recolector no pudo cerrarse."); } }
        finally { process.Dispose(); }
    }
    private async Task<bool> Healthy(string id,CancellationToken token)
    {
        using var client = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(2) };
        for (int i=0;i<60;i++) {
            token.ThrowIfCancellationRequested();
            try { var health = JsonNode.Parse(await client.GetStringAsync("http://127.0.0.1:"+Port()+"/api/health",token))!; if (health["protected_runtime"]?.GetValue<bool>() == true && (health["server_id"]?.GetValue<string>() ?? "") == id && health["server_scope_ready"]?.GetValue<bool>() == true) return true; } catch (System.Net.Http.HttpRequestException) { } catch (TaskCanceledException) when (!token.IsCancellationRequested) { }
            await Task.Delay(250,token);
        }
        return false;
    }
    private async Task<int> SelectServer(JsonObject profile,CancellationToken requestToken)
    {
        requestToken.ThrowIfCancellationRequested();
        using var limit = CancellationTokenSource.CreateLinkedTokenSource(cancellation!.Token); limit.CancelAfter(TimeSpan.FromSeconds(60));
        var previous = profiles.Load(); bool stopped = false, wasRunning = node != null && !node.HasExited;
        await Lifecycle().SuspendIfRunning(limit.Token);
        transitioning = true;
        try {
            StopNode(); stopped = true; await broker!.ResetSsh(limit.Token);
            profiles.Save(profiles.WithActive(profile)); State.Write("runtime.dpapi", "runtime", new() { ["closed"] = false }); broker.ResumeSsh(); StartNode();
            if (!await Healthy(profile["id"]!.GetValue<string>(),limit.Token)) throw new IOException("La conexión no completó el inicio del panel. Se restauró el servidor anterior.");
            return Port();
        } catch {
            if (stopped) {
                StopNode(); profiles.Save(previous);
                using var rollback = CancellationTokenSource.CreateLinkedTokenSource(cancellation.Token); rollback.CancelAfter(TimeSpan.FromSeconds(20));
                await broker!.ResetSsh(rollback.Token);
                State.Write("runtime.dpapi", "runtime", new() { ["closed"] = !wasRunning });
                if (wasRunning) { broker.ResumeSsh(); StartNode(); await Healthy(previous["active"]!.GetValue<string>(),rollback.Token); }
            }
            throw;
        } finally { if (node != null) broker!.ResumeSsh(); transitioning = false; }
    }
    protected override void OnStop() { cancellation?.Cancel(); try { StopNode(); } catch { } broker?.Dispose(); cancellation?.Dispose(); }
}
