using System.Text.Json.Nodes;

namespace FacuSecX.Monitor;

internal static class RuntimeLifecycleTests
{
    internal static async Task<int> Run()
    {
        int count = 0; void Check(bool value) { if (!value) throw new Exception("Falló el ciclo de cierre del panel."); count++; }
        bool running = true, busy = false; var steps = new List<string>();
        var lifecycle = new RuntimeLifecycle(() => running, _ => { steps.Add("suspend"); if (busy) throw new IOException("busy"); return Task.CompletedTask; },
            () => { steps.Add("stop"); running = false; }, _ => { steps.Add("ssh-closed"); return Task.CompletedTask; }, () => steps.Add("persist-closed"));
        busy = true;
        try { await lifecycle.Disconnect(CancellationToken.None); Check(false); } catch (IOException) { Check(running && steps.SequenceEqual(new[] { "suspend" })); }
        busy = false; steps.Clear();
        await lifecycle.Disconnect(CancellationToken.None);
        Check(!running); Check(steps.SequenceEqual(new[] { "suspend", "persist-closed", "stop", "ssh-closed" }));
        steps.Clear(); await lifecycle.Disconnect(CancellationToken.None);
        Check(!running && steps.SequenceEqual(new[] { "persist-closed", "stop", "ssh-closed" }));
        steps.Clear(); await lifecycle.SuspendIfRunning(CancellationToken.None); Check(steps.Count == 0);
        using var canceled = new CancellationTokenSource(); canceled.Cancel();
        try { await lifecycle.Disconnect(canceled.Token); Check(false); } catch (OperationCanceledException) { Check(steps.Count == 0); }
        foreach (var op in new[] { "runtime-status", "runtime-disconnect", "runtime-close" }) {
            Check(Broker.IsDesktopOperation(op)); Check(!Broker.IsDesktopOperation(op + "-other"));
        }
        Check(!Broker.IsDesktopOperation("vault-load")); Check(!Broker.IsDesktopOperation("ssh"));
        using var icon = Branding.LoadIcon(); Check(icon.Width == 32 && icon.Height == 32);
        return count;
    }
}
