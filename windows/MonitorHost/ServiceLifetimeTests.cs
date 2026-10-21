using System.Diagnostics;

namespace FacuSecX.Monitor;

internal static class ServiceLifetimeTests
{
    internal static async Task<int> Run()
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!, "job-lifetime-probe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        using var probe = Process.Start(start) ?? throw new Exception("No se pudo comprobar el cierre de procesos secundarios.");
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        var line = await probe.StandardOutput.ReadLineAsync(limit.Token).ConfigureAwait(false);
        await probe.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        if (!int.TryParse(line, out var childId) || probe.ExitCode != 0) throw new Exception("No se pudo comprobar la protección de procesos secundarios.");
        for (int attempt = 0; attempt < 30; attempt++) {
            try { using var child = Process.GetProcessById(childId); if (child.HasExited) return await ChildClose().ConfigureAwait(false); }
            catch (ArgumentException) { return await ChildClose().ConfigureAwait(false); }
            await Task.Delay(100,limit.Token).ConfigureAwait(false);
        }
        throw new Exception("Un proceso secundario sobrevivió al cierre de su propietario.");
    }
    private static async Task<int> ChildClose()
    {
        using var child = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "job-lifetime-child") { UseShellExecute = false, CreateNoWindow = true }) ?? throw new Exception();
        var job = ServiceLifetime.OwnChild(child);
        job.Dispose();
        using var limit = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await child.WaitForExitAsync(limit.Token).ConfigureAwait(false);
        return 2;
    }
}
