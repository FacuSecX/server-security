namespace FacuSecX.Monitor;

// The same suspension gate protects server switches and tray shutdowns from
// interrupting package installs, account changes or other administrative jobs.
internal sealed class RuntimeLifecycle(Func<bool> running, Func<CancellationToken, Task> suspend,
    Action stop, Func<CancellationToken, Task> resetSsh, Action persistClosed)
{
    internal async Task SuspendIfRunning(CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        if (running()) await suspend(token);
    }
    internal async Task Disconnect(CancellationToken token)
    {
        await SuspendIfRunning(token);
        // Persist first so a service restart cannot silently reconnect after Close.
        // Once suspended, all remaining work is local; do not abandon shutdown
        // merely because the requesting desktop process has already closed.
        persistClosed();
        stop();
        await resetSsh(CancellationToken.None);
    }
}
