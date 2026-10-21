using System.Diagnostics;

namespace FacuSecX.Monitor;

// RequestSignAsync can block the caller's UI pump while Windows creates its UI.
// Poll from a worker, never from a WinForms timer on that same UI thread.
internal sealed class HelloForeground : IDisposable
{
    private readonly IHelloWindows windows;
    private readonly int session;
    private readonly Dictionary<nint, HelloWindow> raised = new();
    private readonly object gate = new();
    private readonly Stopwatch elapsed = Stopwatch.StartNew();
    private readonly System.Threading.Timer timer;
    private bool disposed;
    internal static bool Eligible(HelloWindow window, int session) =>
        window.Handle != 0 && window.SessionId == session && window.ClassName == "Credential Dialog Xaml Host" &&
        string.Equals(window.Executable, Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "CredentialUIBroker.exe"), StringComparison.OrdinalIgnoreCase);
    internal HelloForeground(IHelloWindows? windows = null, int? session = null, bool startTimer = true)
    {
        this.windows = windows ?? new NativeHelloWindows();
        using var current = Process.GetCurrentProcess(); this.session = session ?? current.SessionId;
        timer = new System.Threading.Timer(_ => Poll(), null, Timeout.Infinite, Timeout.Infinite);
        if (startTimer) timer.Change(0, 150);
    }
    internal void Poll()
    {
        lock (gate)
        {
            if (disposed) return;
            if (elapsed.Elapsed > TimeSpan.FromSeconds(100)) { Dispose(); return; }
            try
            {
                foreach (var window in windows.List())
                {
                    // Windows may reuse a visible broker window while opening the
                    // key, before RequestSignAsync has even been reached.
                    if (!Eligible(window, session)) continue;
                    raised.TryAdd(window.Handle, window);
                    windows.Raise(window);
                    break; // Never bounce focus between several OS prompts.
                }
            }
            catch { /* Presentation cannot approve or reject a signed Hello proof. */ }
        }
    }
    public void Dispose()
    {
        lock (gate)
        {
            if (disposed) return;
            disposed = true; timer.Dispose();
            foreach (var window in raised.Values) try { windows.Restore(window); } catch { }
            raised.Clear();
        }
    }
}
