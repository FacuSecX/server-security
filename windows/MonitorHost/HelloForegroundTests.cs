namespace FacuSecX.Monitor;

internal static class HelloForegroundTests
{
    private sealed class Windows : IHelloWindows
    {
        internal HelloWindow[] Items = Array.Empty<HelloWindow>();
        internal int Raised, Restored, WorkerThread;
        internal nint LastRaised;
        public IReadOnlyList<HelloWindow> List() => Volatile.Read(ref Items);
        public void Raise(HelloWindow window) { LastRaised = window.Handle; Interlocked.Increment(ref Raised); WorkerThread = Environment.CurrentManagedThreadId; }
        public void Restore(HelloWindow window) { Interlocked.Increment(ref Restored); }
    }
    internal static int Run()
    {
        int passed = 0;
        void Check(bool valid) { if (!valid) throw new IOException("Hello foreground test failed."); passed++; }
        var real = new HelloWindow(123, 500, 1, "Credential Dialog Xaml Host", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "CredentialUIBroker.exe"), false);
        Check(HelloForeground.Eligible(real, 1));
        Check(!HelloForeground.Eligible(real with { SessionId = 2 }, 1));
        Check(!HelloForeground.Eligible(real with { Executable = @"C:\UserFolder\CredentialUIBroker.exe" }, 1));
        Check(!HelloForeground.Eligible(real with { ClassName = "BrowserWindow" }, 1));
        Check(!HelloForeground.Eligible(real with { Handle = 0 }, 1));
        var fake = new Windows { Items = new[] { real } };
        var presenter = new HelloForeground(fake, 1, false);
        fake.Items = new[] { real, real with { Handle = 124 }, real with { Handle = 125, SessionId = 2 } };
        presenter.Poll(); Check(fake.Raised == 1 && fake.LastRaised == real.Handle); // A reused OS window is eligible; only one prompt is raised.
        presenter.Dispose(); Check(fake.Restored == 1);
        presenter.Poll(); presenter.Dispose(); Check(fake.Raised == 1 && fake.Restored == 1);
        fake = new Windows(); int caller = Environment.CurrentManagedThreadId;
        using (presenter = new HelloForeground(fake, 1))
        {
            fake.Items = new[] { real };
            // Deliberately stop pumping UI messages: the real bug must not recur.
            Thread.Sleep(650);
            Check(Volatile.Read(ref fake.Raised) > 0 && fake.WorkerThread != caller);
        }
        Check(fake.Restored == 1);
        return passed;
    }
}
