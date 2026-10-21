namespace FacuSecX.Monitor;

internal static class HelloConsentTests
{
    // Synthetic actions only: these tests never invoke Windows Hello or a PIN UI.
    internal static int Run()
    {
        var previous = SynchronizationContext.Current;
        try { return RunUiTests(); }
        finally { SynchronizationContext.SetSynchronizationContext(previous); }
    }

    private static int RunUiTests()
    {
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.ThrowException);
        int passed = 0, calls = 0;
        void Check(bool valid) { if (!valid) throw new IOException("Hello consent presentation test failed."); passed++; }
        Button Continue(Form form) => form.Controls.OfType<TableLayoutPanel>().Single().Controls.OfType<Button>().Single();

        using (var dialog = new HelloConsent<int>("Presentation test", _ => { calls++; return Task.FromResult(7); }, CancellationToken.None))
        {
            dialog.Shown += (_, _) =>
            {
                Check(calls == 0 && dialog.TopMost);
                dialog.Close();
            };
            try { dialog.Run().GetAwaiter().GetResult(); Check(false); } catch (OperationCanceledException) { passed++; }
            Check(calls == 0);
        }

        HelloConsent<int>? active = null;
        using (active = new HelloConsent<int>("Presentation test", _ => { calls++; Check(!active!.TopMost); return Task.FromResult(7); }, CancellationToken.None))
        {
            active.Shown += (_, _) => active.BeginInvoke(new Action(() => { Continue(active).PerformClick(); Continue(active).PerformClick(); }));
            Check(active.Run().GetAwaiter().GetResult() == 7);
            Check(calls == 1);
        }

        using (var dialog = new HelloConsent<int>("Presentation test", _ => Task.FromException<int>(new IOException("synthetic denial")), CancellationToken.None))
        {
            dialog.Shown += (_, _) => dialog.BeginInvoke(new Action(() => Continue(dialog).PerformClick()));
            try { dialog.Run().GetAwaiter().GetResult(); Check(false); } catch (IOException error) when (error.Message == "synthetic denial") { passed++; }
        }

        using (var cancellation = new CancellationTokenSource())
        using (var dialog = new HelloConsent<int>("Presentation test", async token => { calls++; await Task.Delay(Timeout.Infinite, token); return 0; }, cancellation.Token))
        using (var timer = new System.Windows.Forms.Timer { Interval = 50 })
        {
            dialog.Shown += (_, _) => dialog.BeginInvoke(new Action(() => { Continue(dialog).PerformClick(); timer.Start(); }));
            timer.Tick += (_, _) => { timer.Stop(); cancellation.Cancel(); };
            try { dialog.Run().GetAwaiter().GetResult(); Check(false); } catch (OperationCanceledException) { passed++; }
            Check(calls == 2);
        }

        using (var cancellation = new CancellationTokenSource())
        {
            cancellation.Cancel();
            using var dialog = new HelloConsent<int>("Presentation test", _ => { calls++; return Task.FromResult(0); }, cancellation.Token);
            try { dialog.Run().GetAwaiter().GetResult(); Check(false); } catch (OperationCanceledException) { passed++; }
            Check(calls == 2);
        }
        return passed;
    }
}
