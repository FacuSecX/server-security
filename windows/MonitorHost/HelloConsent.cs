namespace FacuSecX.Monitor;

// A real click in this process gives Windows a foreground interaction before
// KeyCredentialManager opens its own dialog. This window never collects a PIN.
internal sealed class HelloConsent<T> : Form
{
    private readonly TaskCompletionSource<T> completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource cancellation;
    private readonly Func<CancellationToken, Task<T>> action;
    private readonly Label message;
    private readonly Button proceed;
    private readonly CancellationTokenRegistration registration;
    private bool started;
    private bool released;

    internal HelloConsent(string title, Func<CancellationToken, Task<T>> action, CancellationToken token)
    {
        this.action = action;
        cancellation = CancellationTokenSource.CreateLinkedTokenSource(token);
        Text = Branding.Name + " · " + title;
        Icon = Branding.LoadIcon();
        ClientSize = new Size(460, 165);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = true;
        TopMost = true;
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(20), ColumnCount = 1, RowCount = 2 };
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        message = new Label { Dock = DockStyle.Fill, Text = "Continuá para abrir la verificación de Windows Hello. El PIN se ingresa únicamente en la ventana de Seguridad de Windows.", AutoSize = false };
        proceed = new Button { Text = "Continuar con Windows Hello", AutoSize = true, Anchor = AnchorStyles.Right };
        layout.Controls.Add(message);
        layout.Controls.Add(proceed);
        Controls.Add(layout);
        AcceptButton = proceed;
        proceed.Click += async (_, _) => await Continue();
        FormClosing += (_, _) => { if (!completion.Task.IsCompleted) { cancellation.Cancel(); completion.TrySetCanceled(); } };
        Shown += (_, _) => { Activate(); proceed.Focus(); if (cancellation.IsCancellationRequested) Close(); };
        registration = cancellation.Token.Register(() =>
        {
            if (!IsHandleCreated || IsDisposed) return;
            try { BeginInvoke(new Action(() => { if (!IsDisposed) Close(); })); } catch (InvalidOperationException) { }
        });
    }

    private async Task Continue()
    {
        if (started || cancellation.IsCancellationRequested) return;
        started = true;
        proceed.Enabled = false;
        message.Text = "Completá la verificación en Seguridad de Windows. Podés cancelar para volver al panel.";
        // Do not cover the OS prompt with our own always-on-top window.
        TopMost = false;
        Activate();
        try
        {
            var result = await action(cancellation.Token);
            if (!cancellation.IsCancellationRequested) completion.TrySetResult(result);
        }
        catch (OperationCanceledException) { completion.TrySetCanceled(); }
        catch (Exception error) { completion.TrySetException(error); }
        finally { if (!IsDisposed) Close(); }
    }

    internal async Task<T> Run(IWin32Window? owner = null)
    {
        cancellation.Token.ThrowIfCancellationRequested();
        if (owner == null) ShowDialog(); else ShowDialog(owner);
        return await completion.Task;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !released) { released = true; registration.Dispose(); cancellation.Cancel(); cancellation.Dispose(); }
        base.Dispose(disposing);
    }
}
