using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace FacuSecX.Monitor;

// One user process owns the notification icon, connection selector and Hello UI.
// Closing the browser does not close this controller or the SSH connection.
internal static class DesktopController
{
    internal static void Run(bool showPicker)
    {
        if (WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid")) throw new UnauthorizedAccessException("Abrí Server Monitor desde el usuario de Windows que lo instaló.");
        string id = State.Value("InstallId"), eventName = "Local\\FacuSecX.OpenPicker." + id;
        using var mutex = new Mutex(true, "Local\\FacuSecX.HelloAgent." + id, out var first);
        if (!first) {
            if (showPicker) for (int i = 0; i < 20; i++) {
                if (EventWaitHandle.TryOpenExisting(eventName, out var existing)) { using (existing) existing.Set(); break; }
                Thread.Sleep(100);
            }
            return;
        }
        using var openPicker = new EventWaitHandle(false, EventResetMode.AutoReset, eventName);
        using var lifetime = new CancellationTokenSource();
        using var form = new Form { Text = Branding.Name, Icon = Branding.LoadIcon(), ShowInTaskbar = false, Width = 1, Height = 1, Opacity = 0, FormBorderStyle = FormBorderStyle.FixedToolWindow };
        using var menu = new ContextMenuStrip();
        var open = new ToolStripMenuItem("Abrir panel");
        var change = new ToolStripMenuItem("Cambiar conexión");
        var close = new ToolStripMenuItem("Cerrar programa");
        menu.Items.AddRange(new ToolStripItem[] { open, change, new ToolStripSeparator(), close });
        using var icon = new NotifyIcon { Icon = Branding.LoadIcon(), Text = Branding.Name, ContextMenuStrip = menu, Visible = true };
        using var timer = new System.Windows.Forms.Timer { Interval = 700 };
        bool busy = false, polling = false, helloBusy = false, selecting = false;
        DateTime nextStatus = DateTime.MinValue;
        void EnableActions() { open.Enabled = change.Enabled = close.Enabled = !busy && !helloBusy; }
        void ShowPicker()
        {
            if (busy || helloBusy) return;
            if (selecting) { var current = ServerPicker.Current; if (current != null && !current.IsDisposed) { if (current.WindowState == FormWindowState.Minimized) current.WindowState = FormWindowState.Normal; current.Activate(); } return; }
            selecting = true;
            try { ServiceLifetime.EnsureRunning(); ServerPicker.Run(true); }
            catch (Exception error) { MessageBox.Show(error.Message, Branding.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
            finally { selecting = false; nextStatus = DateTime.MinValue; }
        }
        async Task<JsonObject> Call(string op)
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); timeout.CancelAfter(TimeSpan.FromSeconds(40));
            var result = await Wire.Call(new() { ["op"] = op }, timeout.Token);
            if (result["ok"]?.GetValue<bool>() != true) throw new IOException(result["error"]?.GetValue<string>() ?? "El servicio de Server Monitor no respondió.");
            return result;
        }
        async Task OpenPanel()
        {
            if (busy || helloBusy) return;
            try {
                ServiceLifetime.EnsureRunning();
                var status = await Call("runtime-status");
                if (status["running"]?.GetValue<bool>() == true) Process.Start(new ProcessStartInfo("http://127.0.0.1:" + status["port"]!.GetValue<int>() + "/login") { UseShellExecute = true });
                else ShowPicker();
            } catch (Exception error) { MessageBox.Show(error.Message, Branding.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }
        async Task Disconnect(bool exiting)
        {
            if (busy || helloBusy) return;
            busy = true; EnableActions();
            try {
                ServerPicker.Current?.Close();
                ServiceLifetime.EnsureRunning();
                await Call(exiting ? "runtime-close" : "runtime-disconnect");
                if (exiting) await Task.Run(ServiceLifetime.WaitStopped);
                icon.Text = Branding.Name + " · Sin conexión";
                if (exiting) { icon.Visible = false; lifetime.Cancel(); timer.Stop(); form.Close(); return; }
                busy = false; ShowPicker();
            } catch (Exception error) { MessageBox.Show(error.Message, Branding.Name, MessageBoxButtons.OK, MessageBoxIcon.Error); }
            finally { busy = false; if (!form.IsDisposed) EnableActions(); }
        }
        open.Click += async (_, _) => await OpenPanel();
        icon.DoubleClick += async (_, _) => await OpenPanel();
        change.Click += async (_, _) => await Disconnect(false);
        close.Click += async (_, _) => await Disconnect(true);
        timer.Tick += async (_, _) => {
            if (!busy && !helloBusy && openPicker.WaitOne(0)) form.BeginInvoke(new Action(ShowPicker));
            if (polling || busy) return;
            polling = true;
            try {
                if (DateTime.UtcNow >= nextStatus) {
                    var status = await Call("runtime-status");
                    string text = Branding.Name + (status["running"]?.GetValue<bool>() == true ? " · " + status["label"]?.GetValue<string>() : " · Sin conexión");
                    icon.Text = text.Length > 63 ? text[..63] : text;
                    nextStatus = DateTime.UtcNow.AddSeconds(5);
                }
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); timeout.CancelAfter(TimeSpan.FromSeconds(100));
                var request = await Wire.Call(new() { ["op"] = "agent-poll" }, timeout.Token);
                if (request["pending"]?.GetValue<bool>() != true) return;
                helloBusy = true; EnableActions();
                try { await ProcessRequest(request, timeout.Token); }
                finally { helloBusy = false; EnableActions(); }
            } catch {
                // A closed service must not leave a polling desktop process.
                // The launcher can start it again with its narrow start right.
                try { using var service = new System.ServiceProcess.ServiceController(State.ServiceName);
                    if (!busy && service.Status == System.ServiceProcess.ServiceControllerStatus.Stopped) { ServerPicker.Current?.Close(); form.Close(); }
                } catch { }
            }
            finally { polling = false; }
        };
        form.Shown += (_, _) => { form.Hide(); timer.Start(); if (showPicker) form.BeginInvoke(new Action(ShowPicker)); };
        form.FormClosing += (_, _) => { lifetime.Cancel(); icon.Visible = false; timer.Stop(); };
        Application.Run(form);
    }

    private static async Task ProcessRequest(JsonObject request, CancellationToken token)
    {
        if (request["kind"]?.GetValue<string>() == "report") {
            var name = request["name"]!.GetValue<string>();
            if (!System.Text.RegularExpressions.Regex.IsMatch(name, "^ssh_reporte_[A-Za-z0-9_-]+\\.txt$")) throw new IOException();
            var content = Convert.FromBase64String(request["content"]!.GetValue<string>()); if (content.Length > 16 * 1024 * 1024) throw new IOException();
            var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FacuSecX", "ServerSecurityMonitor", "Reports");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, Path.GetFileNameWithoutExtension(name) + "-" + Guid.NewGuid().ToString("N")[..8] + ".txt");
            using (var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) file.Write(content);
            var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe")) { UseShellExecute = false };
            start.ArgumentList.Add(path); Process.Start(start); return;
        }
        string signature = "";
        try {
            var title = request["purpose"]?.GetValue<string>() switch { "setup" => "Crear administrador — Windows Hello", "recovery" => "Restaurar cuentas — Windows Hello", "users" => "Administrar cuentas — Windows Hello", "game-ftp" => "Mostrar contraseña FTP — Windows Hello", _ => "Abrir terminal — Windows Hello" };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(token); timeout.CancelAfter(TimeSpan.FromSeconds(80));
            using var consent = new HelloConsent<string>(title, async cancellation => {
                using var foreground = new HelloForeground();
                var key = await KeyCredentialManager.OpenAsync(HelloAgent.KeyName).AsTask(cancellation);
                if (key.Status != KeyCredentialStatus.Success) throw new IOException("No se encontró la clave del propietario.");
                var result = await key.Credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(Convert.FromBase64String(request["message"]!.GetValue<string>()))).AsTask(cancellation);
                if (result.Status != KeyCredentialStatus.Success) return "";
                CryptographicBuffer.CopyToByteArray(result.Result, out var bytes); return Convert.ToBase64String(bytes);
            }, timeout.Token);
            signature = await consent.Run();
        } catch { }
        await Wire.Call(new() { ["op"] = "agent-sign", ["id"] = request["id"]!.GetValue<string>(), ["signature"] = signature }, token);
    }
}
