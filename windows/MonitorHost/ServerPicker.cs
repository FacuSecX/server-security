using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json.Nodes;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;

namespace FacuSecX.Monitor;

internal static class ServerPicker
{
    internal static async Task<string> Sign(JsonObject request, IWin32Window owner, CancellationToken token)
    {
        using var consent = new HelloConsent<string>("Conectar al servidor — Windows Hello", async cancellation => {
            using var foreground = new HelloForeground();
            var key = await KeyCredentialManager.OpenAsync(HelloAgent.KeyName).AsTask(cancellation);
            if (key.Status != KeyCredentialStatus.Success) throw new IOException("No se encontró la identidad del propietario. Tus cuentas se conservan.");
            var proof = await key.Credential.RequestSignAsync(CryptographicBuffer.CreateFromByteArray(Convert.FromBase64String(request["message"]!.GetValue<string>()))).AsTask(cancellation);
            if (proof.Status != KeyCredentialStatus.Success) throw new IOException("La conexión se canceló en Windows Hello. No se guardaron cambios.");
            CryptographicBuffer.CopyToByteArray(proof.Result, out var bytes); return Convert.ToBase64String(bytes);
        }, token);
        return await consent.Run(owner);
    }
    internal static Form? Current { get; private set; }
    internal static int Run(bool dialog = false)
    {
        if (WindowsIdentity.GetCurrent().User?.Value != State.Value("OwnerSid")) throw new UnauthorizedAccessException("Abrí el panel desde el usuario de Windows propietario.");
        using var mutex = new Mutex(true, "Local\\FacuSecX.ServerPicker." + State.Value("InstallId"), out var first);
        if (!first) return 0;
        using var form = new Form { Icon = Branding.LoadIcon(), Text = Branding.PickerTitle, ClientSize = new Size(790, 640), MinimumSize = new Size(700, 650), StartPosition = FormStartPosition.CenterScreen, Font = new Font("Segoe UI", 10), MaximizeBox = false };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(22), ColumnCount = 1, RowCount = 5 };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize)); layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        var heading = new Label { Text = "Elegí el servidor al que querés conectarte", AutoSize = true, Font = new Font("Segoe UI", 15, FontStyle.Bold), Margin = new Padding(0,0,0,16) };
        var list = new ListView { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, MultiSelect = false, HideSelection = false };
        list.Columns.Add("Servidor", 215); list.Columns.Add("Dirección SSH", 250); list.Columns.Add("Usuario", 145);
        var editor = new TableLayoutPanel { Dock = DockStyle.Fill, AutoScroll = true, ColumnCount = 1, Visible = false };
        editor.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        var name = new TextBox { Dock = DockStyle.Top, MaxLength = 80, PlaceholderText = "Nombre para reconocer el servidor (opcional)" };
        var fields = new SshSetupFields(new JsonObject { ["authMode"] = "password" }); editor.Controls.Add(name); editor.Controls.Add(fields);
        var content = new Panel { Dock = DockStyle.Fill }; content.Controls.Add(editor); content.Controls.Add(list);
        var note = new Label { AutoSize = true, MaximumSize = new Size(740,0), Margin = new Padding(0,14,0,8), Text = "Las conexiones se guardan cifradas después de verificarlas. La cuenta del panel es la misma para todos los servidores; cada servidor conserva su propio historial." };
        var status = new Label { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(740,0), Margin = new Padding(0,4,0,12), Text = "Cargando conexiones…" };
        var actions = new FlowLayoutPanel { AutoSize = true, Dock = DockStyle.Fill, FlowDirection = FlowDirection.RightToLeft };
        var connect = new Button { Text = "Conectar con Windows Hello", AutoSize = true, Enabled = false };
        var add = new Button { Text = "Nueva conexión", AutoSize = true, Enabled = false };
        var cancel = new Button { Text = "Cancelar", AutoSize = true };
        actions.Controls.Add(connect); actions.Controls.Add(add); actions.Controls.Add(cancel);
        layout.Controls.Add(heading); layout.Controls.Add(content); layout.Controls.Add(note); layout.Controls.Add(status); layout.Controls.Add(actions); form.Controls.Add(layout); form.AcceptButton = connect;
        bool fresh = false, busy = false; using var lifetime = new CancellationTokenSource();
        form.FormClosing += (_, _) => lifetime.Cancel();
        void Edit(bool value) { fresh = value; editor.Visible = value; list.Visible = !value; add.Text = value ? "Volver a conexiones" : "Nueva conexión"; heading.Text = value ? "Agregar un servidor" : "Elegí el servidor al que querés conectarte"; connect.Enabled = value || list.SelectedItems.Count == 1; status.Text = ""; }
        list.SelectedIndexChanged += (_, _) => { if (!busy) connect.Enabled = fresh || list.SelectedItems.Count == 1; };
        list.DoubleClick += (_, _) => { if (connect.Enabled) connect.PerformClick(); };
        add.Click += (_, _) => { if (!busy) Edit(!fresh); }; cancel.Click += (_, _) => form.Close();
        form.Shown += async (_, _) => {
            try {
                var response = await Wire.Call(new JsonObject { ["op"] = "servers-list" }, lifetime.Token); Check(response);
                foreach (var row in response["profiles"]!.AsArray().OfType<JsonObject>()) {
                    var item = new ListViewItem(new[] { row["label"]!.GetValue<string>(), row["host"]!.GetValue<string>() + ":" + row["port"]!.GetValue<int>(), row["user"]!.GetValue<string>() }) { Tag = row["id"]!.GetValue<string>() }; list.Items.Add(item);
                    if (row["id"]!.GetValue<string>() == response["active"]!.GetValue<string>()) item.Selected = true;
                }
                add.Enabled = true; status.Text = ""; if (list.Items.Count == 0) Edit(true);
            } catch (Exception ex) { status.Text = ex is IOException ? ex.Message : "No se pudieron cargar las conexiones. Abrí el panel nuevamente."; }
        };
        connect.Click += async (_, _) => {
            if (busy) return; busy = true; connect.Enabled = false; add.Enabled = false; list.Enabled = false; fields.Enabled = false; name.Enabled = false;
            try {
                status.ForeColor = Color.FromArgb(45,100,75); status.Text = "Comprobando la conexión y el acceso al panel…";
                var request = new JsonObject { ["op"] = "server-prepare" };
                if (fresh) {
                    var settings = fields.Settings(State.InstallPath);
                    using var check = new SshTransport(() => settings, pin => fields.Trust(settings["host"]!.GetValue<string>(), settings["port"]!.GetValue<int>(), pin));
                    using var limit = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token); limit.CancelAfter(TimeSpan.FromSeconds(35));
                    await SshSettings.Check(check, limit.Token);
                    request["settings"] = settings; request["label"] = ServerProfiles.Label(string.IsNullOrWhiteSpace(name.Text) ? settings["host"]!.GetValue<string>() : name.Text);
                } else request["id"] = list.SelectedItems[0].Tag!.ToString();
                var prepared = await Wire.Call(request, lifetime.Token); Check(prepared);
                status.Text = "Confirmá la conexión con Windows Hello…";
                string signature = await Sign(prepared, form, lifetime.Token);
                status.Text = "Abriendo el panel del servidor seleccionado…";
                var committed = await Wire.Call(new JsonObject { ["op"] = "server-commit", ["token"] = prepared["token"]!.DeepClone(), ["signature"] = signature }, lifetime.Token); Check(committed);
                fields.Secret.Clear();
                Process.Start(new ProcessStartInfo("http://127.0.0.1:" + committed["port"]!.GetValue<int>() + "/login?server=" + committed["server"]!.GetValue<string>()) { UseShellExecute = true });
                form.Close();
            } catch (OperationCanceledException) { if (!form.IsDisposed) { status.ForeColor = Color.Firebrick; status.Text = "La conexión se canceló o tardó demasiado. Podés volver a intentarlo."; } }
            catch (Exception ex) { if (!form.IsDisposed) { status.ForeColor = Color.Firebrick; status.Text = ex is IOException ? ex.Message : "No se pudo completar la conexión. Se conserva el servidor anterior; verificá los datos e intentá nuevamente."; } }
            finally { busy = false; if (!form.IsDisposed) { add.Enabled = true; list.Enabled = true; fields.Enabled = true; name.Enabled = true; connect.Enabled = fresh || list.SelectedItems.Count == 1; } }
        };
        Current = form;
        try { if (dialog) form.ShowDialog(); else Application.Run(form); }
        finally { Current = null; }
        return 0;
    }
    private static void Check(JsonObject response) { if (response["ok"]?.GetValue<bool>() != true) throw new IOException(response["error"]?.GetValue<string>() ?? "El servicio no pudo completar la conexión."); }
}
