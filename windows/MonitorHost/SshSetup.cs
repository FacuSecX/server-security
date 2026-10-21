using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace FacuSecX.Monitor;

internal static class SshSettings
{
    internal static string Host(string value)
    {
        value = value.Trim();
        if (value.Length is < 1 or > 253 || value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c))) throw new IOException("Ingresá una IP o un dominio válido, sin protocolo ni puerto.");
        if (IPAddress.TryParse(value, out var address)) return address.ToString();
        string ascii;
        try { ascii = new IdnMapping().GetAscii(value); } catch (ArgumentException) { throw new IOException("El dominio del servidor no es válido."); }
        if (ascii.Length > 253 || !ascii.Split('.').All(label => Regex.IsMatch(label, "^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"))) throw new IOException("Ingresá una IP o un dominio válido, sin protocolo ni puerto.");
        return ascii.ToLowerInvariant();
    }
    internal static JsonObject Create(string host, int port, string user, string mode, string secret, string fingerprint, string keyPath, string source)
    {
        host = Host(host); user = user.Trim(); fingerprint = fingerprint.Trim().TrimEnd('=');
        if (port is < 1 or > 65535) throw new IOException("El puerto SSH debe estar entre 1 y 65535.");
        if (!Regex.IsMatch(user, "^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}[$]?$")) throw new IOException("El usuario SSH no es válido.");
        if (mode is not ("key" or "password")) throw new IOException("Elegí contraseña SSH o llave privada.");
        if (secret.Length > 1024 || secret.Any(char.IsControl) || mode == "password" && secret.Length == 0) throw new IOException("Ingresá una contraseña SSH válida.");
        if (fingerprint.Length != 0 && !Regex.IsMatch(fingerprint, "^SHA256:[A-Za-z0-9+/]{43}$")) throw new IOException("La huella debe tener formato SHA256. Podés dejarla vacía para verificarla al conectar por primera vez.");
        var settings = new JsonObject { ["host"] = host, ["port"] = port, ["user"] = user, ["mode"] = mode, ["secret"] = secret, ["fingerprint"] = fingerprint };
        if (mode == "key")
        {
            if (string.IsNullOrWhiteSpace(keyPath)) throw new IOException("Seleccioná el archivo de tu llave privada.");
            var path = Path.GetFullPath(keyPath, source); State.CheckPath(path);
            if (new FileInfo(path).Length > 262144) throw new IOException("La llave privada supera el tamaño permitido.");
            var bytes = File.ReadAllBytes(path);
            try { using var stream = new MemoryStream(bytes); using var check = new Renci.SshNet.PrivateKeyFile(stream, secret); settings["privateKey"] = Convert.ToBase64String(bytes); }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return settings;
    }
    internal const string CheckCommand = "test \"$(uname -s)\" = Linux && command -v python3 >/dev/null && test -x /usr/local/sbin/storypulse-securityctl && sudo -n -l /usr/local/sbin/storypulse-securityctl collect --json-input >/dev/null 2>&1 && printf FACUSECX_MONITOR_READY";
    internal static async Task Check(SshTransport transport, CancellationToken cancellation)
    {
        var client = await transport.Connect(cancellation);
        using var command = client.CreateCommand(CheckCommand); command.CommandTimeout = TimeSpan.FromSeconds(15);
        await command.ExecuteAsync(cancellation);
        if (command.ExitStatus != 0 || command.Result != "FACUSECX_MONITOR_READY") throw new IOException("El acceso SSH funciona, pero falta Python 3, el controlador del panel o su permiso sudo sin contraseña. Prepará el controlador del panel en el VPS y volvé a comprobar. No se guardó esta conexión.");
    }
}

internal sealed class SshSetupFields : UserControl
{
    internal readonly TextBox Host = new() { Dock = DockStyle.Fill, MaxLength = 253 };
    internal readonly NumericUpDown Port = new() { Dock = DockStyle.Fill, Minimum = 1, Maximum = 65535, Value = 22 };
    internal readonly TextBox User = new() { Dock = DockStyle.Fill, MaxLength = 65 };
    internal readonly ComboBox Mode = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    internal readonly TextBox KeyPath = new() { Dock = DockStyle.Fill, MaxLength = 1024 };
    internal readonly TextBox Secret = new() { Dock = DockStyle.Fill, UseSystemPasswordChar = true, MaxLength = 1024 };
    internal readonly TextBox Fingerprint = new() { Dock = DockStyle.Fill, MaxLength = 51 };
    private readonly Label secretLabel = new() { AutoSize = true };
    private readonly TableLayoutPanel keyRow = new() { ColumnCount = 2, Dock = DockStyle.Top, AutoSize = true };
    private readonly Label keyLabel = new() { Text = "Llave privada PPK / OpenSSH", AutoSize = true };
    internal SshSetupFields(JsonObject ssh)
    {
        Dock = DockStyle.Top; AutoSize = true;
        var grid = new TableLayoutPanel { ColumnCount = 2, Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 8, 0, 8) };
        grid.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 185)); grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); Controls.Add(grid);
        void Row(Control label, Control control) { int row = grid.RowCount++; grid.Controls.Add(label, 0, row); grid.Controls.Add(control, 1, row); label.Margin = new Padding(0, 8, 8, 8); control.Margin = new Padding(0, 5, 0, 5); }
        Row(new Label { Text = "IP o dominio del servidor", AutoSize = true }, Host);
        Row(new Label { Text = "Puerto SSH", AutoSize = true }, Port);
        Row(new Label { Text = "Usuario SSH", AutoSize = true }, User);
        Mode.Items.AddRange(new[] { "Contraseña SSH", "Llave privada" }); Row(new Label { Text = "Método de acceso", AutoSize = true }, Mode);
        keyRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); keyRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var browse = new Button { Text = "Examinar…", AutoSize = true }; keyRow.Controls.Add(KeyPath); keyRow.Controls.Add(browse);
        browse.Click += (_, _) => { using var file = new OpenFileDialog { Title = "Seleccionar llave SSH", Filter = "Llaves SSH|*.ppk;*.pem;id_*|Todos los archivos|*.*", CheckFileExists = true }; if (file.ShowDialog(this) == DialogResult.OK) KeyPath.Text = file.FileName; };
        Row(keyLabel, keyRow); Row(secretLabel, Secret);
        Row(new Label { Text = "Huella SHA256 (opcional)", AutoSize = true }, Fingerprint);
        Host.Text = ssh["host"]?.GetValue<string>() ?? ""; User.Text = ssh["user"]?.GetValue<string>() ?? "";
        if (Host.Text.Contains("IP_O_DOMINIO", StringComparison.Ordinal)) Host.Clear(); if (User.Text == "USUARIO_SSH") User.Clear();
        int port = ssh["port"]?.GetValue<int>() ?? 22; Port.Value = port is >= 1 and <= 65535 ? port : 22;
        KeyPath.Text = ssh["keyPath"]?.GetValue<string>() ?? "";
        if (KeyPath.Text.Contains("RUTA\\A\\LLAVE", StringComparison.Ordinal)) KeyPath.Clear();
        Fingerprint.Text = ssh["hostKeyFingerprint"]?.GetValue<string>() ?? "";
        if (!Regex.IsMatch(Fingerprint.Text, "^SHA256:[A-Za-z0-9+/]{43}=?$")) Fingerprint.Clear();
        Mode.SelectedIndexChanged += (_, _) => { bool key = Mode.SelectedIndex == 1; keyRow.Visible = key; keyLabel.Visible = key; secretLabel.Text = key ? "Frase de la llave (si tiene)" : "Contraseña SSH"; Secret.Clear(); };
        Mode.SelectedIndex = ssh["authMode"]?.GetValue<string>() == "key" ? 1 : 0;
        Host.TextChanged += (_, _) => Fingerprint.Clear(); Port.ValueChanged += (_, _) => Fingerprint.Clear();
    }
    internal JsonObject Settings(string source) => SshSettings.Create(Host.Text, (int)Port.Value, User.Text, Mode.SelectedIndex == 1 ? "key" : "password", Secret.Text, Fingerprint.Text, KeyPath.Text, source);
    internal bool Trust(string host, int port, string fingerprint) => (bool)Invoke(() => MessageBox.Show(this,
        "Servidor: " + host + ":" + port + "\nHuella: " + fingerprint + "\n\nComparala con la huella que te proporciona el administrador o la consola de tu proveedor. Aceptar sin comprobarla no garantiza la identidad del servidor.\n\n¿Confirmás que corresponde a tu servidor?", "Verificar identidad SSH", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) == DialogResult.Yes);
}
