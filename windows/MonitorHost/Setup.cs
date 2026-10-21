using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Win32;

namespace FacuSecX.Monitor;

internal static class Setup
{
    private static void Progress(string phase, bool failed = false, string? category = null)
    {
        try {
            var path = Path.Combine(Path.GetDirectoryName(State.InstallPath)!, "migration-status.json");
            State.CheckPath(path);
            File.WriteAllText(path, new JsonObject { ["time"] = DateTimeOffset.UtcNow.ToString("O"), ["phase"] = phase, ["failed"] = failed, ["category"] = category }.ToJsonString(), new UTF8Encoding(false));
        } catch { }
    }
    internal static int Run(string[] args, bool resume = false)
    {
        if (!State.Elevated || args.Length != 2 || WindowsIdentity.GetCurrent().User?.Value != args[1]) throw new UnauthorizedAccessException("La instalación requiere elevación del mismo usuario de Windows que posee las cuentas.");
        if (!string.Equals(AppContext.BaseDirectory.TrimEnd('\\'), Path.Combine(State.InstallPath, "native"), StringComparison.OrdinalIgnoreCase)) throw new IOException("Ejecutá el instalador desde su ubicación protegida.");
        var source = Path.GetFullPath(args[0]).TrimEnd('\\');
        using (var old = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(State.RegistryPath))
        {
            if (!resume && old != null) throw new IOException("Esta instalación ya tiene propietario. No se reemplazará su registro; usá el acceso existente o la recuperación.");
            if (resume && (old == null || (int)(old.GetValue("Activated") ?? 0) == 1 || (int)(old.GetValue("SetupPending") ?? 0) != 1 || old.GetValue("OwnerSid") as string != args[1] || !string.Equals(old.GetValue("SourceRoot") as string, source, StringComparison.OrdinalIgnoreCase))) throw new UnauthorizedAccessException("No se puede reanudar esta instalación desde otra identidad o carpeta.");
        }
        if (!resume && System.IO.Directory.EnumerateFiles(State.DirectoryPath, "*.dpapi").Any()) throw new IOException("Se encontraron datos de una instalación anterior. Restaurá su registro; no se creará otro administrador.");
        var legacyId = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(source.ToLowerInvariant()))).ToLowerInvariant()[..20];
        var legacyFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FacuSecX", "ServerSecurityMonitor", legacyId, "accounts.dpapi");
        JsonObject? accounts = null;
        byte[]? legacyDigest = null;
        bool recoverPendingAccounts = false;
        if (resume)
        {
            recoverPendingAccounts = State.Mode() == "recovery";
            accounts = State.Read(recoverPendingAccounts ? "checkpoint.dpapi" : "accounts.dpapi", recoverPendingAccounts ? "checkpoint" : "accounts")?["accounts"]?.DeepClone().AsObject();
            if (recoverPendingAccounts && accounts == null) throw new IOException("Falta el respaldo protegido. Restauralo antes de reanudar; no se crearán cuentas nuevas.");
            if (accounts == null)
            {
                using var anchor = State.Registry();
                if (anchor.GetValue("LegacyPath") is string previousPath)
                {
                    State.CheckPath(previousPath);
                    if (!File.Exists(previousPath) || Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(previousPath))) != anchor.GetValue("LegacyDigest") as string) throw new IOException("Faltan las cuentas originales o cambiaron. Restaurá su respaldo; no se creará otro administrador.");
                    var clear = ProtectedData.Unprotect(File.ReadAllBytes(previousPath), Encoding.UTF8.GetBytes("FacuSecX.ServerSecurityMonitor.Accounts.v1"), DataProtectionScope.CurrentUser);
                    try { accounts = JsonNode.Parse(clear)!.AsObject(); } finally { CryptographicOperations.ZeroMemory(clear); }
                }
            }
            if (accounts != null) State.ValidateAccounts(accounts);
        }
        else if (File.Exists(legacyFile))
        {
            State.CheckPath(legacyFile);
            legacyDigest = SHA256.HashData(File.ReadAllBytes(legacyFile));
            var clear = ProtectedData.Unprotect(File.ReadAllBytes(legacyFile), Encoding.UTF8.GetBytes("FacuSecX.ServerSecurityMonitor.Accounts.v1"), DataProtectionScope.CurrentUser);
            try { accounts = JsonNode.Parse(clear)!.AsObject(); State.ValidateAccounts(accounts); }
            finally { CryptographicOperations.ZeroMemory(clear); }
        }
        else if (File.Exists(Path.Combine(source, "data", ".panel-auth-initialized"))) throw new IOException("La instalación anterior tenía cuentas y ahora faltan. Restaurá su respaldo antes de migrar.");
        var configPath = Path.Combine(State.InstallPath, "panel", "config.json");
        JsonObject config;
        try { config = JsonNode.Parse(File.ReadAllText(configPath))!.AsObject(); }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or InvalidOperationException)
        { config = new JsonObject { ["listenHost"] = "127.0.0.1", ["listenPort"] = 8766, ["refreshSeconds"] = 20, ["geoLookup"] = true, ["trustedSshIps"] = new JsonArray() }; }
        if (config["ssh"] is not JsonObject) config["ssh"] = new JsonObject { ["authMode"] = "password" };
        var ssh = config["ssh"]!.AsObject();
        if (resume)
        {
            // Incomplete candidate credentials must remain correctable, never a
            // reason to discard the original owner or require a new account.
            try
            {
                var saved = SshTransport.PendingSettings();
                ssh["authMode"] = saved["mode"]!.DeepClone(); ssh["host"] = saved["host"]!.DeepClone(); ssh["port"] = saved["port"]!.DeepClone(); ssh["user"] = saved["user"]!.DeepClone(); ssh["hostKeyFingerprint"] = saved["fingerprint"]!.DeepClone();
            }
            catch (Exception ex) when (ex is IOException or CryptographicException or System.Text.Json.JsonException) { }
        }
        using var form = new Form { Icon = Branding.LoadIcon(), Text = resume ? "Reanudar configuración de Server Monitor" : "Configurar Server Monitor", Width = 780, Height = 720, StartPosition = FormStartPosition.CenterScreen, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, TopMost = true, AutoScroll = true };
        var layout = new TableLayoutPanel { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(20), ColumnCount = 1 };
        form.Controls.Add(layout);
        layout.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(700, 0), Text = accounts != null ? "Se conservarán todas tus cuentas y permisos. Confirmá la contraseña actual del administrador principal y Windows Hello." : "Configurá el acceso al servidor. Windows Hello registrará al propietario; después elegirás el administrador en el panel." });
        layout.Controls.Add(new Label { Text = "Contraseña actual del administrador del panel (" + (accounts?["users"]?.AsArray().OfType<JsonObject>().Single(x => x["primary"]?.GetValue<bool>() == true)["username"]?.GetValue<string>() ?? "") + ")", AutoSize = true, Visible = accounts != null });
        var passwordRow = new TableLayoutPanel { ColumnCount = 2, Dock = DockStyle.Top, AutoSize = true, Visible = accounts != null };
        passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100)); passwordRow.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        var master = new TextBox { UseSystemPasswordChar = true, Dock = DockStyle.Top, MaxLength = 128, Enabled = accounts != null };
        var show = new CheckBox { Text = "Mostrar", AutoSize = true }; show.CheckedChanged += (_, _) => master.UseSystemPasswordChar = !show.Checked;
        passwordRow.Controls.Add(master); passwordRow.Controls.Add(show); layout.Controls.Add(passwordRow);
        var fields = new SshSetupFields(ssh); layout.Controls.Add(fields);
        var localPort = new NumericUpDown { Minimum = 1, Maximum = 65535, Value = Math.Clamp(config["listenPort"]?.GetValue<int>() ?? 8766, 1, 65535), Width = 140 };
        layout.Controls.Add(new Label { Text = "Puerto local del panel", AutoSize = true }); layout.Controls.Add(localPort);
        layout.Controls.Add(new Label { AutoSize = true, MaximumSize = new Size(700, 0), Text = "La configuración sólo se activa después de comprobar SSH y la pantalla de acceso al panel. Si falla, podés corregirla y reintentar. No se instalan servicios en el VPS durante esta comprobación." });
        var error = new Label { AutoSize = true, ForeColor = Color.Firebrick, MaximumSize = new Size(700, 0) }; layout.Controls.Add(error);
        var confirm = new Button { Text = "Comprobar conexión y continuar", AutoSize = true }; layout.Controls.Add(confirm); bool success = false, busy = false, requiresResume = false;
        form.FormClosing += (_, e) => { if (busy) e.Cancel = true; };
        confirm.Click += async (_, _) =>
        {
            busy = true; confirm.Enabled = false; fields.Enabled = false; passwordRow.Enabled = false; localPort.Enabled = false; error.Text = "Comprobando…"; var phase = "accounts";
            JsonObject? verifiedAccounts = accounts; bool refreshVerifier = false;
            try
            {
                Progress("accounts");
                if (accounts != null)
                {
                    var verified = await PasswordVerifier.Verify(accounts, master.Text, Path.Combine(State.InstallPath, "node", "node.exe"), Path.Combine(State.InstallPath, "panel", "auth-migration-check.mjs"), config["listenPort"]?.GetValue<int>() ?? 8766);
                    verifiedAccounts = verified["accounts"]!.AsObject(); State.ValidateAccounts(verifiedAccounts);
                    refreshVerifier = verified["refresh"]?.GetValue<bool>() == true;
                    Progress("accounts-verified");
                }
                phase = "key";
                Progress(phase);
                var transport = fields.Settings(source);
                phase = "ssh";
                Progress(phase);
                using (var connectionCheck = new SshTransport(() => transport, pin => fields.Trust(transport["host"]!.GetValue<string>(), transport["port"]!.GetValue<int>(), pin)))
                using (var connectionTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30)))
                    await SshSettings.Check(connectionCheck, connectionTimeout.Token);
                phase = "hello";
                Progress(phase);
                form.TopMost = false;
                var id = resume ? State.Value("InstallId") : Guid.NewGuid().ToString("N");
                (string PublicKey, string Algorithm) ownerKey = ("", "");
                if (resume) await HelloAgent.VerifyOwner(form); else ownerKey = await HelloAgent.Enroll(id, form);
                if (recoverPendingAccounts) State.Recover();
                if (legacyDigest != null && !CryptographicOperations.FixedTimeEquals(legacyDigest, SHA256.HashData(File.ReadAllBytes(legacyFile)))) throw new IOException("Las cuentas cambiaron durante la verificación. Cerrá este asistente y volvé a iniciarlo.");
                phase = "save";
                Progress(phase);
                // Record is created only by an elevated installer, after successful Hello enrollment.
                if (!resume)
                {
                    using var existing = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(State.RegistryPath);
                    if (existing != null) throw new IOException("Ya hay un propietario registrado. Cerrá y reanudá el asistente; no se reemplazará su identidad.");
                    using var registry = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(State.RegistryPath, true);
                    registry.SetValue("InstallId", id); registry.SetValue("OwnerSid", args[1]); registry.SetValue("OwnerPublicKey", ownerKey.PublicKey); registry.SetValue("OwnerAlgorithm", ownerKey.Algorithm);
                    registry.SetValue("Enrolled", 0, RegistryValueKind.DWord); registry.SetValue("SetupPending", 1, RegistryValueKind.DWord); registry.SetValue("Activated", 0, RegistryValueKind.DWord); registry.SetValue("SourceRoot", source); registry.Flush();
                    if (legacyDigest != null) { registry.SetValue("LegacyPath", legacyFile); registry.SetValue("LegacyDigest", Convert.ToHexString(legacyDigest)); registry.Flush(); }
                }
                State.Write("ssh.pending.dpapi", "ssh", transport);
                if (verifiedAccounts != null && (!resume || State.Mode() == "setup")) State.Save(verifiedAccounts, true);
                if (refreshVerifier && verifiedAccounts != null)
                {
                    using var refreshedRegistry = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(State.RegistryPath, true)!;
                    refreshedRegistry.SetValue("RefreshLegacy", 1, RegistryValueKind.DWord); refreshedRegistry.Flush();
                }
                ssh["host"] = transport["host"]!.DeepClone(); ssh["port"] = transport["port"]!.DeepClone(); ssh["user"] = transport["user"]!.DeepClone(); ssh["hostKeyFingerprint"] = transport["fingerprint"]!.DeepClone();
                ssh["authMode"] = "key"; ssh["keyPath"] = ""; ssh.Remove("pageantPath"); ssh.Remove("passwordEnv");
                ssh.Remove("password"); ssh.Remove("privateKey");
                ssh["plinkPath"] = Path.Combine(State.InstallPath, "native", "FacuSecX.SshBridge.exe");
                config["listenHost"] = "127.0.0.1"; config["listenPort"] = (int)localPort.Value;
                var temporaryConfig = configPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    using (var file = new FileStream(temporaryConfig, FileMode.CreateNew, FileAccess.Write, FileShare.None)) { file.Write(Encoding.UTF8.GetBytes(config.ToJsonString())); file.Flush(true); }
                    if (File.Exists(configPath)) File.Replace(temporaryConfig, configPath, null); else File.Move(temporaryConfig, configPath);
                }
                finally { if (File.Exists(temporaryConfig)) File.Delete(temporaryConfig); }
                Progress("prepared"); master.Clear(); fields.Secret.Clear(); success = true; busy = false; form.Close();
            }
            catch (Exception ex) { Progress(phase, true, ex.GetType().Name + " " + ex.HResult.ToString("X8")); error.Text = ex is IOException ? ex.Message : phase switch {
                "accounts" => "Falló el verificador local de cuentas. Tus cuentas no se modificaron; no se pudo comprobar la contraseña.",
                "key" => "No se pudo leer la llave o su frase secreta. Revisá el método de acceso y el archivo seleccionado. No se guardó esta conexión.",
                "ssh" => "La conexión SSH no pudo verificarse. Revisá IP, puerto, usuario, credencial y huella. Podés corregir los datos y reintentar; no se guardó esta conexión.",
                "hello" => "Windows Hello no completó la verificación del propietario. Tus cuentas originales se conservan.",
                _ => "No se pudo completar la instalación protegida. Tus cuentas originales se conservan."
            }; if (phase == "save") { requiresResume = true; error.Text += " Cerrá esta ventana y abrí iniciar-panel.bat para reanudar con el mismo propietario."; } }
            finally { if (!success) await Task.Delay(3000); busy = false; if (!form.IsDisposed) { confirm.Enabled = !requiresResume; fields.Enabled = !requiresResume; passwordRow.Enabled = !requiresResume; localPort.Enabled = !requiresResume; } }
        };
        Application.Run(form);
        return success ? 0 : 1;
    }
}
