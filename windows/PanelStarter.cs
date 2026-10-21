using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;
using System.Reflection;
[assembly: AssemblyTitle("Server Monitor")]
[assembly: AssemblyDescription("Server Monitor")]
[assembly: AssemblyProduct("Server Monitor")]
[assembly: AssemblyCompany("FacuSecX")]
[assembly: AssemblyVersion("3.0.0.0")]
[assembly: AssemblyFileVersion("3.0.0.0")]

internal static class PanelStarter
{
    [STAThread]
    private static int Main()
    {
        try
        {
            string root = AppDomain.CurrentDomain.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar);
            string script = Path.Combine(root, "windows", "Start-panel.ps1");
            if (!File.Exists(script)) throw new IOException("No se encontro el archivo de inicio del panel.");
            var info = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), @"WindowsPowerShell\v1.0\powershell.exe"));
            info.UseShellExecute = false;
            info.CreateNoWindow = true;
            info.WindowStyle = ProcessWindowStyle.Hidden;
            info.WorkingDirectory = root;
            info.Arguments = "-NoProfile -ExecutionPolicy Bypass -File \"" + script + "\" -SourceRoot \"" + root + "\"";
            using (var process = Process.Start(info)) { process.WaitForExit(); return process.ExitCode; }
        }
        catch
        {
            MessageBox.Show("No se pudo iniciar el panel. Verifica que su carpeta este completa.", "Server Monitor", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
    }
}
