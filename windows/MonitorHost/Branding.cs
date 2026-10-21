using System.Runtime.InteropServices;

namespace FacuSecX.Monitor;

internal static class Branding
{
    internal const string Name = "Server Monitor";
    internal const string PickerTitle = Name + " · Elegir servidor";
    internal static Icon LoadIcon()
    {
        using var stream = typeof(Branding).Assembly.GetManifestResourceStream("ServerMonitor.Icon") ?? throw new IOException("Falta el icono de Server Monitor.");
        using var icon = new Icon(stream, new Size(32, 32));
        return (Icon)icon.Clone();
    }
    internal static void Initialize()
    {
        SetCurrentProcessExplicitAppUserModelID("FacuSecX.ServerMonitor");
        ApplicationConfiguration.Initialize();
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SetCurrentProcessExplicitAppUserModelID(string appId);
}
