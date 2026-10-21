using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace FacuSecX.Monitor;

internal sealed record HelloWindow(nint Handle, uint ProcessId, int SessionId, string ClassName, string Executable, bool TopMost);
internal interface IHelloWindows
{
    IReadOnlyList<HelloWindow> List();
    void Raise(HelloWindow window);
    void Restore(HelloWindow window);
}
internal sealed class NativeHelloWindows : IHelloWindows
{
    private delegate bool EnumWindow(nint window, nint parameter);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindow callback, nint parameter);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(nint window, StringBuilder name, int count);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(nint window);
    [DllImport("user32.dll")] private static extern bool IsIconic(nint window);
    [DllImport("user32.dll")] private static extern bool ShowWindowAsync(nint window, int command);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint window, out uint process);
    [DllImport("user32.dll")] private static extern bool SetForegroundWindow(nint window);
    [DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] private static extern nint GetWindowLongPtr(nint window, int index);
    [DllImport("user32.dll")] private static extern bool SetWindowPos(nint window, nint after, int x, int y, int width, int height, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] private static extern nint OpenProcess(uint access, bool inherit, uint id);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryFullProcessImageName(nint process, uint flags, StringBuilder name, ref int count);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(nint handle);
    private readonly HashSet<nint> changed = new();
    private const uint PositionOnly = 0x0001 | 0x0002 | 0x0010 | 0x0200 | 0x4000; // no resize, move, activate or owner reordering; asynchronous
    private static HelloWindow? Read(nint window)
    {
        if (!IsWindowVisible(window)) return null;
        var name = new StringBuilder(256); GetClassName(window, name, name.Capacity);
        if (name.ToString() != "Credential Dialog Xaml Host") return null;
        GetWindowThreadProcessId(window, out uint id);
        using var process = Process.GetProcessById((int)id);
        var handle = OpenProcess(0x1000, false, id); if (handle == 0) return null;
        string executable;
        try { var path = new StringBuilder(32768); int size = path.Capacity; if (!QueryFullProcessImageName(handle, 0, path, ref size)) return null; executable = path.ToString(); }
        finally { CloseHandle(handle); }
        return new(window, id, process.SessionId, name.ToString(), executable, (GetWindowLongPtr(window, -20).ToInt64() & 8) != 0);
    }
    public IReadOnlyList<HelloWindow> List()
    {
        var result = new List<HelloWindow>();
        EnumWindows((window, _) => { try { var value = Read(window); if (value != null) result.Add(value); } catch { } return true; }, 0);
        return result;
    }
    public void Raise(HelloWindow window)
    {
        var current = Read(window.Handle);
        if (current == null || current.ProcessId != window.ProcessId || !HelloForeground.Eligible(current, window.SessionId)) return;
        if (IsIconic(window.Handle)) ShowWindowAsync(window.Handle, 9);
        // Keep the real OS prompt visible even when Windows denies foreground permission.
        if (!current.TopMost && SetWindowPos(window.Handle, new nint(-1), 0, 0, 0, 0, PositionOnly)) changed.Add(window.Handle);
        if (GetForegroundWindow() != window.Handle) SetForegroundWindow(window.Handle);
    }
    public void Restore(HelloWindow window)
    {
        if (!changed.Remove(window.Handle) || window.TopMost) return;
        var current = Read(window.Handle);
        if (current != null && current.ProcessId == window.ProcessId && HelloForeground.Eligible(current, window.SessionId))
            SetWindowPos(window.Handle, new nint(-2), 0, 0, 0, 0, PositionOnly);
    }
}
