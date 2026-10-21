using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;

namespace FacuSecX.Monitor;

internal static class PipeIdentity
{
    [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetNamedPipeServerProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle handle, out uint processId);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, int size, out int needed);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint Type, State, Controls, ExitCode, SpecificCode, Checkpoint, WaitHint, ProcessId, Flags; }
    internal static void Verify(NamedPipeClientStream pipe)
    {
        if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out var serverId)) throw new Win32Exception();
        var manager = OpenSCManager(null, null, 1); if (manager == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var service = OpenService(manager, State.ServiceName, 4); if (service == IntPtr.Zero) throw new Win32Exception();
            try
            {
                if (!QueryServiceStatusEx(service, 0, out var status, Marshal.SizeOf<ServiceStatus>(), out _) || status.State != 4 || status.ProcessId == 0 || status.ProcessId != serverId) throw new UnauthorizedAccessException("El canal no pertenece al servicio protegido.");
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(manager); }
    }
}
