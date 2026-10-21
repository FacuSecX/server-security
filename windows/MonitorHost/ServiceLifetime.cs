using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32.SafeHandles;

namespace FacuSecX.Monitor;

internal static class ServiceLifetime
{
    // All service children inherit this job. If the service process disappears,
    // Windows terminates Node and its helpers instead of leaving a collector
    // that continuously tries to contact a broker which no longer exists.
    private static SafeFileHandle? job;
    internal static void Attach()
    {
        if (job != null) return;
        var handle = CreateJobObjectW(0, null);
        if (handle.IsInvalid) throw new Win32Exception();
        var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } };
        if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()) || !AssignProcessToJobObject(handle, Process.GetCurrentProcess().Handle)) {
            int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error);
        }
        job = handle; // Keep the only job handle until the service process exits.
    }
    internal static SafeFileHandle OwnChild(Process process)
    {
        var handle = CreateJobObjectW(0, null);
        if (handle.IsInvalid) throw new Win32Exception();
        var limits = new ExtendedLimits { Basic = new BasicLimits { Flags = 0x2000 } };
        if (!SetInformationJobObject(handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimits>()) || !AssignProcessToJobObject(handle, process.Handle)) {
            int error = Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error);
        }
        return handle;
    }
    internal static void EnsureRunning()
    {
        using var service = new ServiceController(State.ServiceName);
        if (service.Status == ServiceControllerStatus.StopPending) service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
        service.Refresh();
        if (service.Status == ServiceControllerStatus.Stopped) service.Start();
        service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
    }
    internal static void WaitStopped()
    {
        using var service = new ServiceController(State.ServiceName);
        service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
    }
    internal static int Probe()
    {
        Attach();
        using var child = Process.Start(new ProcessStartInfo(Environment.ProcessPath!, "job-lifetime-child") { UseShellExecute = false, CreateNoWindow = true }) ?? throw new IOException();
        Console.WriteLine(child.Id); Console.Out.Flush();
        return 0;
    }
    [StructLayout(LayoutKind.Sequential)] private struct BasicLimits { public long ProcessTime, JobTime; public uint Flags; public nuint MinWorkingSet, MaxWorkingSet; public uint ActiveProcesses; public nuint Affinity; public uint Priority, Scheduling; }
    [StructLayout(LayoutKind.Sequential)] private struct IoCounters { public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes; }
    [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimits { public BasicLimits Basic; public IoCounters Io; public nuint ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern SafeFileHandle CreateJobObjectW(nint attributes, string? name);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref ExtendedLimits limits, uint length);
    [DllImport("kernel32.dll", SetLastError = true)] [return: MarshalAs(UnmanagedType.Bool)] private static extern bool AssignProcessToJobObject(SafeFileHandle job, nint process);
}
