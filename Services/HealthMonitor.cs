using System.Management;
using Microsoft.Win32;

namespace SystemForge;

public record SystemInfo(string Os, string Build, string Cpu, string Gpu, int Threads, double RamGb, string MachineName);
public record VolumeInfo(string Name, string Label, double TotalGb, double FreeGb, double UsedPercent, bool IsSystem);
public record HealthSnapshot(double Cpu, double Gpu, double RamUsedGb, double RamTotalGb, double RamPercent, long UptimeSeconds, List<VolumeInfo> Volumes);
public record PhysicalDiskInfo(string Name, string Media, string Bus, double SizeGb, string Health, int? TemperatureC, int? WearPercent);

/// <summary>Measures total CPU use between calls. Each consumer keeps its own sampler.</summary>
public sealed class CpuSampler
{
    readonly object gate = new();
    long lastIdle, lastKernel, lastUser;
    bool primed;

    public double Sample()
    {
        lock (gate)
        {
            if (!Native.GetSystemTimes(out var idle, out var kernel, out var user)) return 0;
            if (!primed)
            {
                (lastIdle, lastKernel, lastUser, primed) = (idle, kernel, user, true);
                return 0;
            }
            long dIdle = idle - lastIdle, dKernel = kernel - lastKernel, dUser = user - lastUser;
            (lastIdle, lastKernel, lastUser) = (idle, kernel, user);
            long total = dKernel + dUser; // kernel time includes idle time
            if (total <= 0) return 0;
            return Math.Clamp((total - dIdle) * 100.0 / total, 0, 100);
        }
    }
}

public static class HealthMonitor
{
    const double GB = 1024d * 1024 * 1024;
    static readonly Lazy<SystemInfo> info = new(LoadInfo);

    public static SystemInfo Info => info.Value;

    public static HealthSnapshot Snapshot(CpuSampler cpu, GpuSampler gpu)
    {
        var mem = Native.GetMemory();
        double total = mem.ullTotalPhys / GB;
        double used = total - mem.ullAvailPhys / GB;
        string systemRoot = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";

        var volumes = new List<VolumeInfo>();
        foreach (var d in DriveInfo.GetDrives())
        {
            // One bad drive (BitLocker-locked, disconnecting, access denied) must not fail the whole snapshot.
            try
            {
                if (d.DriveType != DriveType.Fixed || !d.IsReady) continue;
                long size = d.TotalSize, free = d.AvailableFreeSpace;
                volumes.Add(new VolumeInfo(
                    d.Name.TrimEnd('\\'),
                    SafeLabel(d),
                    R(size / GB),
                    R(free / GB),
                    size > 0 ? R(100.0 * (size - free) / size) : 0,
                    d.Name.Equals(systemRoot, StringComparison.OrdinalIgnoreCase)));
            }
            catch { /* skip this drive */ }
        }

        return new HealthSnapshot(
            R(cpu.Sample()), R(gpu.Sample()), R(used), R(total), total > 0 ? R(100 * used / total) : 0,
            Environment.TickCount64 / 1000, volumes);
    }

    /// <summary>Physical drives with health, temperature and wear where the drive reports them.</summary>
    public static List<PhysicalDiskInfo> PhysicalDisks()
    {
        var list = new List<PhysicalDiskInfo>();
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Storage");
            using var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_PhysicalDisk"));
            foreach (ManagementObject disk in searcher.Get())
            {
                using (disk)
                {
                    int? temp = null, wear = null;
                    try
                    {
                        foreach (ManagementObject rc in disk.GetRelated("MSFT_StorageReliabilityCounter"))
                        {
                            using (rc)
                            {
                                if (rc["Temperature"] is not null) { int t = Convert.ToInt32(rc["Temperature"]); if (t > 0) temp = t; }
                                if (rc["Wear"] is not null) wear = Convert.ToInt32(rc["Wear"]);
                            }
                        }
                    }
                    catch { /* not every drive exposes reliability counters */ }

                    list.Add(new PhysicalDiskInfo(
                        disk["FriendlyName"] as string ?? "Drive",
                        Convert.ToInt32(disk["MediaType"] ?? 0) switch { 3 => "HDD", 4 => "SSD", 5 => "SCM", _ => "Drive" },
                        Convert.ToInt32(disk["BusType"] ?? 0) switch { 17 => "NVMe", 11 => "SATA", 7 => "USB", 8 => "RAID", 10 => "SAS", _ => "" },
                        R(Convert.ToUInt64(disk["Size"] ?? 0UL) / GB),
                        Convert.ToInt32(disk["HealthStatus"] ?? 5) switch { 0 => "Healthy", 1 => "Warning", 2 => "Unhealthy", _ => "Unknown" },
                        temp, wear));
                }
            }
        }
        catch { /* storage WMI unavailable */ }
        return list;
    }

    static SystemInfo LoadInfo()
    {
        int build = Environment.OSVersion.Version.Build;
        string os = "Windows", cpu = "Processor", gpu = "Graphics";

        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var product = k?.GetValue("ProductName") as string ?? "Windows";
            // Windows 11 still reports "Windows 10" here.
            if (build >= 22000) product = product.Replace("Windows 10", "Windows 11");
            var version = k?.GetValue("DisplayVersion") as string;
            os = version is null ? product : $"{product} {version}";
        }
        catch { }

        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            cpu = (k?.GetValue("ProcessorNameString") as string ?? cpu).Trim();
        }
        catch { }

        try
        {
            using var s = new ManagementObjectSearcher("SELECT Name FROM Win32_VideoController");
            var names = s.Get().Cast<ManagementObject>()
                .Select(o => o["Name"] as string ?? "")
                .Where(n => n.Length > 0 && !n.Contains("Basic Display") && !n.Contains("Remote"))
                .Distinct()
                .ToList();
            if (names.Count > 0) gpu = string.Join(" + ", names);
        }
        catch { }

        return new SystemInfo(os, build.ToString(), cpu, gpu, Environment.ProcessorCount,
            R(Native.GetMemory().ullTotalPhys / GB), Environment.MachineName);
    }

    static string SafeLabel(DriveInfo d)
    {
        try { return d.VolumeLabel; } catch { return ""; }
    }

    static double R(double v) => Math.Round(v, 1);
}
