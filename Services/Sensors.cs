using System.Management;
using LibreHardwareMonitor.Hardware;
using Microsoft.Win32;

namespace SystemForge;

/// <summary>One temperature (°C) or fan speed (RPM).</summary>
public record SensorValue(string Group, string Device, string Name, double Value, string Kind);

public record SensorReport(
    double? CpuC, double? GpuC, List<SensorValue> Sensors,
    bool DriverInstalled, bool CpuNeedsDriver, string Unit);

/// <summary>
/// Temperatures and fan speeds through LibreHardwareMonitor (MPL-2.0).
/// Graphics cards and drives are read without any driver. CPU and motherboard sensors need the PawnIO driver
/// (signed, open source, by namazso), which is offered as an optional install. The old WinRing0 driver that
/// Defender flags is never used. All values are kept in °C; the screen converts to °F when asked.
/// </summary>
public static class Sensors
{
    static readonly object gate = new();
    static Computer? computer;
    static bool openFailed;
    static SensorReport? last;
    static DateTime lastRead = DateTime.MinValue;

    // Drives are slow to query (and a sleeping hard drive would be woken), so they refresh once a minute.
    static List<SensorValue> driveCache = new();
    static DateTime lastDrives = DateTime.MinValue;
    static List<SensorValue> zoneCache = new();
    static DateTime lastZones = DateTime.MinValue;

    public static SensorReport Read(string unit)
    {
        lock (gate)
        {
            if (last is not null && DateTime.UtcNow - lastRead < TimeSpan.FromSeconds(1.5))
                return last with { Unit = unit };

            if (computer is null && !openFailed)
            {
                try
                {
                    var c = new Computer { IsCpuEnabled = true, IsGpuEnabled = true, IsMotherboardEnabled = true, IsStorageEnabled = true };
                    c.Open();
                    computer = c;
                }
                catch { openFailed = true; }
            }

            var list = new List<SensorValue>();
            bool drivesDue = DateTime.UtcNow - lastDrives > TimeSpan.FromSeconds(60);
            var drives = new List<SensorValue>();

            if (computer is not null)
            {
                foreach (var hw in computer.Hardware.ToList())
                {
                    string? group = GroupOf(hw.HardwareType);
                    if (group is null) continue;
                    if (group == "Drives" && !drivesDue) continue;
                    try
                    {
                        hw.Update();
                        foreach (var sub in hw.SubHardware) sub.Update();
                    }
                    catch { continue; /* this device stopped answering; keep the rest */ }
                    Collect(hw, group, group == "Drives" ? drives : list);
                }
            }

            if (drivesDue)
            {
                if (drives.Count == 0) drives = DrivesFromWindows();
                driveCache = drives;
                lastDrives = DateTime.UtcNow;
            }
            list.AddRange(driveCache);

            // No motherboard chip readable (no driver): fall back to the ACPI thermal zone Windows exposes.
            if (!list.Any(s => s.Group == "Motherboard" && s.Kind == "temp"))
            {
                if (DateTime.UtcNow - lastZones > TimeSpan.FromSeconds(10))
                {
                    zoneCache = ThermalZones();
                    lastZones = DateTime.UtcNow;
                }
                list.AddRange(zoneCache);
            }

            double? cpu = Pick(list, "Processor", "CPU Package", "Core (Tctl/Tdie)", "Core (Tctl)", "Tctl", "Core (Tdie)", "Core Max", "Core Average");
            double? gpu = PickGpu(list);
            bool driver = DriverInstalled();
            last = new SensorReport(cpu, gpu, list, driver, cpu is null && !driver, unit);
            lastRead = DateTime.UtcNow;
            return last;
        }
    }

    /// <summary>Re-detects hardware, e.g. after the sensor driver was installed.</summary>
    public static void Reset()
    {
        lock (gate)
        {
            try { computer?.Close(); } catch { }
            computer = null;
            openFailed = false;
            last = null;
            lastDrives = DateTime.MinValue;
        }
    }

    public static void Shutdown()
    {
        lock (gate)
        {
            try { computer?.Close(); } catch { }
            computer = null;
        }
    }

    /// <summary>PawnIO registers both an uninstall entry and a driver service.</summary>
    public static bool DriverInstalled()
    {
        try
        {
            using var u = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\PawnIO");
            if (u is not null) return true;
            using var s = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\PawnIO");
            return s is not null;
        }
        catch { return false; }
    }

    static string? GroupOf(HardwareType t) => t switch
    {
        HardwareType.Cpu => "Processor",
        HardwareType.GpuNvidia or HardwareType.GpuAmd or HardwareType.GpuIntel => "Graphics",
        HardwareType.Motherboard or HardwareType.SuperIO or HardwareType.EmbeddedController => "Motherboard",
        HardwareType.Storage => "Drives",
        _ => null,
    };

    static void Collect(IHardware hw, string group, List<SensorValue> into)
    {
        foreach (var h in new[] { hw }.Concat(hw.SubHardware))
        {
            foreach (var s in h.Sensors)
            {
                if (s.Value is not float f || float.IsNaN(f) || float.IsInfinity(f)) continue;
                if (s.SensorType == SensorType.Temperature)
                {
                    // Unconnected motherboard inputs read -55, 0 or 127; real parts sit well inside this range.
                    if (f < 5 || f > 125) continue;
                    // "Distance to TjMax" is headroom, not a temperature.
                    if (s.Name.Contains("Distance", StringComparison.OrdinalIgnoreCase)) continue;
                    // Drives report several (warning limits etc.); the one called "Temperature" is the live reading.
                    if (group == "Drives" && !s.Name.StartsWith("Temperature", StringComparison.OrdinalIgnoreCase)) continue;
                    into.Add(new SensorValue(group, hw.Name, s.Name, Math.Round(f, 1), "temp"));
                }
                else if (s.SensorType == SensorType.Fan && f > 0 && f < 20000)
                {
                    into.Add(new SensorValue(group, hw.Name, s.Name, Math.Round(f), "fan"));
                }
            }
        }
    }

    static double? Pick(List<SensorValue> list, string group, params string[] preferred)
    {
        var temps = list.Where(s => s.Group == group && s.Kind == "temp").ToList();
        if (temps.Count == 0) return null;
        foreach (var name in preferred)
        {
            var hit = temps.FirstOrDefault(s => s.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (hit is not null) return hit.Value;
        }
        return temps.Max(s => s.Value);
    }

    /// <summary>The graphics card games run on: a dedicated card's core temperature before integrated graphics.</summary>
    static double? PickGpu(List<SensorValue> list)
    {
        var temps = list.Where(s => s.Group == "Graphics" && s.Kind == "temp").ToList();
        if (temps.Count == 0) return null;
        var dedicated = temps.Where(s => !s.Device.Contains("Intel", StringComparison.OrdinalIgnoreCase)).ToList();
        var pool = dedicated.Count > 0 ? dedicated : temps;
        return (pool.FirstOrDefault(s => s.Name.Equals("GPU Core", StringComparison.OrdinalIgnoreCase)) ?? pool[0]).Value;
    }

    static List<SensorValue> DrivesFromWindows()
    {
        var list = new List<SensorValue>();
        try
        {
            foreach (var d in HealthMonitor.PhysicalDisks())
                if (d.TemperatureC is int t && t > 0 && t < 125)
                    list.Add(new SensorValue("Drives", d.Name, "Temperature", t, "temp"));
        }
        catch { }
        return list;
    }

    /// <summary>ACPI thermal zones, in tenths of a kelvin. Usually a motherboard or chipset reading.</summary>
    static List<SensorValue> ThermalZones()
    {
        var list = new List<SensorValue>();
        try
        {
            using var q = new ManagementObjectSearcher(@"root\cimv2",
                "SELECT Name, HighPrecisionTemperature FROM Win32_PerfFormattedData_Counters_ThermalZoneInformation");
            int i = 0;
            foreach (ManagementObject o in q.Get())
            {
                using (o)
                {
                    double c = Convert.ToDouble(o["HighPrecisionTemperature"]) / 10.0 - 273.15;
                    if (c < 5 || c > 110) continue;
                    i++;
                    list.Add(new SensorValue("Motherboard", "ACPI", i == 1 ? "Thermal zone" : $"Thermal zone {i}", Math.Round(c, 1), "temp"));
                }
            }
        }
        catch { }
        return list;
    }
}
