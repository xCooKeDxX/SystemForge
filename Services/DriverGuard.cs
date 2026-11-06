using System.Management;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace SystemForge;

public sealed record DriverPreflight(bool HasBattery, bool OnBattery, int BatteryPercent, bool RestartPending, List<string> Blockers, List<string> Warnings);

/// <summary>
/// The guard rails around driver changes, so someone who doesn't know drivers can't break their PC with SystemForge:
///   • Drivers for the parts a PC needs to start (storage controllers, chipset/system devices, firmware/BIOS,
///     the processor, TPM) are only offered with "Advanced driver options" on. A bad driver there can stop Windows booting.
///   • Drivers for unplugged devices are advanced-only too.
///   • Before installing: the laptop must be plugged in, no restart may be pending from an earlier install, and a
///     restore point must really be created. Without Advanced options these block the install; with them they're warnings.
/// The dashboard hides what isn't allowed, but these rules are enforced here as well.
/// </summary>
public static class DriverGuard
{
    /// <summary>Device classes whose driver Windows needs to boot or that touch firmware.</summary>
    static readonly Dictionary<string, string> Critical = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SCSIAdapter"] = "Storage controller: Windows starts from the drive behind it.",
        ["HDC"] = "Storage controller: Windows starts from the drive behind it.",
        ["DiskDrive"] = "The drive Windows runs from.",
        ["Volume"] = "Part of how Windows reads your drives.",
        ["VolumeSnapshot"] = "Part of how Windows reads your drives.",
        ["System"] = "Chipset or core system device. A wrong one can stop Windows starting.",
        ["Computer"] = "Core system device. A wrong one can stop Windows starting.",
        ["Processor"] = "Processor driver. A wrong one can stop Windows starting.",
        ["Firmware"] = "Firmware (BIOS/UEFI) update. Losing power during it can damage the PC.",
        ["SecurityDevices"] = "Security chip (TPM). Changes can trigger a BitLocker recovery-key prompt.",
    };

    public static bool IsCritical(string deviceClass) => Critical.ContainsKey(deviceClass ?? "");

    public static string RiskNote(string deviceClass) => Critical.GetValueOrDefault(deviceClass ?? "", "");

    /// <summary>Checks that don't change anything, shown before the install confirmation.</summary>
    public static DriverPreflight Check(AppSettings settings, bool advanced)
    {
        var blockers = new List<string>();
        var warnings = new List<string>();

        bool hasBattery = false, onBattery = false;
        int percent = -1;
        if (GetSystemPowerStatus(out var ps))
        {
            hasBattery = (ps.BatteryFlag & 128) == 0 && ps.BatteryFlag != 255;
            onBattery = hasBattery && ps.ACLineStatus == 0;
            percent = ps.BatteryLifePercent <= 100 ? ps.BatteryLifePercent : -1;
        }
        if (onBattery)
        {
            string msg = $"Your laptop is on battery{(percent >= 0 ? $" ({percent}%)" : "")}. Plug it in first: if it dies mid-install the driver can be left half-installed.";
            (advanced ? warnings : blockers).Add(msg);
        }

        bool pending = RestartPending(settings);
        if (pending)
        {
            const string msg = "Restart your PC first. An earlier update is still waiting for a restart, and stacking driver changes on top of it is how things break.";
            (advanced ? warnings : blockers).Add(msg);
        }
        return new DriverPreflight(hasBattery, onBattery, percent, pending, blockers, warnings);
    }

    /// <summary>True when Windows, or an earlier SystemForge install, is waiting for a restart.</summary>
    public static bool RestartPending(AppSettings settings)
    {
        if (settings.DriverRestartNeededUtc is DateTime since)
        {
            var bootedAt = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
            if (bootedAt < since) return true;
            settings.DriverRestartNeededUtc = null; // restarted since then
            settings.Save();
        }
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var wu = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired");
            if (wu is not null) return true;
            using var cbs = hklm.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending");
            if (cbs is not null) return true;
        }
        catch { /* can't tell: don't block */ }
        return false;
    }

    public static void NoteRestartNeeded(AppSettings settings)
    {
        settings.DriverRestartNeededUtc = DateTime.UtcNow;
        settings.Save();
    }

    /// <summary>
    /// Windows normally skips a new restore point if one was made in the last 24 hours, which would leave nothing
    /// to go back to for this change. Lift that limit for this one call, then put it back exactly as it was.
    /// </summary>
    public static RestorePointResult CreateFreshRestorePoint(string description)
    {
        const string keyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
        const string valueName = "SystemRestorePointCreationFrequency";
        object? previous = null;
        bool changed = false;
        try
        {
            using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = hklm.OpenSubKey(keyPath, writable: true);
            if (key is not null)
            {
                previous = key.GetValue(valueName);
                key.SetValue(valueName, 0, RegistryValueKind.DWord);
                changed = true;
            }
        }
        catch { /* fall back to Windows' normal rule */ }

        try { return DriverSafety.CreateRestorePoint(description); }
        finally
        {
            if (changed)
            {
                try
                {
                    using var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                    using var key = hklm.OpenSubKey(keyPath, writable: true);
                    if (previous is null) key?.DeleteValue(valueName, throwOnMissingValue: false);
                    else key?.SetValue(valueName, previous, RegistryValueKind.DWord);
                }
                catch { }
            }
        }
    }

    /// <summary>Turns on System Protection (restore points) for the Windows drive, as in System Properties.</summary>
    public static string EnableSystemProtection()
    {
        string drive = Path.GetPathRoot(Environment.SystemDirectory) ?? @"C:\";
        try
        {
            using var cls = new ManagementClass(new ManagementScope(@"\\.\root\default"), new ManagementPath("SystemRestore"), null);
            using var inParams = cls.GetMethodParameters("Enable");
            inParams["Drive"] = drive;
            inParams["WaitTillEnabled"] = true;
            using var outParams = cls.InvokeMethod("Enable", inParams, null);
            uint code = Convert.ToUInt32(outParams?["ReturnValue"] ?? 1u);
            return code == 0
                ? $"System Protection is on for {drive.TrimEnd('\\')}. You can install drivers now."
                : throw new InvalidOperationException($"Windows didn't turn on System Protection (code {code}). Turn it on in Control Panel → System → System Protection.");
        }
        catch (InvalidOperationException) { throw; }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Couldn't turn on System Protection: {ex.Message}");
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct SYSTEM_POWER_STATUS
    {
        public byte ACLineStatus;
        public byte BatteryFlag;
        public byte BatteryLifePercent;
        public byte SystemStatusFlag;
        public uint BatteryLifeTime;
        public uint BatteryFullLifeTime;
    }

    [DllImport("kernel32.dll")]
    static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);
}
