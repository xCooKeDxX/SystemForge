using System.Diagnostics;
using System.Management;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SystemForge;

public record InstalledDriver(string DeviceName, string DeviceClass, string Manufacturer, string Provider,
    string Version, DateTime? Date, string InfName, string HardwareId, bool IsSigned, string DeviceId);

public record DriverUpdate(string UpdateId, string Title, string Model, string Provider, string Manufacturer,
    string DeviceClass, string HardwareId, DateTime? Date, long DownloadSizeBytes);

public record DriverMatch(InstalledDriver? Current, DriverUpdate Update);
public record InstallItemResult(string UpdateId, string Title, bool Success, string Message);
public record InstallSummary(List<InstallItemResult> Items, bool RebootRequired, string RestorePoint, string? BackupFolder)
{
    /// <summary>Nothing was installed because no restore point could be made (System Protection is off).</summary>
    public bool NeedsSystemProtection { get; init; }
}
public record RestorePointResult(bool Created, string Message);
public record BackupSet(string Id, string Folder, DateTime Created, string Reason, int DriverCount, double SizeMb);

/// <summary>Lists every device and the driver it uses (WMI Win32_PnPSignedDriver).</summary>
public static class DriverScanner
{
    public static List<InstalledDriver> Scan()
    {
        var drivers = new List<InstalledDriver>();
        const string query =
            "SELECT DeviceName, DeviceClass, Manufacturer, DriverProviderName, DriverVersion, " +
            "DriverDate, InfName, HardWareID, IsSigned, DeviceID FROM Win32_PnPSignedDriver";

        using var searcher = new ManagementObjectSearcher(query);
        foreach (ManagementObject mo in searcher.Get())
        {
            using (mo)
            {
                var name = mo["DeviceName"] as string;
                if (string.IsNullOrWhiteSpace(name)) continue;

                drivers.Add(new InstalledDriver(
                    name,
                    mo["DeviceClass"] as string ?? "",
                    mo["Manufacturer"] as string ?? "",
                    mo["DriverProviderName"] as string ?? "",
                    mo["DriverVersion"] as string ?? "",
                    ParseCimDate(mo["DriverDate"] as string),
                    mo["InfName"] as string ?? "",
                    mo["HardWareID"] as string ?? "",
                    mo["IsSigned"] as bool? ?? false,
                    mo["DeviceID"] as string ?? ""));
            }
        }

        return drivers.OrderBy(d => d.DeviceClass).ThenBy(d => d.DeviceName).ToList();
    }

    static DateTime? ParseCimDate(string? cim)
    {
        if (string.IsNullOrWhiteSpace(cim)) return null;
        try { return ManagementDateTimeConverter.ToDateTime(cim); } catch { return null; }
    }
}

/// <summary>
/// Finds and installs driver updates through Windows Update. Every driver it offers is signed by Microsoft
/// and published by the hardware maker, so nothing comes from a third-party driver database.
/// </summary>
public static class WindowsUpdateService
{
    const string Criteria = "IsInstalled=0 and Type='Driver' and IsHidden=0";

    static dynamic NewSession()
    {
        var type = Type.GetTypeFromProgID("Microsoft.Update.Session")
            ?? throw new InvalidOperationException("Windows Update isn't available on this PC.");
        dynamic session = Activator.CreateInstance(type)!;
        session.ClientApplicationID = "SystemForge";
        return session;
    }

    public static List<DriverUpdate> FindDriverUpdates()
    {
        dynamic session = NewSession();
        dynamic searcher = session.CreateUpdateSearcher();
        searcher.Online = true;
        dynamic result = searcher.Search(Criteria);
        dynamic updates = result.Updates;

        var found = new List<DriverUpdate>();
        int count = updates.Count;
        for (int i = 0; i < count; i++)
        {
            dynamic u = updates[i];
            found.Add(new DriverUpdate(
                (string)u.Identity.UpdateID,
                (string)u.Title,
                Safe(() => (string)u.DriverModel),
                Safe(() => (string)u.DriverProvider),
                Safe(() => (string)u.DriverManufacturer),
                Safe(() => (string)u.DriverClass),
                Safe(() => (string)u.DriverHardwareID),
                SafeDate(() => (DateTime)u.DriverVerDate),
                SafeLong(() => Convert.ToInt64(u.MaxDownloadSize))));
        }
        return found;
    }

    /// <summary>Pairs each update with the installed driver it replaces.</summary>
    public static List<DriverMatch> Match(List<DriverUpdate> updates, List<InstalledDriver> installed) =>
        updates.Select(up => new DriverMatch(
            installed.FirstOrDefault(d =>
                    up.HardwareId.Length > 0 &&
                    (d.HardwareId.Equals(up.HardwareId, StringComparison.OrdinalIgnoreCase) ||
                     d.HardwareId.StartsWith(up.HardwareId, StringComparison.OrdinalIgnoreCase)))
                ?? installed.FirstOrDefault(d =>
                    up.Model.Length > 0 && d.DeviceName.Equals(up.Model, StringComparison.OrdinalIgnoreCase)),
            up)).ToList();

    /// <summary>Downloads and installs the chosen updates one at a time, reporting progress as it goes.</summary>
    public static (List<InstallItemResult> items, bool rebootRequired) Install(
        IReadOnlyCollection<string> updateIds, Action<int, int, string, string> progress)
    {
        dynamic session = NewSession();
        dynamic searcher = session.CreateUpdateSearcher();
        dynamic result = searcher.Search(Criteria);
        dynamic all = result.Updates;

        var wanted = new HashSet<string>(updateIds, StringComparer.OrdinalIgnoreCase);
        var chosen = new List<dynamic>();
        int count = all.Count;
        for (int i = 0; i < count; i++)
        {
            dynamic u = all[i];
            if (wanted.Contains((string)u.Identity.UpdateID)) chosen.Add(u);
        }

        var results = new List<InstallItemResult>();
        bool reboot = false;
        var collType = Type.GetTypeFromProgID("Microsoft.Update.UpdateColl")!;

        for (int i = 0; i < chosen.Count; i++)
        {
            dynamic u = chosen[i];
            string id = (string)u.Identity.UpdateID;
            string title = (string)u.Title;
            try
            {
                if (!(bool)u.EulaAccepted) u.AcceptEula();
                dynamic one = Activator.CreateInstance(collType)!;
                one.Add(u);

                progress(i + 1, chosen.Count, title, "Downloading");
                dynamic downloader = session.CreateUpdateDownloader();
                downloader.Updates = one;
                dynamic dl = downloader.Download();
                int dlCode = (int)dl.ResultCode;
                if (dlCode != 2 && dlCode != 3)
                {
                    results.Add(new InstallItemResult(id, title, false, $"Download didn't finish (code {dlCode})."));
                    continue;
                }

                progress(i + 1, chosen.Count, title, "Installing");
                dynamic installer = session.CreateUpdateInstaller();
                installer.Updates = one;
                dynamic ins = installer.Install();
                int code = (int)ins.ResultCode;
                bool ok = code == 2 || code == 3;
                if ((bool)ins.RebootRequired) reboot = true;
                results.Add(new InstallItemResult(id, title, ok,
                    ok ? "Installed" : $"Windows reported a failure (code {code}, 0x{(int)ins.HResult:X8})."));
            }
            catch (Exception ex)
            {
                results.Add(new InstallItemResult(id, title, false, ex.Message));
            }
        }

        if (chosen.Count < wanted.Count)
            results.Add(new InstallItemResult("", "Some updates", false,
                "Windows Update no longer offers some of the selected drivers. Check for updates again."));

        return (results, reboot);
    }

    static string Safe(Func<string> get) { try { return get() ?? ""; } catch { return ""; } }
    static DateTime? SafeDate(Func<DateTime> get) { try { return get(); } catch { return null; } }
    static long SafeLong(Func<long> get) { try { return get(); } catch { return 0; } }
}

/// <summary>Restore points, driver backups and rollback — the safety net around every driver change.</summary>
public static class DriverSafety
{
    public static string BackupRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SystemForge", "DriverBackups");

    static string PnpUtil => Path.Combine(Environment.SystemDirectory, "pnputil.exe");

    public static RestorePointResult CreateRestorePoint(string description)
    {
        try
        {
            using var cls = new ManagementClass(new ManagementScope(@"\\.\root\default"), new ManagementPath("SystemRestore"), null);
            using var inParams = cls.GetMethodParameters("CreateRestorePoint");
            inParams["Description"] = description;
            inParams["RestorePointType"] = 10;  // DEVICE_DRIVER_INSTALL
            inParams["EventType"] = 100;        // BEGIN_SYSTEM_CHANGE
            using var outParams = cls.InvokeMethod("CreateRestorePoint", inParams, null);
            uint code = Convert.ToUInt32(outParams?["ReturnValue"] ?? 1u);
            return code == 0
                ? new RestorePointResult(true, "Restore point made (Windows reuses the last one if it was made in the past 24 hours).")
                : new RestorePointResult(false, $"No restore point: System Protection may be off for your system drive (code {code}).");
        }
        catch (Exception ex)
        {
            return new RestorePointResult(false, $"No restore point: {ex.Message}");
        }
    }

    /// <summary>Exports the drivers of specific devices before they get replaced.</summary>
    public static BackupSet? Backup(IEnumerable<InstalledDriver> drivers, string reason) =>
        BackupInfs(drivers.Select(d => d.InfName), reason);

    /// <summary>Exports the given driver packages (by their oemNN.inf name) into a new backup.</summary>
    public static BackupSet? BackupInfs(IEnumerable<string> infNames, string reason)
    {
        // Only third-party drivers (oemNN.inf) can be exported; Windows keeps its own inbox drivers.
        var infs = infNames
            .Where(n => n.StartsWith("oem", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (infs.Count == 0) return null;

        var folder = NewBackupFolder(reason);
        foreach (var inf in infs) Run(PnpUtil, "/export-driver", inf, folder);
        return Finish(folder, reason);
    }

    public static BackupSet BackupAll(string reason)
    {
        var folder = NewBackupFolder(reason);
        var (code, output) = Run(PnpUtil, "/export-driver", "*", folder);
        var set = Finish(folder, reason);
        if (set is null) throw new InvalidOperationException($"The backup didn't export any drivers. {LastLine(output)}");
        return set;
    }

    public static List<BackupSet> ListBackups()
    {
        if (!Directory.Exists(BackupRoot)) return new List<BackupSet>();
        return Directory.GetDirectories(BackupRoot)
            .Select(Describe)
            .Where(b => b is not null)
            .Select(b => b!)
            .OrderByDescending(b => b.Created)
            .ToList();
    }

    public static string RestoreBackup(string id)
    {
        var folder = ResolveBackup(id);
        var (code, output) = Run(PnpUtil, "/add-driver", Path.Combine(folder, "*.inf"), "/subdirs", "/install");
        return code switch
        {
            0 => "Reinstalled the drivers from this backup.",
            3010 => "Reinstalled the drivers from this backup. Restart your PC to finish.",
            _ => $"Windows couldn't reinstall everything from this backup. {LastLine(output)}"
        };
    }

    /// <summary>Same as "Roll Back Driver" in Device Manager.</summary>
    public static string Rollback(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) throw new ArgumentException("No device was given.");
        IntPtr set = Native.SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        if (set == Native.INVALID_HANDLE_VALUE) throw new InvalidOperationException("Couldn't open the device list.");
        try
        {
            var data = new Native.SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<Native.SP_DEVINFO_DATA>() };
            if (!Native.SetupDiOpenDeviceInfo(set, deviceId, IntPtr.Zero, 0, ref data))
                throw new InvalidOperationException("That device isn't connected right now.");

            if (Native.DiRollbackDriver(set, ref data, IntPtr.Zero, Native.ROLLBACK_FLAG_NO_UI, out int reboot))
                return reboot != 0 ? "Rolled back. Restart your PC to finish." : "Rolled back to the previous driver.";

            int err = Marshal.GetLastWin32Error();
            throw new InvalidOperationException(
                $"Windows has no earlier driver saved for this device (error {err}). Reinstall one from the Backups tab instead.");
        }
        finally { Native.SetupDiDestroyDeviceInfoList(set); }
    }

    public static object OpenBackupFolder()
    {
        Directory.CreateDirectory(BackupRoot);
        Process.Start(new ProcessStartInfo("explorer.exe", $"\"{BackupRoot}\"") { UseShellExecute = true });
        return new { ok = true };
    }

    // ---- helpers ----

    static string NewBackupFolder(string reason)
    {
        Downloader.EnsureSecureDataRoot(); // backups are reinstalled as admin, so only admins may write here
        var folder = Path.Combine(BackupRoot, DateTime.Now.ToString("yyyy-MM-dd_HHmmss", System.Globalization.CultureInfo.InvariantCulture));
        Directory.CreateDirectory(folder);
        File.WriteAllText(Path.Combine(folder, "manifest.json"),
            JsonSerializer.Serialize(new { created = DateTime.Now, reason }));
        return folder;
    }

    static BackupSet? Finish(string folder, string reason)
    {
        var set = Describe(folder);
        if (set is null || set.DriverCount == 0)
        {
            try { Directory.Delete(folder, true); } catch { }
            return null;
        }
        return set;
    }

    static BackupSet? Describe(string folder)
    {
        try
        {
            var dir = new DirectoryInfo(folder);
            DateTime created = dir.CreationTime;
            string reason = "Backup";
            var manifest = Path.Combine(folder, "manifest.json");
            if (File.Exists(manifest))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                if (doc.RootElement.TryGetProperty("created", out var c) && c.TryGetDateTime(out var dt)) created = dt;
                if (doc.RootElement.TryGetProperty("reason", out var r)) reason = r.GetString() ?? reason;
            }
            var files = dir.EnumerateFiles("*", SearchOption.AllDirectories).ToList();
            int infCount = files.Count(f => f.Extension.Equals(".inf", StringComparison.OrdinalIgnoreCase));
            double sizeMb = Math.Round(files.Sum(f => f.Length) / 1048576.0, 1);
            return new BackupSet(dir.Name, folder, created, reason, infCount, sizeMb);
        }
        catch { return null; }
    }

    static string ResolveBackup(string id)
    {
        // Ids are plain folder names; refuse anything that tries to point elsewhere.
        if (string.IsNullOrWhiteSpace(id) || Path.GetFileName(id) != id)
            throw new ArgumentException("That backup doesn't exist.");
        Downloader.EnsureSecureDataRoot();
        var folder = Path.Combine(BackupRoot, id);
        if (!Directory.Exists(folder)) throw new ArgumentException("That backup doesn't exist.");
        return folder;
    }

    static (int code, string output) Run(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync();
        var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        return (p.ExitCode, stdout.Result + stderr.Result);
    }

    static string LastLine(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "";
}
