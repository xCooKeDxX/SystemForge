using System.Security.Principal;
using System.Text.Json;

namespace SystemForge;

/// <summary>
/// Connects the dashboard (JavaScript) to the C# services.
/// JS sends { id, cmd, args }; C# answers { type: "reply", id, ok, data | error } and can push { type: "event", name, data }.
/// </summary>
public sealed class Bridge
{
    readonly MainForm form;
    readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web);
    readonly CpuSampler cpu = new();
    readonly GpuSampler gpu = new();
    readonly ProcessSampler apps = new();
    List<InstalledDriver>? lastScan;

    public Bridge(MainForm form) => this.form = form;

    public async Task HandleAsync(string rawJson)
    {
        int id = 0;
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            id = root.GetProperty("id").GetInt32();
            string cmd = root.GetProperty("cmd").GetString() ?? "";
            JsonElement args = root.TryGetProperty("args", out var a) ? a.Clone() : default;

            object? data = await Task.Run(() => Dispatch(cmd, args));
            Send(new { type = "reply", id, ok = true, data });
        }
        catch (Exception ex)
        {
            var inner = ex is System.Reflection.TargetInvocationException { InnerException: not null } t ? t.InnerException! : ex;
            Send(new { type = "reply", id, ok = false, error = inner.Message });
        }
    }

    object? Dispatch(string cmd, JsonElement a) => cmd switch
    {
        "app.info" => AppInfo(),
        "health.snapshot" => Snapshot(),
        "sensors.read" => Sensors.Read(form.Settings.TempUnit),
        "sensors.installDriver" => InstallSensorDriver(),
        "settings.unit" => SetUnit(Str(a, "unit")),
        "settings.opacity" => SetOpacity(Int(a, "value", 96)),
        "app.checkUpdate" => Wait(Updater.CheckAsync()),
        "app.lastUpdate" => Updater.Last,
        "app.installUpdate" => InstallUpdate(),

        "gamemode.status" => GameMode.Status(),
        "gamemode.set" => GameMode.Set(Bool(a, "on")),
        "gamemode.option" => GameMode.SetOption(Str(a, "key"), Bool(a, "value")),
        "gamemode.game" => GameMode.SetGame(Str(a, "path"), OptStr(a, "list"), Bool(a, "add")),
        "gamemode.candidates" => GameMode.Candidates(),
        "gamemode.openWindowsSettings" => OpenWindowsGameMode(),
        "health.disks" => HealthMonitor.PhysicalDisks(),

        "drivers.scan" => lastScan = DriverScanner.Scan(),
        "drivers.check" => Wait(DriverUpdates.CheckAsync((stage, done, total) =>
                                Emit("drivers.scanProgress", new { stage, done, total }))),
        "drivers.install" => InstallDrivers(StrList(a, "ids")),
        "drivers.backupAll" => DriverSafety.BackupAll("Full backup"),
        "drivers.backups" => DriverSafety.ListBackups(),
        "drivers.restoreBackup" => new { message = DriverSafety.RestoreBackup(Str(a, "id")) },
        "drivers.rollback" => Rollback(Str(a, "deviceId")),
        "drivers.preflight" => DriverGuard.Check(form.Settings, form.Settings.AdvancedDrivers),
        "drivers.enableRestore" => new { message = DriverGuard.EnableSystemProtection() },
        "system.openRestore" => OpenSystemRestore(),
        "drivers.openBackups" => DriverSafety.OpenBackupFolder(),

        "junk.scan" => JunkCleaner.Scan(),
        "junk.clean" => JunkCleaner.Clean(StrList(a, "ids"), StrList(a, "exclude")),
        "junk.files" => JunkCleaner.Files(Str(a, "id"), Int(a, "offset", 0), Int(a, "limit", 200), OptStr(a, "query"), OptStr(a, "sort")),
        "junk.reveal" => JunkCleaner.Reveal(Str(a, "path")),

        "startup.list" => StartupManager.List(),
        "startup.set" => StartupManager.SetEnabled(Str(a, "id"), Bool(a, "enabled")),
        "startup.reveal" => StartupManager.Reveal(Str(a, "id")),

        "memory.optimize" => MemoryOptimizer.Optimize(GameMode.GamePid),
        "apps.top" => apps.TopApps(14),
        "apps.end" => ProcessManager.EndApp(Str(a, "name")),

        "apps.check" => Wait(AppUpdates.CheckAsync(form.Settings)),
        "apps.last" => AppUpdates.Last,
        "apps.update" => Wait(AppUpdates.InstallAsync(StrList(a, "ids"), (phase, i, n, title, pct) =>
                                Emit("apps.progress", new { phase, index = i, total = n, title, percent = pct }))),
        "apps.ignore" => AppUpdates.Ignore(form.Settings, Str(a, "id"), Bool(a, "ignore")),
        "apps.skip" => AppUpdates.Skip(form.Settings, Str(a, "id"), OptStr(a, "version")),

        "security.status" => new { defender = Defender.Status(), threats = Defender.Threats() },
        "security.scan" => RunSecurityScan(),
        "security.last" => lastSecurityScan,
        "security.fix" => SecurityFixes.Apply(StrList(a, "ids"), form.Settings, (label, i, n) =>
                                Emit("security.fixProgress", new { label, index = i, total = n })),
        "security.history" => SecurityFixes.Journal().OrderByDescending(e => e.When).Take(200).ToList(),
        "security.undo" => new { message = SecurityFixes.UndoEntry(Str(a, "id")) },
        "security.deleteQuarantined" => NativeConfirm.Ask("Delete quarantined files for good?",
                                "The files from this fix will be permanently deleted and can't be put back.")
                                ? new { message = SecurityFixes.DeleteQuarantined(Str(a, "id")) }
                                : new { message = "Kept in quarantine." },
        "security.trust" => Trust(Str(a, "key"), Bool(a, "trust")),
        "defender.update" => new { message = Defender.UpdateDefinitions() },
        "defender.scan" => new { message = Defender.Scan(Bool(a, "full")) },
        "defender.offline" => NativeConfirm.Ask("Restart into Microsoft Defender Offline?",
                                "Your PC will restart now and scan for about 15 minutes before Windows starts. Save your work first.")
                                ? new { message = Defender.StartOfflineScan() }
                                : new { message = "Offline scan cancelled." },
        "defender.removeThreats" => new { message = Defender.RemoveThreats() },
        "system.openCredit" => OpenCredit(),
        "system.openVendorUrl" => OpenVendorUrl(Str(a, "url")),

        "settings.set" => SetSetting(Str(a, "key"), Bool(a, "value")),
        "overlay.toggle" => OnUi(() => form.ToggleOverlay()),

        _ => throw new InvalidOperationException($"Unknown command: {cmd}"),
    };

    object AppInfo()
    {
        bool admin;
        using (var identity = WindowsIdentity.GetCurrent())
            admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);

        return new
        {
            version = typeof(Bridge).Assembly.GetName().Version?.ToString(3) ?? "0.1.0",
            isAdmin = admin,
            hotkey = MainForm.HotkeyLabel,
            settings = form.Settings,
            system = HealthMonitor.Info,
        };
    }

    object Snapshot()
    {
        var snap = HealthMonitor.Snapshot(cpu, gpu);
        SensorReport? temps = null;
        try { temps = Sensors.Read(form.Settings.TempUnit); } catch { }
        return new { snap.Cpu, snap.Gpu, snap.RamUsedGb, snap.RamTotalGb, snap.RamPercent, snap.UptimeSeconds, snap.Volumes,
            cpuTempC = temps?.CpuC, gpuTempC = temps?.GpuC, unit = form.Settings.TempUnit, gameMode = GameMode.Active };
    }

    object InstallUpdate()
    {
        var u = Updater.Last?.Update ?? throw new InvalidOperationException("Check for updates first.");
        string msg = Wait(Updater.InstallAsync(u, (phase, pct) => Emit("app.updateProgress", new { phase, percent = pct }),
            () => { try { form.BeginInvoke(() => form.QuitForUpdate()); } catch { } }));
        return new { message = msg };
    }

    AppSettings SetOpacity(int value)
    {
        form.Settings.OverlayOpacity = Math.Clamp(value, 40, 100);
        form.Settings.Save();
        OnUi(() => form.RefreshOverlay());
        return form.Settings;
    }

    AppSettings SetUnit(string unit)
    {
        if (unit is not ("C" or "F")) throw new ArgumentException("Use C or F.");
        form.Settings.TempUnit = unit;
        form.Settings.Save();
        OnUi(() => form.RefreshOverlay());
        return form.Settings;
    }

    /// <summary>
    /// PawnIO is a signed, open-source kernel driver (by namazso) that LibreHardwareMonitor, Fan Control and others
    /// use to read CPU and motherboard sensors. It's optional, so it only goes on after a real Windows confirmation.
    /// </summary>
    object InstallSensorDriver()
    {
        if (Sensors.DriverInstalled()) { Sensors.Reset(); return new { message = "The sensor driver is already installed." }; }
        if (!Winget.IsAvailable) throw new InvalidOperationException("winget (App Installer) isn't available, so the driver can't be installed from here.");
        if (!NativeConfirm.Ask("Install the PawnIO sensor driver?",
                "CPU and motherboard temperatures and fan speeds can only be read through a driver.\n\n" +
                "PawnIO is a small, signed, open-source driver by namazso, used by LibreHardwareMonitor and Fan Control. " +
                "It only lets approved programs read sensors. You can remove it any time from Settings › Apps.\n\nInstall it now?"))
            return new { message = "Not installed." };

        var (ok, message, reboot) = Wait(Winget.InstallAsync("namazso.PawnIO", true,
            (phase, pct) => Emit("sensors.driverProgress", new { phase, percent = pct }), CancellationToken.None));
        Sensors.Reset();
        if (!ok) throw new InvalidOperationException($"The driver didn't install: {message}");
        return new { message = reboot ? "Installed. Restart your PC to see CPU temperatures." : "Installed. CPU and motherboard temperatures are now available." };
    }

    static object OpenWindowsGameMode()
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("ms-settings:gaming-gamemode") { UseShellExecute = true });
        return new { ok = true };
    }

    InstallSummary InstallDrivers(List<string> ids)
    {
        if (ids.Count == 0) throw new InvalidOperationException("Pick at least one update to install.");
        lastScan = null;
        return Wait(DriverUpdates.InstallAsync(ids, form.Settings, (phase, i, n, title, pct) =>
            Emit("drivers.progress", new { phase, index = i, total = n, title, percent = pct })));
    }

    SecScan? lastSecurityScan;

    SecScan RunSecurityScan()
    {
        var defender = Defender.Status();
        var threats = Defender.Threats();
        return lastSecurityScan = new SecurityScanner(form.Settings, (step, pct) =>
            Emit("security.progress", new { step, percent = pct })).Run(defender, threats);
    }

    AppSettings Trust(string key, bool trust)
    {
        if (key.Length == 0 || key.Length > 1000) throw new ArgumentException("Nothing to trust.");
        var s = form.Settings;
        s.SecurityTrusted.RemoveAll(k => k.Equals(key, StringComparison.OrdinalIgnoreCase));
        if (trust) s.SecurityTrusted.Add(key);
        s.Save();
        return s;
    }

    /// <summary>Opens a maker's download in the browser (manual BIOS files). Only the four makers' hosts are allowed.</summary>
    static object OpenVendorUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttps ||
            !(u.Host.EndsWith("asus.com", StringComparison.OrdinalIgnoreCase) || u.Host.EndsWith("lenovo.com", StringComparison.OrdinalIgnoreCase) ||
              u.Host.EndsWith("dell.com", StringComparison.OrdinalIgnoreCase) || u.Host.EndsWith("hp.com", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("That isn't one of the makers' download sites.");
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(url) { UseShellExecute = true });
        return new { ok = true };
    }

    /// <summary>The only web page the dashboard can open: the credit link for PC Health Scan.</summary>
    static object OpenCredit()
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("https://github.com/TCPeep/PC-Health-Scan") { UseShellExecute = true });
        return new { ok = true };
    }

    object Rollback(string deviceId)
    {
        // Rolling back a storage or chipset driver can stop Windows booting just like installing one.
        var dev = DeviceInventory.Scan().FirstOrDefault(d => d.InstanceId.Equals(deviceId, StringComparison.OrdinalIgnoreCase));
        if (dev is not null && DriverGuard.IsCritical(dev.Class) && !form.Settings.AdvancedDrivers)
            throw new InvalidOperationException($"{dev.Name} is a device Windows needs to start. Rolling back its driver needs Advanced driver options (Settings).");
        return new { message = DriverSafety.Rollback(deviceId) };
    }

    static object OpenSystemRestore()
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "rstrui.exe")) { UseShellExecute = true });
        return new { ok = true };
    }

    /// <summary>Dispatch already runs on a worker thread, so blocking on async work here is safe.</summary>
    static T Wait<T>(Task<T> task) => task.GetAwaiter().GetResult();

    object SetSetting(string key, bool value)
    {
        var s = form.Settings;
        switch (key)
        {
            case "overlayEnabled":
                s.OverlayEnabled = value;
                if (!value) OnUi(() => form.ToggleOverlay(false));
                break;
            case "advancedDrivers":
                // Turning safety off needs a real Windows confirmation, not just the page.
                if (value && !NativeConfirm.Ask("Turn on Advanced driver options?",
                        "This shows drivers for storage, chipset and firmware, which can stop Windows from starting if they go wrong, and turns some safety checks into warnings. Only for experienced users."))
                    break;
                s.AdvancedDrivers = value;
                break;
            case "appUpdateChecks":
                s.AppUpdateChecks = value;
                break;
            case "minimizeToTray":
                s.MinimizeToTray = value;
                break;
            case "startWithWindows":
                AutoStart.Set(value);
                s.StartWithWindows = AutoStart.IsEnabled();
                s.AutoStartPath = value ? Environment.ProcessPath : null;
                break;
            default:
                throw new ArgumentException($"Unknown setting: {key}");
        }
        s.Save();
        return s;
    }

    object OnUi(Action action)
    {
        form.Invoke(action);
        return new { ok = true };
    }

    // ---- messaging ----

    public void Emit(string name, object data) => Send(new { type = "event", name, data });

    void Send(object message)
    {
        string payload = JsonSerializer.Serialize(message, json);
        try
        {
            if (form.IsDisposed) return;
            form.BeginInvoke(() => form.PostToWeb(payload));
        }
        catch { /* window closing */ }
    }

    // ---- argument helpers ----

    static string Str(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()! : throw new ArgumentException($"Missing '{name}'.");

    static bool Bool(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) &&
        (v.ValueKind == JsonValueKind.True || v.ValueKind == JsonValueKind.False)
            ? v.GetBoolean() : throw new ArgumentException($"Missing '{name}'.");

    static string OptStr(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString() ?? "" : "";

    static int Int(JsonElement a, string name, int fallback) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number &&
        v.TryGetInt32(out int n) ? n : fallback;

    static List<string> StrList(JsonElement a, string name) =>
        a.ValueKind == JsonValueKind.Object && a.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!).ToList()
            : new List<string>();
}
