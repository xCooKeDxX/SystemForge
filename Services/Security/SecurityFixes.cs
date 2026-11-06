using System.Diagnostics;
using System.Management;
using System.Text.Json;
using Microsoft.Win32;

namespace SystemForge;

public sealed record FixResult(string Id, string Label, bool Ok, string Message);

public sealed class JournalEntry
{
    public string Id { get; set; } = "";
    public DateTime When { get; set; }
    public string Kind { get; set; } = "";
    public string Label { get; set; } = "";
    public Dictionary<string, string> Undo { get; set; } = new();
    public bool CanUndo { get; set; }
    public bool Undone { get; set; }
}

/// <summary>
/// The only things the Security page can change. The scan registers each possible fix here and the dashboard only
/// ever sends back fix ids, so it can't ask for anything that wasn't offered. Everything changed is recorded in a
/// journal (ProgramData\SystemForge\Security) with what's needed to put it back:
/// files and folders are moved to quarantine rather than deleted, registry values and settings are saved first,
/// tasks and services are turned off rather than deleted. Windows' own files and Microsoft-signed programs are never touched.
/// The same safety model as PC Health Scan by TCPeep, written for SystemForge.
/// </summary>
public static class SecurityFixes
{
    sealed record Pending(string Kind, string Label, string Risk, Dictionary<string, string> P);

    static readonly object Gate = new();
    static Dictionary<string, Pending> pending = new();
    static int counter;

    static string Root => Path.Combine(Downloader.DataRoot, "Security");
    static string QuarantineRoot => Path.Combine(Downloader.DataRoot, "Quarantine");
    static string JournalFile => Path.Combine(Root, "journal.json");

    /// <summary>Called when a new scan starts: fixes from the previous scan stop being valid.</summary>
    public static void BeginScan()
    {
        lock (Gate) pending = new();
    }

    public static SecAction Plan(string kind, string label, string risk, bool recommended, Dictionary<string, string> p)
    {
        string id;
        lock (Gate)
        {
            id = $"a{++counter}";
            pending[id] = new Pending(kind, label, risk, p);
        }
        return new SecAction(id, label, risk, recommended);
    }

    // ---- what may be quarantined ----

    static readonly string[] Protected =
    {
        "csrss", "winlogon", "services", "smss", "lsass", "wininit", "svchost", "dwm", "explorer", "msmpeng", "system", "registry",
        "chrome", "msedge", "firefox", "brave", "opera", "vivaldi", "cmd", "powershell", "pwsh", "windowsterminal", "code", "devenv",
        "anydesk", "teamviewer", "rustdesk", "systemforge",
    };

    public static bool CanQuarantine(string path)
    {
        try
        {
            string? full = Normalize(path);
            if (full is null) return false;
            bool isDir = Directory.Exists(full);
            if (!isDir && !File.Exists(full)) return false;
            if (Path.GetPathRoot(full)?.TrimEnd('\\').Equals(full, StringComparison.OrdinalIgnoreCase) == true) return false;
            if (SecUtil.Zone(full) == "Windows") return false;

            // Never whole well-known folders, only things inside them.
            var keep = new List<string>
            {
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
                Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? "",
                SecUtil.WinDir,
            };
            foreach (var v in new[] { "OneDrive", "OneDriveConsumer", "OneDriveCommercial" })
            {
                string? od = Environment.GetEnvironmentVariable(v);
                if (string.IsNullOrEmpty(od)) continue;
                keep.Add(od);
                foreach (var sub in new[] { "Desktop", "Documents", "Pictures" }) keep.Add(Path.Combine(od, sub));
            }
            foreach (var p in SecUtil.Profiles())
            {
                keep.Add(p);
                foreach (var sub in new[] { "AppData", @"AppData\Local", @"AppData\Roaming", @"AppData\LocalLow", @"AppData\Local\Programs", @"AppData\Local\Temp", "Desktop", "Downloads", "Documents",
                             @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" })
                    keep.Add(Path.Combine(p, sub));
            }
            if (keep.Any(k => k.Length > 0 && k.TrimEnd('\\').Equals(full, StringComparison.OrdinalIgnoreCase))) return false;

            // Never SystemForge itself or its own data.
            foreach (var own in new[] { AppContext.BaseDirectory.TrimEnd('\\'), Downloader.DataRoot })
                if (full.Equals(own, StringComparison.OrdinalIgnoreCase) || full.StartsWith(own + "\\", StringComparison.OrdinalIgnoreCase) ||
                    own.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase)) return false;

            if (!isDir)
            {
                var sig = FileTrust.Check(full);
                if (sig.Trusted && sig.IsMicrosoft) return false;
            }
            return true;
        }
        catch { return false; }
    }

    // ---- applying ----

    static readonly SemaphoreSlim ApplyBusy = new(1, 1);

    public static List<FixResult> Apply(IReadOnlyList<string> ids, AppSettings settings, Action<string, int, int> progress)
    {
        if (!ApplyBusy.Wait(0)) throw new InvalidOperationException("Fixes are already being applied. Wait for them to finish.");
        try { return ApplyCore(ids, settings, progress); }
        finally { ApplyBusy.Release(); }
    }

    static List<FixResult> ApplyCore(IReadOnlyList<string> ids, AppSettings settings, Action<string, int, int> progress)
    {
        List<(string id, Pending p)> chosen;
        lock (Gate)
        {
            // Each fix can be used once: it's taken off the list as soon as it's chosen, so a double-click can't run it twice.
            chosen = ids.Distinct().Where(pending.ContainsKey).Select(id => (id, pending[id])).ToList();
            if (chosen.Count > 30) throw new InvalidOperationException("That's more than 30 changes at once. Do the most important ones first, then scan again.");
            foreach (var c in chosen) pending.Remove(c.id);
        }
        if (chosen.Count == 0) throw new InvalidOperationException("Those fixes are no longer listed. Scan again.");

        // The offline scan restarts the PC, so it always goes last.
        chosen = chosen.OrderBy(c => c.p.Kind == "DefenderOffline" ? 1 : 0).ToList();
        var results = new List<FixResult>();

        if (chosen.Any(c => c.p.Risk == "caution"))
        {
            progress("Creating a restore point", 0, chosen.Count);
            var rp = DriverGuard.CreateFreshRestorePoint("SystemForge security fixes");
            if (!rp.Created && !settings.AdvancedDrivers)
            {
                lock (Gate) foreach (var c in chosen) pending[c.id] = c.p;
                throw new InvalidOperationException("Nothing was changed, because Windows couldn't make a restore point. Turn on System Protection (the Drivers page offers a button for it) and try again.");
            }
        }
        if (chosen.Any(c => c.p.Kind == "DefenderOffline") && !NativeConfirm.Ask("Restart into Microsoft Defender Offline?",
                "Your PC will restart after the other fixes and scan for about 15 minutes before Windows starts. Save your work first."))
        {
            chosen = chosen.Where(c => c.p.Kind != "DefenderOffline").ToList();
            results.Add(new FixResult("", "Microsoft Defender Offline", false, "Skipped: you chose not to restart."));
        }

        Downloader.EnsureSecureDataRoot();
        Directory.CreateDirectory(Root);
        for (int i = 0; i < chosen.Count; i++)
        {
            var (id, p) = chosen[i];
            progress(p.Label, i + 1, chosen.Count);
            try
            {
                string msg = Run(p, settings);
                results.Add(new FixResult(id, p.Label, true, msg));
            }
            catch (Exception ex)
            {
                results.Add(new FixResult(id, p.Label, false, ex.Message));
                lock (Gate) pending[id] = p; // failed: it can be tried again
            }
        }
        return results;
    }

    static string Run(Pending p, AppSettings settings)
    {
        var a = p.P;
        switch (p.Kind)
        {
            case "Quarantine": return Quarantine(a["paths"].Split('|', StringSplitOptions.RemoveEmptyEntries), p.Label);
            case "RemoveRegValue": return RemoveRegValue(a, p.Label);
            case "SetRegDword": return SetReg(a, p.Label, RegistryValueKind.DWord);
            case "SetRegString": return SetReg(a, p.Label, RegistryValueKind.String);
            case "DisableTask": return DisableTask(a["task"], p.Label);
            case "DisableService": return DisableService(a["service"], p.Label);
            case "RemoveWmi": return RemoveWmi(a["class"], a["name"], p.Label);
            case "CleanHosts": return CleanHosts(a["lines"].Split('\n'), p.Label);
            case "ClearProxy": return ClearProxy(p.Label);
            case "RemoveExclusion":
                Defender.ChangeExclusion(a["kind"], a["value"], add: false);
                Record("RemoveExclusion", p.Label, true, new() { ["kind"] = a["kind"], ["value"] = a["value"] });
                return "Removed.";
            case "DefenderPua":
                Defender.SetPuaProtection(true);
                Record("DefenderPua", p.Label, true, new());
                return "Turned on.";
            case "DefenderUpdate": return Defender.UpdateDefinitions();
            case "DefenderRemove": return Defender.RemoveThreats();
            case "DefenderOffline": return Defender.StartOfflineScan();
            case "Sfc": return RunSfc();
            case "Uninstall": return Uninstall(a, p.Label);
            case "OpenSettings": return OpenSettings(a.GetValueOrDefault("uri", ""), a.GetValueOrDefault("browser", ""));
            default: throw new InvalidOperationException("Unknown fix.");
        }
    }

    // ---- quarantine ----

    static string Quarantine(string[] paths, string label)
    {
        string entryId = NewEntryId();
        string dest = Path.Combine(QuarantineRoot, entryId);

        // Check every item first, so a problem with the third doesn't leave the first two half-done.
        var items = new List<(string path, bool isDir)>();
        foreach (var raw in paths)
        {
            string path = Normalize(raw) ?? throw new InvalidOperationException($"{raw} isn't a normal file path, so it wasn't moved.");
            if (!CanQuarantine(path)) throw new InvalidOperationException($"{path} is protected or already gone, so nothing was moved.");
            bool isDir = Directory.Exists(path);
            if (isDir)
            {
                if (!string.Equals(Path.GetPathRoot(path), Path.GetPathRoot(QuarantineRoot), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException($"{path} is on another drive. Move or delete it yourself.");
                CheckFolderSize(path);
            }
            else if (new FileInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
                throw new InvalidOperationException($"{path} is a link or a cloud file (e.g. OneDrive), so it wasn't moved.");
            items.Add((path, isDir));
        }

        var moved = new Dictionary<string, string>();
        try
        {
            int n = 0;
            foreach (var (path, isDir) in items)
            {
                EndProcessesIn(path, isDir);
                Directory.CreateDirectory(dest);
                string target = Path.Combine(dest, $"{n++}_{Path.GetFileName(path)}");
                if (isDir) Directory.Move(path, target);
                else
                {
                    var fi = new FileInfo(path);
                    if (fi.IsReadOnly) { fi.IsReadOnly = false; moved["ro:" + target] = "1"; }
                    File.Move(path, target);
                }
                moved[target] = path;
            }
        }
        finally
        {
            // Whatever did move is always recorded, so it can be put back even if a later item failed.
            if (moved.Keys.Any(k => !k.StartsWith("ro:"))) Record("Quarantine", label, true, moved, entryId);
        }
        int count = moved.Keys.Count(k => !k.StartsWith("ro:"));
        return count == 1 ? "Moved to quarantine." : $"Moved {count} items to quarantine.";
    }

    /// <summary>Refuses big folders and folders holding links or cloud-only files (moving those would delete them from OneDrive).</summary>
    static void CheckFolderSize(string path)
    {
        if (new DirectoryInfo(path).Attributes.HasFlag(FileAttributes.ReparsePoint))
            throw new InvalidOperationException($"{path} is a link or a cloud folder, so it wasn't moved.");
        long bytes = 0; int files = 0;
        var opts = new System.IO.EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = true, AttributesToSkip = 0 };
        var stack = new Stack<DirectoryInfo>();
        stack.Push(new DirectoryInfo(path));
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            foreach (var e in dir.EnumerateFileSystemInfos("*", opts))
            {
                if (e.Attributes.HasFlag(FileAttributes.ReparsePoint))
                    throw new InvalidOperationException($"{path} contains links or cloud-only files (e.g. OneDrive), so it wasn't moved. Uninstall it instead.");
                if (e is DirectoryInfo d) { stack.Push(d); continue; }
                bytes += ((FileInfo)e).Length;
                if (++files > 5000 || bytes > 2L << 30)
                    throw new InvalidOperationException($"{path} is too big to quarantine safely (over 5,000 files or 2 GB). Uninstall it instead.");
            }
        }
    }

    /// <summary>A plain, fully expanded local path, or null for device paths, network paths and the like.</summary>
    static string? Normalize(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw) || raw.StartsWith(@"\\") || raw.StartsWith(@"\??\") || !Path.IsPathFullyQualified(raw)) return null;
        try
        {
            string full = Path.GetFullPath(raw).TrimEnd('\\');
            if (full.Contains('~')) full = LongPath(full); // 8.3 short names (PROGRA~1) would dodge the folder checks
            return full;
        }
        catch { return null; }
    }

    static string LongPath(string p)
    {
        var sb = new System.Text.StringBuilder(1024);
        uint n = GetLongPathNameW(p, sb, (uint)sb.Capacity);
        return n > 0 && n < sb.Capacity ? sb.ToString() : p;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern uint GetLongPathNameW(string shortPath, System.Text.StringBuilder longPath, uint size);

    /// <summary>Ends programs running from what's about to be quarantined, except protected ones (which must be closed by hand).</summary>
    static void EndProcessesIn(string path, bool isDir)
    {
        var running = new List<Process>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string? exe = p.MainModule?.FileName;
                if (exe is null) { p.Dispose(); continue; }
                bool inside = isDir ? exe.StartsWith(path + "\\", StringComparison.OrdinalIgnoreCase) : exe.Equals(path, StringComparison.OrdinalIgnoreCase);
                if (inside) running.Add(p); else p.Dispose();
            }
            catch { p.Dispose(); }
        }
        try
        {
            if (running.Count > 8) throw new InvalidOperationException($"More than 8 programs are running from {path}. Close them yourself first.");
            var prot = running.FirstOrDefault(p => Protected.Contains(p.ProcessName.ToLowerInvariant()));
            if (prot is not null) throw new InvalidOperationException($"Close {prot.ProcessName} yourself first, then try again.");
            foreach (var p in running)
            {
                try { p.Kill(entireProcessTree: false); p.WaitForExit(5000); } catch { }
            }
        }
        finally { foreach (var p in running) p.Dispose(); }
    }

    // ---- registry ----

    /// <summary>Registry places the Security page may change. Anything else is refused even if asked.</summary>
    static bool AllowedKey(string key, string? name)
    {
        string k = key.ToUpperInvariant();
        string bare = System.Text.RegularExpressions.Regex.Replace(k, @"^S-1-5-21-[0-9-]+\\", "");
        string[] prefixes =
        {
            @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN", @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUNONCE",
            @"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\EXPLORER\RUN",
            @"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\IMAGE FILE EXECUTION OPTIONS\",
            @"SOFTWARE\POLICIES\GOOGLE\CHROME", @"SOFTWARE\POLICIES\MICROSOFT\EDGE", @"SOFTWARE\POLICIES\BRAVESOFTWARE\BRAVE", @"SOFTWARE\POLICIES\VIVALDI",
        };
        if (prefixes.Any(p => bare == p.TrimEnd('\\') || bare.StartsWith(p))) return true;
        var exact = new (string key, string name)[]
        {
            (@"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM", "ENABLELUA"),
            (@"SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\POLICIES\SYSTEM", "CONSENTPROMPTBEHAVIORADMIN"),
            (@"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON", "SHELL"),
            (@"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON", "USERINIT"),
            (@"SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS", "APPINIT_DLLS"),
        };
        if (exact.Any(e => e.key == bare && e.name == (name ?? "").ToUpperInvariant())) return true;
        return bare.StartsWith(@"SYSTEM\CURRENTCONTROLSET\SERVICES\SHAREDACCESS\PARAMETERS\FIREWALLPOLICY\") && (name ?? "").Equals("EnableFirewall", StringComparison.OrdinalIgnoreCase);
    }

    static RegistryKey OpenRoot(string hive, string? view) => RegistryKey.OpenBaseKey(
        hive switch { "HKLM" => RegistryHive.LocalMachine, "HKU" => RegistryHive.Users, "HKCU" => RegistryHive.CurrentUser, _ => throw new InvalidOperationException("Unknown registry hive.") },
        view == "32" ? RegistryView.Registry32 : RegistryView.Registry64);

    static string RemoveRegValue(Dictionary<string, string> a, string label)
    {
        string hive = a["hive"], key = a["key"], name = a["name"];
        string? view = a.GetValueOrDefault("view");
        if (!AllowedKey(key, name)) throw new InvalidOperationException("SystemForge doesn't change that part of the registry.");
        using var root = OpenRoot(hive, view);
        using var k = root.OpenSubKey(key, writable: true) ?? throw new InvalidOperationException("It's already gone.");
        var value = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) ?? throw new InvalidOperationException("It's already gone.");
        var kind = k.GetValueKind(name);
        // Saved first, so the history can always put it back.
        string entry = Record("RegValue", label, true, new()
        {
            ["hive"] = hive, ["view"] = view ?? "64", ["key"] = key, ["name"] = name, ["existed"] = "1",
            ["kind"] = kind.ToString(), ["data"] = Serialize(value, kind),
        });
        try { k.DeleteValue(name); }
        catch { Forget(entry); throw; }
        return "Removed.";
    }

    static string SetReg(Dictionary<string, string> a, string label, RegistryValueKind kind)
    {
        string hive = a["hive"], key = a["key"], name = a["name"], value = a["value"];
        string? view = a.GetValueOrDefault("view");
        if (!AllowedKey(key, name)) throw new InvalidOperationException("SystemForge doesn't change that part of the registry.");
        using var root = OpenRoot(hive, view);
        using var k = root.CreateSubKey(key, writable: true);
        var old = k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        var undo = new Dictionary<string, string> { ["hive"] = hive, ["view"] = view ?? "64", ["key"] = key, ["name"] = name, ["existed"] = old is null ? "0" : "1" };
        if (old is not null) { var oldKind = k.GetValueKind(name); undo["kind"] = oldKind.ToString(); undo["data"] = Serialize(old, oldKind); }
        string entry = Record("RegValue", label, true, undo);
        try
        {
            if (kind == RegistryValueKind.DWord) k.SetValue(name, int.Parse(value), RegistryValueKind.DWord);
            else k.SetValue(name, value, RegistryValueKind.String);
        }
        catch { Forget(entry); throw; }
        return name.Equals("EnableLUA", StringComparison.OrdinalIgnoreCase) ? "Done. Restart your PC for it to take effect." : "Done.";
    }

    static string Serialize(object value, RegistryValueKind kind) => value switch
    {
        byte[] bytes => Convert.ToBase64String(bytes),                          // Binary, None and unknown kinds
        string[] parts => parts.Length == 0 ? "" : "\u0001" + string.Join("\0", parts),
        _ => kind switch
        {
            RegistryValueKind.DWord or RegistryValueKind.QWord => Convert.ToString(value, System.Globalization.CultureInfo.InvariantCulture) ?? "0",
            _ => value.ToString() ?? "",
        },
    };

    static object Deserialize(string data, RegistryValueKind kind) => kind switch
    {
        RegistryValueKind.Binary or RegistryValueKind.None or RegistryValueKind.Unknown => Convert.FromBase64String(data),
        RegistryValueKind.MultiString => data.Length == 0 ? Array.Empty<string>() : data.TrimStart('\u0001').Split('\0'),
        RegistryValueKind.DWord => int.Parse(data, System.Globalization.CultureInfo.InvariantCulture),
        RegistryValueKind.QWord => long.Parse(data, System.Globalization.CultureInfo.InvariantCulture),
        _ => data,
    };

    // ---- tasks and services ----

    static string DisableTask(string taskPath, string label)
    {
        Sta.Run(() =>
        {
            dynamic svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
            svc.Connect();
            int cut = taskPath.LastIndexOf('\\');
            dynamic folder = svc.GetFolder(cut <= 0 ? "\\" : taskPath[..cut]);
            dynamic task = folder.GetTask(taskPath[(cut + 1)..]);
            // Windows' own tasks that run Windows' own programs are off limits.
            if (taskPath.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase))
            {
                foreach (dynamic act in task.Definition.Actions)
                {
                    if ((int)act.Type != 0) continue;
                    string cmd = $"\"{(string)(act.Path ?? "")}\" {(string)(act.Arguments ?? "")}";
                    var sig = FileTrust.Check(SecUtil.LaunchTarget(cmd).target);
                    // A task in Windows' folder that runs PowerShell with an encoded command is malware hiding there, not Windows.
                    if (sig.Trusted && sig.IsMicrosoft && !SecUtil.StrongCommand(cmd))
                        throw new InvalidOperationException("That's one of Windows' own tasks, so it was left alone.");
                }
            }
            task.Enabled = false;
            return 0;
        });
        Record("DisableTask", label, true, new() { ["task"] = taskPath });
        return "Turned off. It's still there and can be turned back on.";
    }

    static readonly HashSet<string> CriticalServices = new(StringComparer.OrdinalIgnoreCase)
    {
        "WinDefend", "WdNisSvc", "SecurityHealthService", "mpssvc", "BFE", "EventLog", "RpcSs", "DcomLaunch", "LSM", "SamSs", "Winmgmt",
        "wuauserv", "TrustedInstaller", "CryptSvc", "Dhcp", "Dnscache", "nsi", "PlugPlay", "Power", "ProfSvc", "Schedule", "AudioSrv",
    };

    static string DisableService(string name, string label)
    {
        if (CriticalServices.Contains(name)) throw new InvalidOperationException("That's a Windows service SystemForge never turns off.");
        using var s = new ManagementObject($"Win32_Service.Name='{name.Replace("'", "''")}'");
        s.Get();
        string pathName = s["PathName"]?.ToString() ?? "";
        var (target, _) = SecUtil.LaunchTarget(pathName);
        var sig = FileTrust.Check(target);
        if (sig.Trusted && sig.IsMicrosoft && !SecUtil.StrongCommand(pathName) &&
            !Path.GetFileName(target).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("That service is part of Windows, so it was left alone.");
        string oldMode = s["StartMode"]?.ToString() ?? "Manual";
        int delayed = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{name}")?.GetValue("DelayedAutostart") is int d ? d : 0;
        string entry = Record("DisableService", label, true, new() { ["service"] = name, ["mode"] = oldMode == "Auto" ? "Automatic" : oldMode, ["delayed"] = delayed.ToString() });
        var r = s.InvokeMethod("ChangeStartMode", new object[] { "Disabled" });
        if (Convert.ToUInt32(r) != 0) { Forget(entry); throw new InvalidOperationException($"Windows didn't allow the change (code {r})."); }
        try { s.InvokeMethod("StopService", null); } catch { }
        return "Stopped and turned off. It can be turned back on.";
    }

    // ---- WMI subscriptions ----

    static string RemoveWmi(string cls, string name, string label)
    {
        if (cls is not ("CommandLineEventConsumer" or "ActiveScriptEventConsumer")) throw new InvalidOperationException("Unknown WMI item.");
        var scope = new ManagementScope(@"root\subscription");
        scope.Connect();
        using var cs = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {cls} WHERE Name = '{Wql(name)}'"));
        var consumer = cs.Get().Cast<ManagementObject>().FirstOrDefault() ?? throw new InvalidOperationException("It's already gone.");
        string consumerPath = consumer.Path.RelativePath;
        var undo = new Dictionary<string, string> { ["class"] = cls };
        foreach (PropertyData pd in consumer.Properties)
            if (pd.Value is string or int or uint or bool) undo["c." + pd.Name] = Convert.ToString(pd.Value, System.Globalization.CultureInfo.InvariantCulture) ?? "";

        // Gather everything first and save it to the history, then delete.
        var bindings = new List<ManagementObject>();
        using (var bs = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding")))
            foreach (ManagementObject b in bs.Get())
                if (SameWmiPath(b["Consumer"]?.ToString(), consumerPath)) bindings.Add(b); else b.Dispose();
        var filters = new List<ManagementObject>();
        int i = 0;
        foreach (var fp in bindings.Select(b => b["Filter"]?.ToString() ?? "").Where(x => x.Length > 0).Distinct())
        {
            try
            {
                var f = new ManagementObject(scope, new ManagementPath(fp), null);
                f.Get();
                undo[$"f{i}.Name"] = f["Name"]?.ToString() ?? "";
                undo[$"f{i}.Query"] = f["Query"]?.ToString() ?? "";
                undo[$"f{i}.QueryLanguage"] = f["QueryLanguage"]?.ToString() ?? "WQL";
                undo[$"f{i}.EventNamespace"] = f["EventNamespace"]?.ToString() ?? @"root\cimv2";
                i++;
                filters.Add(f);
            }
            catch { }
        }
        undo["filters"] = i.ToString();
        Record("RemoveWmi", label, true, undo);

        foreach (var b in bindings) { try { b.Delete(); } catch { } b.Dispose(); }
        foreach (var f in filters)
        {
            // Only delete the filter if nothing else still uses it.
            using var others = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM __FilterToConsumerBinding"));
            if (!others.Get().Cast<ManagementObject>().Any(o => SameWmiPath(o["Filter"]?.ToString(), f.Path.RelativePath))) { try { f.Delete(); } catch { } }
            f.Dispose();
        }
        consumer.Delete();
        consumer.Dispose();
        return "Removed.";
    }

    /// <summary>WQL string escaping: backslash and quote are escaped with a backslash.</summary>
    static string Wql(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'");

    static bool SameWmiPath(string? a, string b) =>
        a is not null && (a.EndsWith(b, StringComparison.OrdinalIgnoreCase) || b.EndsWith(a, StringComparison.OrdinalIgnoreCase));

    // ---- network ----

    static string HostsPath => Path.Combine(SecUtil.System32, @"drivers\etc\hosts");

    static string CleanHosts(string[] lines, string label)
    {
        var remove = new HashSet<string>(lines.Select(Norm).Where(l => l.Length > 0));
        string original = File.ReadAllText(HostsPath);
        var kept = original.Replace("\r\n", "\n").Split('\n').Where(l => !remove.Contains(Norm(System.Text.RegularExpressions.Regex.Replace(l, "#.*$", "")))).ToList();
        string entryId = NewEntryId();
        string backup = Path.Combine(QuarantineRoot, entryId, "hosts.backup");
        Directory.CreateDirectory(Path.GetDirectoryName(backup)!);
        File.WriteAllText(backup, original);
        var fi = new FileInfo(HostsPath);
        if (fi.IsReadOnly) fi.IsReadOnly = false;
        File.WriteAllText(HostsPath, string.Join("\r\n", kept));
        Record("Hosts", label, true, new() { ["backup"] = backup }, entryId);
        return "Removed. The old file is saved and can be put back.";

        static string Norm(string l) => System.Text.RegularExpressions.Regex.Replace(l.Trim(), @"\s+", " ").ToLowerInvariant();
    }

    const string Inet = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    static string ClearProxy(string label)
    {
        using var k = Registry.CurrentUser.OpenSubKey(Inet, writable: true) ?? throw new InvalidOperationException("No proxy settings found.");
        var undo = new Dictionary<string, string>
        {
            ["ProxyEnable"] = k.GetValue("ProxyEnable") is int e ? e.ToString() : "",
            ["ProxyServer"] = k.GetValue("ProxyServer") as string ?? "",
            ["AutoConfigURL"] = k.GetValue("AutoConfigURL") as string ?? "",
        };
        k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
        k.DeleteValue("AutoConfigURL", throwOnMissingValue: false);
        Record("Proxy", label, true, undo);
        return "Proxy turned off. Restart your browser.";
    }

    // ---- tools ----

    static string RunSfc()
    {
        var psi = new ProcessStartInfo(Path.Combine(SecUtil.System32, "sfc.exe"), "/scannow") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true };
        using var p = Process.Start(psi)!;
        p.OutputDataReceived += (_, _) => { };
        p.BeginOutputReadLine();
        if (!p.WaitForExit(TimeSpan.FromMinutes(40))) { try { p.Kill(); } catch { } throw new TimeoutException("System File Checker took too long."); }
        return p.ExitCode == 0 ? "System File Checker finished. Restart your PC." : $"System File Checker finished with code {p.ExitCode}. Restart and scan again.";
    }

    static string Uninstall(Dictionary<string, string> a, string label)
    {
        // Read the uninstall command from the registry now, rather than trusting anything passed in.
        string key = a["key"];
        if (!key.StartsWith(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("That isn't an installed program.");
        using var root = OpenRoot(a["hive"], a.GetValueOrDefault("view"));
        using var k = root.OpenSubKey(key) ?? throw new InvalidOperationException("It's already uninstalled.");
        string cmd = k.GetValue("QuietUninstallString") as string ?? k.GetValue("UninstallString") as string ?? throw new InvalidOperationException("It has no uninstaller. Use Installed apps.");
        cmd = Environment.ExpandEnvironmentVariables(cmd);

        ProcessStartInfo psi;
        var msi = System.Text.RegularExpressions.Regex.Match(cmd, @"(?i)msiexec(\.exe)?\s+/[IX]\s*(\{[0-9A-F-]{36}\})");
        if (msi.Success) psi = new ProcessStartInfo(Path.Combine(SecUtil.System32, "msiexec.exe"), $"/x {msi.Groups[2].Value} /qb /norestart");
        else
        {
            var (exe, args) = SplitCommand(cmd);
            if (!File.Exists(exe)) throw new InvalidOperationException("Its uninstaller is missing. Quarantine its folders instead.");
            if (!exe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Its uninstaller isn't a normal program. Use Installed apps instead.");
            psi = new ProcessStartInfo(exe, args);
        }
        psi.UseShellExecute = false;
        using var p = Process.Start(psi)!;
        if (!p.WaitForExit(TimeSpan.FromMinutes(15))) throw new TimeoutException("The uninstaller is still open. Finish it, then scan again.");
        Record("Uninstall", label, false, new());
        return p.ExitCode is 0 or 3010 or 1641 ? "Uninstalled. Scan again to catch leftovers." : $"The uninstaller closed with code {p.ExitCode}. Scan again to check.";
    }

    /// <summary>First token (or quoted path) and the rest, exactly as the uninstall command was written.</summary>
    static (string exe, string args) SplitCommand(string cmd)
    {
        cmd = cmd.Trim();
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            return end > 0 ? (cmd[1..end], cmd[(end + 1)..].Trim()) : (cmd.Trim('"'), "");
        }
        int exeEnd = cmd.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        if (exeEnd > 0) return (cmd[..(exeEnd + 4)], cmd[(exeEnd + 4)..].Trim());
        int sp = cmd.IndexOf(' ');
        return sp > 0 ? (cmd[..sp], cmd[(sp + 1)..]) : (cmd, "");
    }

    static string OpenSettings(string uri, string browser)
    {
        if (uri.StartsWith("ms-settings:") || uri.StartsWith("windowsdefender:") || uri.StartsWith("microsoft-edge:"))
        {
            Process.Start(new ProcessStartInfo(uri) { UseShellExecute = true });
            return "Opened.";
        }
        if (browser.Length > 0)
            return $"Open {browser}, type {browser.ToLowerInvariant() switch { "brave" => "brave", "vivaldi" => "vivaldi", _ => "chrome" }}://extensions in the address bar and remove it there.";
        throw new InvalidOperationException("Nothing to open.");
    }

    // ---- journal and undo ----

    static string NewEntryId() => $"{DateTime.Now:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..6]}";

    static string Record(string kind, string label, bool canUndo, Dictionary<string, string> undo, string? id = null)
    {
        lock (Gate)
        {
            var list = LoadJournal(strict: true);
            string entryId = id ?? NewEntryId();
            list.Add(new JournalEntry { Id = entryId, When = DateTime.Now, Kind = kind, Label = label, Undo = undo, CanUndo = canUndo });
            SaveJournal(list);
            return entryId;
        }
    }

    /// <summary>Drops an entry recorded just before a change that then failed.</summary>
    static void Forget(string id)
    {
        lock (Gate)
        {
            var list = LoadJournal(strict: true);
            list.RemoveAll(e => e.Id == id);
            SaveJournal(list);
        }
    }

    static readonly JsonSerializerOptions JournalJson = new() { WriteIndented = true };

    /// <summary>Written to a temporary file and then swapped in, so a crash can't leave half a journal.</summary>
    static void SaveJournal(List<JournalEntry> list)
    {
        Downloader.EnsureSecureDataRoot();
        Directory.CreateDirectory(Root);
        string tmp = JournalFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(list, JournalJson));
        File.Move(tmp, JournalFile, overwrite: true);
    }

    /// <summary>
    /// A damaged journal is set aside, never silently replaced: with <paramref name="strict"/> it stops further changes,
    /// because they couldn't be undone.
    /// </summary>
    static List<JournalEntry> LoadJournal(bool strict)
    {
        if (!File.Exists(JournalFile)) return new();
        try { return JsonSerializer.Deserialize<List<JournalEntry>>(File.ReadAllText(JournalFile)) ?? new(); }
        catch
        {
            string aside = Path.Combine(Root, $"journal.damaged-{DateTime.Now:yyyyMMdd-HHmmss}.json");
            try { File.Move(JournalFile, aside); } catch { }
            if (strict) throw new InvalidOperationException($"SystemForge's change history was damaged and has been set aside ({aside}). Nothing was changed. Try again.");
            return new();
        }
    }

    public static List<JournalEntry> Journal() { lock (Gate) return LoadJournal(strict: false); }

    public static string UndoEntry(string id)
    {
        lock (Gate)
        {
            var list = LoadJournal(strict: true);
            var e = list.FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("That change isn't in the history.");
            if (!e.CanUndo) throw new InvalidOperationException("That change can't be undone automatically.");
            if (e.Undone) throw new InvalidOperationException("It's already been undone.");
            var u = e.Undo;
            switch (e.Kind)
            {
                case "Quarantine":
                    foreach (var (from, to) in u.Where(x => !x.Key.StartsWith("ro:")))
                    {
                        bool inQuarantine = Directory.Exists(from) || File.Exists(from);
                        bool atHome = Directory.Exists(to) || File.Exists(to);
                        if (!inQuarantine && atHome) continue; // already put back by an earlier, interrupted undo
                        if (!inQuarantine) throw new InvalidOperationException($"The quarantined copy of {Path.GetFileName(to)} is missing.");
                        if (atHome) throw new InvalidOperationException($"Something new is already at {to}. Move it first.");
                        Directory.CreateDirectory(Path.GetDirectoryName(to)!);
                        if (Directory.Exists(from)) Directory.Move(from, to); else File.Move(from, to);
                        ResetPermissions(to);
                        if (u.ContainsKey("ro:" + from) && File.Exists(to)) new FileInfo(to).IsReadOnly = true;
                    }
                    break;
                case "RegValue":
                    {
                        using var root = OpenRoot(u["hive"], u.GetValueOrDefault("view"));
                        using var k = root.CreateSubKey(u["key"], writable: true);
                        if (u["existed"] == "1")
                        {
                            var kind = Enum.Parse<RegistryValueKind>(u["kind"]);
                            k.SetValue(u["name"], Deserialize(u["data"], kind), kind);
                        }
                        else k.DeleteValue(u["name"], throwOnMissingValue: false);
                    }
                    break;
                case "DisableTask":
                    Sta.Run(() =>
                    {
                        dynamic svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
                        svc.Connect();
                        string t = u["task"];
                        int cut = t.LastIndexOf('\\');
                        dynamic task = svc.GetFolder(cut <= 0 ? "\\" : t[..cut]).GetTask(t[(cut + 1)..]);
                        task.Enabled = true;
                        return 0;
                    });
                    break;
                case "DisableService":
                    {
                        using var s = new ManagementObject($"Win32_Service.Name='{u["service"].Replace("'", "''")}'");
                        s.Get();
                        var rc = s.InvokeMethod("ChangeStartMode", new object[] { u["mode"] });
                        if (Convert.ToUInt32(rc) != 0) throw new InvalidOperationException($"Windows didn't allow turning it back on (code {rc}).");
                        if (u.GetValueOrDefault("delayed") == "1")
                            using (var k = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\{u["service"]}", writable: true))
                                k?.SetValue("DelayedAutostart", 1, RegistryValueKind.DWord);
                        if (u["mode"] == "Automatic") { try { s.InvokeMethod("StartService", null); } catch { } }
                    }
                    break;
                case "RemoveWmi":
                    RestoreWmi(u);
                    break;
                case "Hosts":
                    {
                        var fi = new FileInfo(HostsPath);
                        if (fi.Exists && fi.IsReadOnly) fi.IsReadOnly = false;
                        File.WriteAllText(HostsPath, File.ReadAllText(u["backup"]));
                    }
                    break;
                case "Proxy":
                    {
                        using var k = Registry.CurrentUser.CreateSubKey(Inet, writable: true);
                        if (u["ProxyEnable"].Length > 0) k.SetValue("ProxyEnable", int.Parse(u["ProxyEnable"]), RegistryValueKind.DWord);
                        else k.DeleteValue("ProxyEnable", throwOnMissingValue: false);
                        if (u["ProxyServer"].Length > 0) k.SetValue("ProxyServer", u["ProxyServer"]);
                        if (u["AutoConfigURL"].Length > 0) k.SetValue("AutoConfigURL", u["AutoConfigURL"]);
                    }
                    break;
                case "RemoveExclusion":
                    Defender.ChangeExclusion(u["kind"], u["value"], add: true);
                    break;
                case "DefenderPua":
                    Defender.SetPuaProtection(false);
                    break;
                default:
                    throw new InvalidOperationException("That change can't be undone automatically.");
            }
            e.Undone = true;
            SaveJournal(list);
            return "Put back.";
        }
    }

    /// <summary>
    /// Quarantine is admin-only, and moved items keep those permissions. Put back in a user's folder, they'd be locked
    /// to that user; resetting makes them inherit the folder's normal permissions again.
    /// </summary>
    static void ResetPermissions(string path)
    {
        try
        {
            var psi = new ProcessStartInfo(Path.Combine(SecUtil.System32, "icacls.exe")) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { path, "/reset", "/T", "/C", "/Q" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            p.WaitForExit(60_000);
        }
        catch { /* best effort: the files are back either way */ }
    }

    static void RestoreWmi(Dictionary<string, string> u)
    {
        var scope = new ManagementScope(@"root\subscription");
        scope.Connect();
        using var consumerClass = new ManagementClass(scope, new ManagementPath(u["class"]), null);
        using var consumer = consumerClass.CreateInstance();
        foreach (var (k, v) in u.Where(x => x.Key.StartsWith("c.")))
        {
            string prop = k[2..];
            try
            {
                var pd = consumer.Properties[prop];
                consumer[prop] = pd.Type switch
                {
                    CimType.Boolean => bool.Parse(v),
                    CimType.UInt32 => uint.Parse(v),
                    CimType.SInt32 => int.Parse(v),
                    _ => v,
                };
            }
            catch { /* read-only or system property */ }
        }
        var consumerPath = consumer.Put();
        int n = int.Parse(u.GetValueOrDefault("filters", "0"));
        for (int i = 0; i < n; i++)
        {
            using var filterClass = new ManagementClass(scope, new ManagementPath("__EventFilter"), null);
            using var filter = filterClass.CreateInstance();
            filter["Name"] = u[$"f{i}.Name"];
            filter["Query"] = u[$"f{i}.Query"];
            filter["QueryLanguage"] = u[$"f{i}.QueryLanguage"];
            filter["EventNamespace"] = u[$"f{i}.EventNamespace"];
            var filterPath = filter.Put();
            using var bindClass = new ManagementClass(scope, new ManagementPath("__FilterToConsumerBinding"), null);
            using var bind = bindClass.CreateInstance();
            bind["Filter"] = filterPath.RelativePath;
            bind["Consumer"] = consumerPath.RelativePath;
            bind.Put();
        }
    }

    /// <summary>Permanently deletes what's in quarantine for one journal entry (the user's choice, after checking nothing broke).</summary>
    public static string DeleteQuarantined(string id)
    {
        lock (Gate)
        {
            var list = LoadJournal(strict: true);
            var e = list.FirstOrDefault(x => x.Id == id && x.Kind == "Quarantine") ?? throw new InvalidOperationException("Nothing in quarantine for that.");
            string dir = Path.Combine(QuarantineRoot, e.Id);
            if (Directory.Exists(dir) && Path.GetFullPath(dir).StartsWith(QuarantineRoot + "\\", StringComparison.OrdinalIgnoreCase)) Directory.Delete(dir, true);
            e.CanUndo = false;
            e.Label += " (deleted for good)";
            SaveJournal(list);
            return "Deleted for good.";
        }
    }
}
