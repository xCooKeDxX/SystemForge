using System.Diagnostics;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SystemForge;

/// <summary>
/// SystemForge's own security checks: everything that starts automatically, browser hijacks, network tampering,
/// suspicious recent files, login-screen backdoors, remote-access tools and Windows' security settings.
/// The scan only reads. Fixes are separate actions (see <see cref="SecurityFixes"/>) the user picks.
/// Inspired by PC Health Scan by TCPeep (https://github.com/TCPeep/PC-Health-Scan).
/// </summary>
public sealed class SecurityScanner
{
    readonly AppSettings settings;
    readonly Action<string, int> progress;
    readonly List<SecFinding> findings = new();
    readonly List<AutorunItem> autoruns = new();
    readonly List<string> passed = new();
    readonly List<string> notes = new();
    readonly HashSet<string> trusted;
    int filesChecked;
    int nextId;

    public SecurityScanner(AppSettings settings, Action<string, int> progress)
    {
        this.settings = settings;
        this.progress = progress;
        trusted = new HashSet<string>(settings.SecurityTrusted, StringComparer.OrdinalIgnoreCase);
    }

    public SecScan Run(DefenderStatus defender, List<DefenderThreat> threats)
    {
        var sw = Stopwatch.StartNew();
        FileTrust.ClearCache();
        SecurityFixes.BeginScan();
        var steps = new (string label, Action run)[]
        {
            ("Checking Microsoft Defender", () => CheckDefender(defender, threats)),
            ("Checking Windows security settings", CheckSettings),
            ("Checking startup entries", CheckRunKeys),
            ("Checking startup folders", CheckStartupFolders),
            ("Checking scheduled tasks", CheckTasks),
            ("Checking services and drivers", CheckServices),
            ("Checking hidden auto-start tricks", CheckDeepPersistence),
            ("Checking installed programs", CheckInstalledPrograms),
            ("Checking for leftover adware folders", CheckAdwareFolders),
            ("Checking browsers", CheckBrowsers),
            ("Checking network settings", CheckNetwork),
            ("Checking login-screen tools", CheckAccessibilityBackdoor),
            ("Checking remote-access tools", CheckRemoteAccess),
            ("Checking recent downloads and files", CheckRecentFiles),
        };
        for (int i = 0; i < steps.Length; i++)
        {
            progress(steps[i].label, (int)(i * 100.0 / steps.Length));
            try { steps[i].run(); }
            catch (Exception ex) { notes.Add($"{steps[i].label} didn't finish: {ex.Message}"); }
        }
        SummarizeAutoruns();
        progress("Done", 100);

        var ordered = findings
            .OrderByDescending(f => SecUtil.Rank(f.Severity))
            .ThenBy(f => f.Category)
            .ToList();
        return new SecScan(ordered, autoruns.OrderByDescending(a => SecUtil.Rank(a.Severity)).ThenBy(a => a.Type).ThenBy(a => a.Name).ToList(),
            passed, DateTime.Now, filesChecked, Math.Round(sw.Elapsed.TotalSeconds, 1), notes);
    }

    // ---- helpers ----

    string NewId() => $"f{++nextId}";

    void Add(string severity, string category, string title, string detail, string why, string fix,
        IEnumerable<string>? evidence = null, IEnumerable<SecAction>? actions = null, string? trustKey = null)
    {
        if (trustKey is not null && trusted.Contains(trustKey)) return;
        findings.Add(new SecFinding(NewId(), severity, category, title, detail, why, fix,
            (evidence ?? Array.Empty<string>()).ToList(), (actions ?? Array.Empty<SecAction>()).ToList(), trustKey));
    }

    void Pass(string text) => passed.Add(text);

    static object? Reg(RegistryHive hive, RegistryView view, string key, string name)
    {
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, view);
            using var k = root.OpenSubKey(key);
            return k?.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
        }
        catch { return null; }
    }

    static int RegInt(RegistryHive hive, string key, string name, int fallback) =>
        Reg(hive, RegistryView.Registry64, key, name) is int i ? i : fallback;

    /// <summary>Records an auto-start item and, if it's concerning and not trusted, a finding with fixes.</summary>
    void Autorun(string type, string location, string name, string command, Func<SecAction>? disable, string? extraWhy = null, string? forceSeverity = null, string? forceReason = null)
    {
        var (target, sig, zone, sev, reasons, adware) = SecUtil.RateLaunch(command, name);
        // SystemForge itself (its "Start with Windows" task): listed honestly, but not raised as a suspicious finding.
        if (target.Length > 0 && Path.GetFullPath(target).Equals(Path.Combine(AppContext.BaseDirectory, "SystemForge.exe"), StringComparison.OrdinalIgnoreCase))
        {
            bool exposed = SecUtil.UserWritable(zone);
            autoruns.Add(new AutorunItem(type, location, name, command, target, sig.Signer, sig.Trusted, zone, exposed ? "Low" : "",
                exposed ? $"This is SystemForge. It runs from {zone}, which other programs can change; installing SystemForge in Program Files fixes that." : "This is SystemForge.", false));
            return;
        }
        if (forceSeverity is not null) { sev = SecUtil.Max(sev, forceSeverity); if (forceReason is not null) reasons.Insert(0, forceReason); }
        string key = "path:" + (target.Length > 0 ? target : command);
        bool userTrusted = trusted.Contains(key);
        autoruns.Add(new AutorunItem(type, location, name, command, target, sig.Signer, sig.Trusted, zone,
            userTrusted ? "" : sev, userTrusted ? "Trusted by you" : string.Join("; ", reasons), userTrusted));
        if (userTrusted || SecUtil.Rank(sev) < 2) return;

        var actions = new List<SecAction>();
        bool sure = SecUtil.Rank(sev) >= 3 && (adware is null || adware.Severity == "High");
        if (disable is not null) actions.Add(disable() with { Recommended = sure });
        if (sig.Exists && target.Length > 0 && SecurityFixes.CanQuarantine(target))
            actions.Add(SecurityFixes.Plan("Quarantine", $"Move {Path.GetFileName(target)} to quarantine", "caution", sure && adware is not null,
                new() { ["paths"] = target }));
        Add(sev, adware is not null ? "Adware" : "Auto-start", adware is not null ? $"{adware.Name} starts with Windows" : $"Suspicious {type.ToLowerInvariant()}: {name}",
            string.Join("; ", reasons),
            adware?.About ?? extraWhy ?? "Malware almost always sets itself to start automatically. Most of these are harmless programs, so check whether you recognise it.",
            adware is not null ? "Turn it off and move its files to quarantine, then uninstall it from Installed apps." : "If you don't recognise it, turn it off. If you do, choose \"Trust it\" and it won't be flagged again.",
            new[] { $"{type} ({location}): {name}", $"Runs: {command}", $"Signed by: {(sig.Trusted ? sig.Signer : sig.Status)}" },
            actions, key);
    }

    void SummarizeAutoruns()
    {
        int low = autoruns.Count(a => a.Severity == "Low");
        if (low > 0)
            notes.Add($"{low} startup item{(low == 1 ? " is" : "s are")} unsigned or point to missing files but didn't look harmful. They're listed under Startup & tasks.");
        if (!findings.Any(f => f.Category == "Auto-start" || f.Category == "Adware"))
            Pass($"Nothing suspicious among {autoruns.Count} things that start automatically");
    }

    // ---- Defender and settings ----

    void CheckDefender(DefenderStatus d, List<DefenderThreat> threats)
    {
        bool otherAv = d.OtherAntivirus.Any(a => a.Enabled);
        if (!d.Available || d.Mode is "Not running")
        {
            if (otherAv) Pass($"{d.OtherAntivirus.First(a => a.Enabled).Name} is protecting this PC");
            else Add("Critical", "Protection", "No antivirus is running", d.Message,
                "Without an antivirus nothing stops malware as it arrives. Windows comes with Microsoft Defender, which is free and rated among the best.",
                "Open Windows Security → Virus & threat protection and turn it on. If it's missing, a \"debloat\" tool may have removed it.");
            return;
        }
        if (!d.RealTime && !otherAv)
            Add("Critical", "Protection", "Defender's real-time protection is off", "", "Malware can run without being stopped.",
                "Turn on Real-time protection in Windows Security → Virus & threat protection settings. If it keeps turning off, something is disabling it, which is itself a warning sign.",
                actions: new[] { SecurityFixes.Plan("OpenSettings", "Open Virus & threat protection settings", "guided", true, new() { ["uri"] = "windowsdefender://threatsettings" }) });
        else if (d.RealTime) Pass("Defender's real-time protection is on");

        if (d.DefinitionAgeDays > 7)
            Add("Medium", "Protection", $"Virus definitions are {d.DefinitionAgeDays} days old", "", "New malware appears daily, and old definitions miss it.", "Update them now.",
                actions: new[] { SecurityFixes.Plan("DefenderUpdate", "Update Defender's virus definitions", "safe", true, new()) });

        if (!d.Tamper)
            Add("Low", "Protection", "Tamper Protection is off", "", "Tamper Protection stops malware from turning Defender off.",
                "Turn it on in Windows Security → Virus & threat protection settings.",
                actions: new[] { SecurityFixes.Plan("OpenSettings", "Open Virus & threat protection settings", "guided", false, new() { ["uri"] = "windowsdefender://threatsettings" }) });

        if (d.PuaProtection != 1)
            Add("Low", "Protection", "Blocking of unwanted apps is off", "", "Defender can block adware and bundleware (\"potentially unwanted apps\") before it installs, but this is off by default.",
                "Turn it on.", actions: new[] { SecurityFixes.Plan("DefenderPua", "Turn on Defender's blocking of unwanted apps", "safe", true, new()) });

        if (d.Exclusions.Count > 0)
        {
            var risky = d.Exclusions.Where(e => Regex.IsMatch(e, @"(?i)(:\s*[a-z]:\\?$|\\users\\|appdata|\\temp|\\downloads|\\desktop|programdata|\\public|\.exe$|: exe$|: dll$|: ps1$|: bat$)")).ToList();
            var actions = d.Exclusions.Select(e =>
            {
                var (kind, value) = SplitExclusion(e);
                return SecurityFixes.Plan("RemoveExclusion", $"Remove exclusion: {e}", "safe", risky.Contains(e), new() { ["kind"] = kind, ["value"] = value });
            }).ToList();
            Add(risky.Count > 0 ? "High" : "Medium", "Protection", $"Defender skips {d.Exclusions.Count} location{(d.Exclusions.Count == 1 ? "" : "s")}", "",
                "Exclusions tell Defender not to scan something. Malware often adds one for itself; some games and developer tools add them legitimately.",
                "Remove any you didn't add on purpose.", d.Exclusions, actions);
        }

        var active = threats.Where(t => t.Active).ToList();
        if (active.Count > 0)
            Add("High", "Protection", $"Defender found {active.Count} active threat{(active.Count == 1 ? "" : "s")}", string.Join(", ", active.Select(t => t.Name).Take(5)),
                "Defender detected these and they haven't been cleaned up yet.", "Have Defender remove them, then run a full scan.",
                active.SelectMany(t => t.Resources.Take(3).Select(r => $"{t.Name}: {r}")),
                new[] { SecurityFixes.Plan("DefenderRemove", "Have Defender remove the threats", "caution", true, new()) });
        else Pass("Defender has no active threats");
    }

    static (string kind, string value) SplitExclusion(string e)
    {
        int i = e.IndexOf(": ", StringComparison.Ordinal);
        string label = i > 0 ? e[..i] : "";
        string v = i > 0 ? e[(i + 2)..] : e;
        return (label switch { "Program" => "ExclusionProcess", "File type" => "ExclusionExtension", _ => "ExclusionPath" }, v);
    }

    void CheckSettings()
    {
        const string sys = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
        if (RegInt(RegistryHive.LocalMachine, sys, "EnableLUA", 1) == 0)
            Add("High", "Windows settings", "User Account Control is turned off", "",
                "Without UAC every program runs with full admin rights, so anything you run can change the whole PC.",
                "Turn it back on. Windows needs a restart afterwards.",
                actions: new[] { SecurityFixes.Plan("SetRegDword", "Turn User Account Control back on (needs a restart)", "safe", true,
                    new() { ["hive"] = "HKLM", ["key"] = sys, ["name"] = "EnableLUA", ["value"] = "1" }) });
        else if (RegInt(RegistryHive.LocalMachine, sys, "ConsentPromptBehaviorAdmin", 5) == 0)
            Add("Medium", "Windows settings", "User Account Control never asks", "",
                "Programs get admin rights silently, so you never see when something changes the system.",
                "Set it back to the default.",
                actions: new[] { SecurityFixes.Plan("SetRegDword", "Set User Account Control back to Windows' default", "safe", true,
                    new() { ["hive"] = "HKLM", ["key"] = sys, ["name"] = "ConsentPromptBehaviorAdmin", ["value"] = "5" }) });
        else Pass("User Account Control is on");

        const string fw = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\";
        var off = new[] { ("DomainProfile", "work networks"), ("StandardProfile", "private networks"), ("PublicProfile", "public networks") }
            .Where(p => RegInt(RegistryHive.LocalMachine, fw + p.Item1, "EnableFirewall", 1) == 0).ToList();
        if (off.Count > 0)
            Add(off.Any(o => o.Item1 == "PublicProfile") ? "High" : "Medium", "Windows settings", $"Windows Firewall is off for {string.Join(" and ", off.Select(o => o.Item2))}", "",
                "The firewall blocks other devices from connecting into your PC. On public Wi-Fi that matters most.",
                "Turn it back on, unless another security suite provides its own firewall.",
                actions: off.Select(o => SecurityFixes.Plan("SetRegDword", $"Turn the firewall back on for {o.Item2}", "safe", true,
                    new() { ["hive"] = "HKLM", ["key"] = fw + o.Item1, ["name"] = "EnableFirewall", ["value"] = "1" })).ToList());
        else Pass("Windows Firewall is on");

        if (RegInt(RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1) == 0 ||
            string.Equals(Reg(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string, "Off", StringComparison.OrdinalIgnoreCase))
            Add("Medium", "Windows settings", "SmartScreen is turned off", "",
                "SmartScreen warns before you run downloads that are new or known to be bad.",
                "Turn it on in Windows Security → App & browser control.",
                actions: new[] { SecurityFixes.Plan("OpenSettings", "Open App & browser control", "guided", true, new() { ["uri"] = "windowsdefender://appbrowser" }) });
    }

    // ---- things that start automatically ----

    static readonly string[] RunKeys =
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    };

    void CheckRunKeys()
    {
        var places = new List<(RegistryHive hive, RegistryView view, string prefix, string label)>
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, "", "all users"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, "", "all users, 32-bit"),
        };
        // Every signed-in user's own hive (HKEY_USERS\S-1-5-21-…).
        try
        {
            using var users = RegistryKey.OpenBaseKey(RegistryHive.Users, RegistryView.Registry64);
            foreach (var sid in users.GetSubKeyNames().Where(n => n.StartsWith("S-1-5-21-") && !n.EndsWith("_Classes")))
                places.Add((RegistryHive.Users, RegistryView.Registry64, sid + "\\", AccountName(sid)));
        }
        catch { }

        foreach (var (hive, view, prefix, label) in places)
        {
            foreach (var keyPath in RunKeys)
            {
                string full = prefix + keyPath;
                try
                {
                    using var root = RegistryKey.OpenBaseKey(hive, view);
                    using var k = root.OpenSubKey(full);
                    if (k is null) continue;
                    foreach (var name in k.GetValueNames())
                    {
                        if (k.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames) is not string cmd || cmd.Length == 0) continue;
                        string where = $"{(hive == RegistryHive.LocalMachine ? "HKLM" : "HKU")}\\{full} ({label})";
                        var h = hive; var v = view;
                        Autorun("Startup entry", where, name.Length > 0 ? name : "(default)", cmd,
                            () => SecurityFixes.Plan("RemoveRegValue", $"Remove the startup entry \"{name}\"", "caution", false,
                                new() { ["hive"] = h == RegistryHive.LocalMachine ? "HKLM" : "HKU", ["view"] = v == RegistryView.Registry32 ? "32" : "64", ["key"] = full, ["name"] = name }));
                    }
                }
                catch { }
            }
        }
    }

    static string AccountName(string sid)
    {
        try { return new System.Security.Principal.SecurityIdentifier(sid).Translate(typeof(System.Security.Principal.NTAccount)).Value; }
        catch { return sid; }
    }

    void CheckStartupFolders()
    {
        var folders = new List<string> { Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) };
        foreach (var p in SecUtil.Profiles())
            folders.Add(Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"));

        var shortcuts = new List<(string folder, string file)>();
        foreach (var f in folders.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var file in Directory.EnumerateFiles(f))
                    if (!Path.GetFileName(file).Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) shortcuts.Add((f, file));
            }
            catch { }
        }
        var resolved = Sta.Run(() => shortcuts.Select(s => (s.folder, s.file, cmd: ResolveShortcut(s.file))).ToList());
        foreach (var (folder, file, cmd) in resolved)
        {
            string path = file;
            Autorun("Startup folder", folder, Path.GetFileName(file), cmd,
                () => SecurityFixes.Plan("Quarantine", $"Move the shortcut {Path.GetFileName(path)} to quarantine", "caution", false, new() { ["paths"] = path }));
        }
    }

    /// <summary>"target args" for a .lnk; the file itself for anything else. Call on an STA thread.</summary>
    static string ResolveShortcut(string file)
    {
        if (!file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase)) return file;
        try
        {
            dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
            dynamic lnk = shell.CreateShortcut(file);
            string target = lnk.TargetPath ?? "";
            string args = lnk.Arguments ?? "";
            return target.Length == 0 ? file : (target.Contains(' ') ? $"\"{target}\"" : target) + (args.Length > 0 ? " " + args : "");
        }
        catch { return file; }
    }

    void CheckTasks()
    {
        var tasks = Sta.Run(() =>
        {
            var list = new List<(string path, string cmd, bool hidden, bool enabled, string runLevel, string author)>();
            dynamic svc = Activator.CreateInstance(Type.GetTypeFromProgID("Schedule.Service")!)!;
            svc.Connect();
            void Walk(dynamic folder)
            {
                try
                {
                    foreach (dynamic t in folder.GetTasks(1 /* include hidden */))
                    {
                        try
                        {
                            dynamic def = t.Definition;
                            foreach (dynamic a in def.Actions)
                            {
                                if ((int)a.Type != 0) continue; // only "start a program"
                                string exe = a.Path ?? "";
                                string args = a.Arguments ?? "";
                                string cmd = (exe.Contains(' ') && !exe.StartsWith('"') ? $"\"{exe}\"" : exe) + (args.Length > 0 ? " " + args : "");
                                list.Add(((string)t.Path, cmd, (bool)def.Settings.Hidden, (bool)t.Enabled,
                                    (int)def.Principal.RunLevel == 1 ? "highest" : "normal", (string)(def.RegistrationInfo.Author ?? "")));
                            }
                        }
                        catch { }
                    }
                    foreach (dynamic sub in folder.GetFolders(0)) Walk(sub);
                }
                catch { }
            }
            Walk(svc.GetFolder("\\"));
            return list;
        });

        foreach (var t in tasks.Where(t => t.enabled))
        {
            var (target, _) = SecUtil.LaunchTarget(t.cmd);
            var sig = FileTrust.Check(target);
            // Windows' own tasks running Windows' own programs: skip, there are hundreds.
            if (t.path.StartsWith(@"\Microsoft\", StringComparison.OrdinalIgnoreCase) && sig.Trusted && sig.IsMicrosoft && !SecUtil.StrongCommand(t.cmd)) continue;
            string taskPath = t.path;
            Autorun("Scheduled task", t.runLevel == "highest" ? "Task Scheduler (runs as admin)" : "Task Scheduler", t.path, t.cmd,
                () => SecurityFixes.Plan("DisableTask", $"Turn off the task {Path.GetFileName(taskPath)}", "caution", false, new() { ["task"] = taskPath }),
                forceSeverity: t.hidden && !sig.Trusted ? "Medium" : null,
                forceReason: t.hidden && !sig.Trusted ? "Hidden task" : null);
        }
    }

    void CheckServices()
    {
        using (var s = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, StartMode FROM Win32_Service"))
        {
            foreach (ManagementObject o in s.Get())
            {
                using (o)
                {
                    string name = o["Name"]?.ToString() ?? "";
                    string mode = o["StartMode"]?.ToString() ?? "";
                    if (mode is "Disabled") continue;
                    string path = o["PathName"]?.ToString() ?? "";
                    string cmd = path;
                    // Services hosted inside svchost run a DLL; rate that DLL instead of svchost itself.
                    if (Path.GetFileName(SecUtil.LaunchTarget(path).target).Equals("svchost.exe", StringComparison.OrdinalIgnoreCase) &&
                        Reg(RegistryHive.LocalMachine, RegistryView.Registry64, $@"SYSTEM\CurrentControlSet\Services\{name}\Parameters", "ServiceDll") is string dll)
                        cmd = $"\"{Environment.ExpandEnvironmentVariables(dll)}\"";
                    var (target, _) = SecUtil.LaunchTarget(cmd);
                    var sig = FileTrust.Check(target);
                    if (sig.Trusted && sig.IsMicrosoft) continue;
                    string display = o["DisplayName"]?.ToString() ?? name;
                    string svcName = name;
                    Autorun("Service", mode == "Auto" ? "Services (starts with Windows)" : "Services (starts when needed)", $"{display} ({name})", cmd,
                        () => SecurityFixes.Plan("DisableService", $"Stop and turn off the service {display}", "caution", false, new() { ["service"] = svcName }));
                }
            }
        }

        // Kernel drivers that aren't validly signed: Windows normally refuses these unless test-signing is on.
        using var d = new ManagementObjectSearcher("SELECT Name, DisplayName, PathName, State FROM Win32_SystemDriver WHERE State = 'Running'");
        var unsigned = new List<string>();
        foreach (ManagementObject o in d.Get())
        {
            using (o)
            {
                string p = o["PathName"]?.ToString() ?? "";
                if (p.StartsWith(@"\??\")) p = p[4..];
                var sig = FileTrust.Check(p);
                if (sig.Exists && !sig.Trusted) unsigned.Add($"{o["DisplayName"]} ({p}) [{sig.Status}]");
            }
        }
        if (unsigned.Count > 0)
            Add("High", "Auto-start", $"{unsigned.Count} running driver{(unsigned.Count == 1 ? " isn't" : "s aren't")} validly signed", "",
                "Drivers run inside Windows itself with full control. Windows normally only loads signed ones, so an unsigned running driver needs explaining (test-signing mode, cheat software, or a rootkit).",
                "Look each one up. If you don't recognise it, run Microsoft Defender Offline.", unsigned,
                new[] { SecurityFixes.Plan("DefenderOffline", "Restart into Microsoft Defender Offline scan (about 15 minutes)", "caution", false, new()) });
        else Pass("Every running driver is validly signed");
    }

    void CheckDeepPersistence()
    {
        // WMI event subscriptions that run commands or scripts: a favourite of fileless malware, rarely used legitimately.
        try
        {
            var scope = new ManagementScope(@"root\subscription");
            scope.Connect();
            foreach (var (cls, field) in new[] { ("CommandLineEventConsumer", "CommandLineTemplate"), ("ActiveScriptEventConsumer", "ScriptText") })
            {
                using var s = new ManagementObjectSearcher(scope, new ObjectQuery($"SELECT * FROM {cls}"));
                foreach (ManagementObject o in s.Get())
                {
                    using (o)
                    {
                        string name = o["Name"]?.ToString() ?? "";
                        string body = Prop(o, field) ?? Prop(o, "ExecutablePath") ?? Prop(o, "ScriptFileName") ?? "";
                        string shortBody = body.Length > 300 ? body[..300] + "…" : body;
                        autoruns.Add(new AutorunItem("WMI subscription", @"root\subscription", name, shortBody, "", "", false, "Other", "High", "Runs a command when a system event happens", false));
                        Add("High", "Auto-start", $"Hidden WMI trigger: {name}", cls,
                            "A WMI event subscription runs a command or script whenever something happens in Windows. It leaves no file in the usual startup places, which is why malware uses it. Very few legitimate programs do.",
                            "Remove it unless you know a program you use needs it.",
                            new[] { $"{cls}: {name}", $"Runs: {shortBody}" },
                            new[] { SecurityFixes.Plan("RemoveWmi", $"Remove the WMI trigger \"{name}\"", "caution", true, new() { ["class"] = cls, ["name"] = name }) },
                            "wmi:" + name);
                    }
                }
            }
        }
        catch (Exception ex) { notes.Add($"WMI subscriptions couldn't be read: {ex.Message}"); }

        // Image File Execution Options "Debugger": makes Windows run something else whenever a program starts.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            const string ifeo = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
            try
            {
                using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var k = root.OpenSubKey(ifeo);
                if (k is null) continue;
                foreach (var exe in k.GetSubKeyNames())
                {
                    using var sub = k.OpenSubKey(exe);
                    if (sub?.GetValue("Debugger") is not string dbg || dbg.Trim().Length == 0) continue;
                    var (target, _) = SecUtil.LaunchTarget(dbg);
                    var sig = FileTrust.Check(target);
                    bool benign = sig.Trusted && (sig.IsMicrosoft || sig.Signer.Contains("Sysinternals", StringComparison.OrdinalIgnoreCase));
                    autoruns.Add(new AutorunItem("Program hijack", "Image File Execution Options", exe, dbg, target, sig.Signer, sig.Trusted, SecUtil.Zone(target),
                        benign ? "" : "High", benign ? "Replaced by a Microsoft tool (e.g. Process Explorer for Task Manager)" : "Runs something else whenever this program starts", false));
                    if (benign) continue;
                    var v = view; var e = exe;
                    Add("High", "Auto-start", $"Starting {exe} runs something else instead", dbg,
                        "This setting (a \"debugger\" in Image File Execution Options) makes Windows launch another program every time this one starts. Malware uses it to block security tools or to start itself.",
                        "Remove it unless you set it up yourself.", new[] { $"{exe} → {dbg}" },
                        new[] { SecurityFixes.Plan("RemoveRegValue", $"Remove the hijack on {exe}", "caution", true,
                            new() { ["hive"] = "HKLM", ["view"] = v == RegistryView.Registry32 ? "32" : "64", ["key"] = $@"{ifeo}\{e}", ["name"] = "Debugger" }) },
                        "ifeo:" + exe);
                }
            }
            catch { }
        }

        // Winlogon: what Windows starts as the desktop and right after sign-in.
        const string wl = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        if (Reg(RegistryHive.LocalMachine, RegistryView.Registry64, wl, "Shell") is string shell && !Regex.IsMatch(shell.Trim(), @"(?i)^explorer(\.exe)?,?$"))
            Add("High", "Auto-start", "Windows starts something extra as your desktop", shell,
                "The Winlogon \"Shell\" setting should be just explorer.exe. Anything else starts with every sign-in.",
                "Set it back to explorer.exe.", new[] { $"Shell = {shell}" },
                new[] { SecurityFixes.Plan("SetRegString", "Set the Windows shell back to explorer.exe", "caution", true,
                    new() { ["hive"] = "HKLM", ["key"] = wl, ["name"] = "Shell", ["value"] = "explorer.exe" }) }, "winlogon:shell");
        string expectedUserinit = Path.Combine(SecUtil.System32, "userinit.exe") + ",";
        if (Reg(RegistryHive.LocalMachine, RegistryView.Registry64, wl, "Userinit") is string ui &&
            !ui.Trim().TrimEnd(',').Equals(expectedUserinit.TrimEnd(','), StringComparison.OrdinalIgnoreCase))
            Add("High", "Auto-start", "Something extra runs right after you sign in", ui,
                "The Winlogon \"Userinit\" setting should only start userinit.exe.",
                "Set it back to Windows' default.", new[] { $"Userinit = {ui}" },
                new[] { SecurityFixes.Plan("SetRegString", "Set Userinit back to Windows' default", "caution", true,
                    new() { ["hive"] = "HKLM", ["key"] = wl, ["name"] = "Userinit", ["value"] = expectedUserinit }) }, "winlogon:userinit");

        // AppInit_DLLs: loaded into every program that uses the Windows UI.
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            const string win = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";
            if (Reg(RegistryHive.LocalMachine, view, win, "AppInit_DLLs") is string dlls && dlls.Trim().Length > 0 &&
                Reg(RegistryHive.LocalMachine, view, win, "LoadAppInit_DLLs") is int load && load != 0)
            {
                var v = view;
                Add("High", "Auto-start", "A DLL is loaded into almost every program", dlls,
                    "AppInit_DLLs injects these files into every program that shows a window. Old software used it; today it's mostly malware.",
                    "Clear it unless you know which program needs it.", new[] { $"AppInit_DLLs = {dlls}" },
                    new[] { SecurityFixes.Plan("SetRegString", "Clear AppInit_DLLs", "caution", true,
                        new() { ["hive"] = "HKLM", ["view"] = v == RegistryView.Registry32 ? "32" : "64", ["key"] = win, ["name"] = "AppInit_DLLs", ["value"] = "" }) },
                    "appinit:" + dlls);
            }
        }
    }

    // ---- programs and folders ----

    void CheckInstalledPrograms()
    {
        foreach (var (hive, view, key) in new[]
        {
            (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var k = root.OpenSubKey(key);
                if (k is null) continue;
                foreach (var sub in k.GetSubKeyNames())
                {
                    using var app = k.OpenSubKey(sub);
                    if (app?.GetValue("DisplayName") is not string name) continue;
                    string publisher = app.GetValue("Publisher") as string ?? "";
                    string location = app.GetValue("InstallLocation") as string ?? "";
                    var hit = AdwareDb.Match(name, publisher, location);
                    if (hit is null) continue;
                    string uninstall = app.GetValue("QuietUninstallString") as string ?? app.GetValue("UninstallString") as string ?? "";
                    var actions = new List<SecAction>();
                    if (uninstall.Length > 0)
                        actions.Add(SecurityFixes.Plan("Uninstall", $"Run {name}'s uninstaller (can't be undone)", "caution", hit.Severity == "High",
                            new() { ["hive"] = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU", ["view"] = view == RegistryView.Registry32 ? "32" : "64", ["key"] = $@"{key}\{sub}" }));
                    actions.Add(SecurityFixes.Plan("OpenSettings", "Open Installed apps", "guided", false, new() { ["uri"] = "ms-settings:appsfeatures" }));
                    Add(hit.Severity, "Adware", $"{hit.Name} is installed", $"{name}{(publisher.Length > 0 ? $" by {publisher}" : "")}",
                        hit.About, "Uninstall it, then scan again to catch anything it leaves behind.",
                        new[] { $"{name} {app.GetValue("DisplayVersion")}", location }, actions, "app:" + name);
                }
            }
            catch { }
        }
    }

    void CheckAdwareFolders()
    {
        var roots = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
        };
        foreach (var p in SecUtil.Profiles())
            roots.AddRange(new[] { p, Path.Combine(p, @"AppData\Local"), Path.Combine(p, @"AppData\Local\Programs"), Path.Combine(p, @"AppData\Roaming") });

        var hits = new Dictionary<string, List<string>>();
        foreach (var r in roots.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                foreach (var d in Directory.GetDirectories(r))
                {
                    var a = AdwareDb.Match("\\" + Path.GetFileName(d) + "\\", Path.GetFileName(d));
                    if (a is null) continue;
                    if (!hits.TryGetValue(a.Name, out var list)) hits[a.Name] = list = new();
                    list.Add(d);
                }
            }
            catch { }
        }
        foreach (var (family, folders) in hits)
        {
            var a = AdwareDb.Match(family)!;
            var ok = folders.Where(SecurityFixes.CanQuarantine).ToList();
            Add(a.Severity, "Adware", $"{family} folders on disk", string.Join(", ", folders.Select(Path.GetFileName).Distinct()),
                a.About, "Uninstall it first if it's still listed in Installed apps, then quarantine what's left.",
                folders,
                ok.Count > 0 ? new[] { SecurityFixes.Plan("Quarantine", $"Close its programs and move {ok.Count} folder{(ok.Count == 1 ? "" : "s")} to quarantine", "caution", true,
                    new() { ["paths"] = string.Join("|", ok) }) } : null, "adware:" + family);
        }
        if (hits.Count == 0) Pass("No folders from known adware");
    }

    // ---- browsers ----

    static readonly (string name, string policyKey, string dataDir)[] Chromium =
    {
        ("Chrome", @"SOFTWARE\Policies\Google\Chrome", @"Google\Chrome\User Data"),
        ("Edge", @"SOFTWARE\Policies\Microsoft\Edge", @"Microsoft\Edge\User Data"),
        ("Brave", @"SOFTWARE\Policies\BraveSoftware\Brave", @"BraveSoftware\Brave-Browser\User Data"),
        ("Vivaldi", @"SOFTWARE\Policies\Vivaldi", @"Vivaldi\User Data"),
    };

    void CheckBrowsers()
    {
        bool managedPc = IsDomainJoined();
        foreach (var (browser, policyKey, dataDir) in Chromium)
        {
            foreach (var hive in new[] { RegistryHive.LocalMachine, RegistryHive.CurrentUser })
            {
                string hiveName = hive == RegistryHive.LocalMachine ? "HKLM" : "HKCU";
                // Force-installed extensions: users can't remove these from the browser.
                foreach (var (val, data) in RegValues(hive, policyKey + @"\ExtensionInstallForcelist"))
                {
                    bool store = data.Contains("clients2.google.com", StringComparison.OrdinalIgnoreCase) || data.Contains("edge.microsoft.com", StringComparison.OrdinalIgnoreCase) || !data.Contains(';');
                    string id = data.Split(';')[0];
                    Add(managedPc ? "Low" : store ? "Medium" : "High", "Browsers", $"{browser} is forced to install an extension", id,
                        "A policy installs this extension and stops you from removing it. Companies do this on work PCs; on a home PC it's a classic adware trick (the \"Managed by your organization\" message).",
                        "Remove the policy, then remove the extension in the browser.",
                        new[] { $@"{hiveName}\{policyKey}\ExtensionInstallForcelist\{val} = {data}" },
                        new[] { SecurityFixes.Plan("RemoveRegValue", $"Remove the forced install of {id}", "caution", !managedPc,
                            new() { ["hive"] = hiveName, ["key"] = policyKey + @"\ExtensionInstallForcelist", ["name"] = val }) },
                        $"policy:{browser}:{id}");
                }
                // Forced home page, start pages, new tab or search engine.
                var forced = new List<(string name, string value, string key)>();
                foreach (var name in new[] { "HomepageLocation", "NewTabPageLocation", "DefaultSearchProviderSearchURL", "DefaultSearchProviderName" })
                    if (Reg(hive, RegistryView.Registry64, policyKey, name) is string v && v.Length > 0) forced.Add((name, v, policyKey));
                foreach (var (val, data) in RegValues(hive, policyKey + @"\RestoreOnStartupURLs")) forced.Add((val, data, policyKey + @"\RestoreOnStartupURLs"));
                if (forced.Count > 0)
                {
                    bool knownSearch = forced.All(f => Regex.IsMatch(f.value, @"(?i)(google\.|bing\.com|duckduckgo|ecosia|startpage|yahoo\.com|brave\.com)"));
                    Add(managedPc ? "Low" : knownSearch ? "Low" : "High", "Browsers", $"{browser}'s home page or search engine is locked by a policy",
                        string.Join(", ", forced.Select(f => f.value).Distinct().Take(3)),
                        "Search hijackers set these policies so your search goes through their ad-filled pages and you can't change it back.",
                        "Remove the policies, then pick your search engine in the browser's settings.",
                        forced.Select(f => $@"{hiveName}\{f.key}\{f.name} = {f.value}"),
                        forced.Select(f => SecurityFixes.Plan("RemoveRegValue", $"Remove the {f.name} policy", "caution", !managedPc && !knownSearch,
                            new() { ["hive"] = hiveName, ["key"] = f.key, ["name"] = f.name })).ToList(),
                        $"policy:{browser}:home");
                }
            }
            CheckExtensions(browser, dataDir);
        }
        CheckBrowserShortcuts();
    }

    static string? Prop(ManagementBaseObject o, string name)
    {
        try { return o[name]?.ToString(); } catch { return null; }
    }

    static List<(string name, string data)> RegValues(RegistryHive hive, string key)
    {
        var list = new List<(string, string)>();
        try
        {
            using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var k = root.OpenSubKey(key);
            if (k is null) return list;
            foreach (var n in k.GetValueNames()) if (k.GetValue(n) is string s) list.Add((n, s));
        }
        catch { }
        return list;
    }

    static bool IsDomainJoined()
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT PartOfDomain FROM Win32_ComputerSystem");
            foreach (ManagementObject o in s.Get()) using (o) return o["PartOfDomain"] is bool b && b;
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Extensions loaded from a folder (developer mode) or from adware families. Extensions are removed in the browser itself,
    /// so these are guided fixes: removing files under a running browser can corrupt the profile.
    /// </summary>
    void CheckExtensions(string browser, string dataDir)
    {
        foreach (var profileRoot in SecUtil.Profiles())
        {
            string userData = Path.Combine(profileRoot, "AppData", "Local", dataDir);
            if (!Directory.Exists(userData)) continue;
            IEnumerable<string> profiles;
            try { profiles = Directory.GetDirectories(userData).Where(d => Path.GetFileName(d) is "Default" || Path.GetFileName(d).StartsWith("Profile ")); }
            catch { continue; }
            foreach (var profile in profiles)
            {
                foreach (var prefsFile in new[] { "Secure Preferences", "Preferences" })
                {
                    try
                    {
                        string file = Path.Combine(profile, prefsFile);
                        if (!File.Exists(file)) continue;
                        using var doc = JsonDocument.Parse(File.ReadAllText(file));
                        if (!doc.RootElement.TryGetProperty("extensions", out var ext) || !ext.TryGetProperty("settings", out var all)) continue;
                        foreach (var e in all.EnumerateObject())
                        {
                            var v = e.Value;
                            int location = v.TryGetProperty("location", out var l) && l.ValueKind == JsonValueKind.Number ? l.GetInt32() : 0;
                            if (location is 5 or 10) continue; // built into the browser
                            string path = v.TryGetProperty("path", out var p) && p.ValueKind == JsonValueKind.String ? p.GetString() ?? "" : "";
                            string name = ExtensionName(profile, e.Name, path, v);
                            bool unpacked = location == 4;
                            var hit = AdwareDb.Match(name, path);
                            if (hit is null && !unpacked) continue;
                            string sev = hit is not null ? "High" : "Medium";
                            Add(sev, "Browsers", hit is not null ? $"{browser} extension from {hit.Name}: {name}" : $"{browser} extension loaded from a folder: {name}",
                                $"{Path.GetFileName(profile)} profile",
                                hit?.About ?? "This extension wasn't installed from the browser's store: it was loaded from a folder on the PC (developer mode). Developers do that; adware does too, to avoid store review.",
                                $"Open {browser}'s extensions page and remove it if you don't use it.",
                                new[] { $"ID {e.Name}", path.Length > 0 ? $"Loaded from {path}" : "" },
                                new[] { SecurityFixes.Plan("OpenSettings", $"Open {browser}'s extensions page", "guided", false,
                                    new() { ["uri"] = browser switch { "Edge" => "microsoft-edge:edge://extensions", _ => "" }, ["browser"] = browser }) },
                                $"ext:{browser}:{e.Name}");
                        }
                        break; // Secure Preferences had the list
                    }
                    catch { }
                }
            }
        }
    }

    static string ExtensionName(string profile, string id, string path, JsonElement v)
    {
        try
        {
            if (v.TryGetProperty("manifest", out var m) && m.TryGetProperty("name", out var n) && n.GetString() is string s && !s.StartsWith("__MSG_")) return s;
            string dir = Path.IsPathFullyQualified(path) ? path : Path.Combine(profile, "Extensions", id);
            if (!Path.IsPathFullyQualified(path) && Directory.Exists(dir)) dir = Directory.GetDirectories(dir).OrderByDescending(x => x).FirstOrDefault() ?? dir;
            string manifest = Path.Combine(dir, "manifest.json");
            if (File.Exists(manifest))
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(manifest));
                string name = doc.RootElement.TryGetProperty("name", out var nn) ? nn.GetString() ?? id : id;
                var msg = Regex.Match(name, @"^__MSG_(\w+)__$");
                if (msg.Success)
                {
                    foreach (var loc in new[] { "en", "en_US", "en_GB" })
                    {
                        string mf = Path.Combine(dir, "_locales", loc, "messages.json");
                        if (!File.Exists(mf)) continue;
                        using var md = JsonDocument.Parse(File.ReadAllText(mf));
                        foreach (var prop in md.RootElement.EnumerateObject())
                            if (prop.Name.Equals(msg.Groups[1].Value, StringComparison.OrdinalIgnoreCase) && prop.Value.TryGetProperty("message", out var mm))
                                return mm.GetString() ?? id;
                    }
                }
                return name;
            }
        }
        catch { }
        return id;
    }

    /// <summary>Browser shortcuts that sneak in an extension or a web page.</summary>
    void CheckBrowserShortcuts()
    {
        var places = new List<string>
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonDesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonStartMenu),
        };
        foreach (var p in SecUtil.Profiles())
        {
            places.Add(Path.Combine(p, "Desktop"));
            places.Add(Path.Combine(p, @"AppData\Roaming\Microsoft\Windows\Start Menu"));
            places.Add(Path.Combine(p, @"AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar"));
        }
        var links = new List<string>();
        foreach (var dir in places.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try { links.AddRange(Directory.EnumerateFiles(dir, "*.lnk", new System.IO.EnumerationOptions { RecurseSubdirectories = true, MaxRecursionDepth = 3, IgnoreInaccessible = true })); }
            catch { }
        }
        var browsers = new[] { "chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe", "vivaldi.exe" };
        var resolved = Sta.Run(() => links.Select(l => (l, cmd: ResolveShortcut(l))).ToList());
        foreach (var (lnk, cmd) in resolved)
        {
            var (target, args) = SecUtil.LaunchTarget(cmd);
            if (!browsers.Contains(Path.GetFileName(target).ToLowerInvariant())) continue;
            bool loadsExt = args.Contains("--load-extension", StringComparison.OrdinalIgnoreCase);
            bool opensUrl = Regex.IsMatch(args, @"(?i)https?://");
            if (!loadsExt && !opensUrl) continue;
            string l2 = lnk;
            Add(loadsExt ? "High" : "Medium", "Browsers", $"Browser shortcut has been changed: {Path.GetFileNameWithoutExtension(lnk)}", args,
                loadsExt ? "This shortcut secretly loads an extension every time you open the browser with it." : "This shortcut opens a specific web page every time, a common way to force an ad-filled start page.",
                "Move the shortcut to quarantine and make a new one (pin the browser again from the Start menu).",
                new[] { lnk, $"Runs: {cmd}" },
                new[] { SecurityFixes.Plan("Quarantine", "Move this shortcut to quarantine", "caution", true, new() { ["paths"] = l2 }) },
                "lnk:" + lnk);
        }
    }

    // ---- network ----

    void CheckNetwork()
    {
        string hosts = Path.Combine(SecUtil.System32, @"drivers\etc\hosts");
        try
        {
            var entries = File.ReadAllLines(hosts)
                .Select(l => Regex.Replace(l, "#.*$", "").Trim())
                .Where(l => l.Length > 0)
                .Where(l => !Regex.IsMatch(l, @"(?i)^(127\.0\.0\.1|::1)\s+localhost$"))
                .ToList();
            static bool IsBlock(string e) => Regex.IsMatch(e, @"^(0\.0\.0\.0|127\.\d+\.\d+\.\d+|::1?|::)\s");
            // Blocking security or update sites keeps protection from updating: that's what malware does.
            var securityRx = new Regex(@"(?i)\s(\S*\.)?(windowsupdate|update\.microsoft|delivery\.mp\.microsoft|wdcp\.microsoft|wdcpalt\.microsoft|smartscreen|definitionupdates|defender|avast|avg|norton|mcafee|kaspersky|eset|bitdefender|malwarebytes|virustotal|sophos|trendmicro|f-secure|webroot)\.");
            // Sending a well-known site to some other address is how fake banking/login pages are served.
            var popularRx = new Regex(@"(?i)\s(\S*\.)?(google|microsoft|windows|live|outlook|office|bing|apple|icloud|paypal|amazon|facebook|instagram|bank|chase|wellsfargo|steam(community|powered)?|epicgames|discord|roblox)\.");
            var important = entries.Where(e => IsBlock(e) ? securityRx.IsMatch(e) : (popularRx.IsMatch(e) || securityRx.IsMatch(e))).ToList();
            var privacyBlocks = entries.Where(IsBlock).Except(important).ToList();
            bool blockList = entries.Count > 0 && entries.All(IsBlock) && important.Count == 0;
            if (important.Count > 0)
                Add("High", "Network", "The hosts file redirects well-known websites", $"{important.Count} entr{(important.Count == 1 ? "y" : "ies")}",
                    "The hosts file overrides where websites point. Malware uses it to send you to fake banking or update sites, or to block security software.",
                    "Remove the entries. A backup of the file is kept.", important.Take(20),
                    new[] { SecurityFixes.Plan("CleanHosts", $"Remove {important.Count} hosts entr{(important.Count == 1 ? "y" : "ies")} for well-known sites", "caution", true,
                        new() { ["lines"] = string.Join("\n", important) }) }, "hosts:important");
            else if (entries.Count > 0 && !blockList)
                Add("Low", "Network", $"The hosts file has {entries.Count} custom entr{(entries.Count == 1 ? "y" : "ies")}", "",
                    "Usually added by developer tools, privacy tools or ad blockers.", "Check that you recognise them.", entries.Take(20), trustKey: "hosts:custom");
            else Pass(blockList ? $"The hosts file only blocks sites ({privacyBlocks.Count} entr{(privacyBlocks.Count == 1 ? "y" : "ies")}, e.g. an ad or tracking blocklist)" : "The hosts file is clean");
        }
        catch (Exception ex) { notes.Add($"Couldn't read the hosts file: {ex.Message}"); }

        const string inet = @"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        bool proxyOn = Reg(RegistryHive.CurrentUser, RegistryView.Default, inet, "ProxyEnable") is int pe && pe == 1;
        string proxy = Reg(RegistryHive.CurrentUser, RegistryView.Default, inet, "ProxyServer") as string ?? "";
        string pac = Reg(RegistryHive.CurrentUser, RegistryView.Default, inet, "AutoConfigURL") as string ?? "";
        if ((proxyOn && proxy.Length > 0) || pac.Length > 0)
            Add(pac.Length > 0 ? "Medium" : "Low", "Network", "Your web traffic goes through a proxy",
                pac.Length > 0 ? pac : proxy,
                "A proxy sees everything you browse. VPNs, school/work networks and some security tools set one; adware sets one to inject ads or watch your traffic.",
                "Turn it off unless you know what set it.", new[] { proxyOn ? $"Proxy server: {proxy}" : "", pac.Length > 0 ? $"Setup script: {pac}" : "" }.Where(s => s.Length > 0),
                new[] { SecurityFixes.Plan("ClearProxy", "Turn off the proxy", "safe", false, new()) }, "proxy:" + (pac.Length > 0 ? pac : proxy));
        else Pass("No web proxy is set");
    }

    // ---- backdoors and remote access ----

    void CheckAccessibilityBackdoor()
    {
        var shells = new[] { "cmd.exe", "powershell.exe", "pwsh.exe", "explorer.exe", "taskmgr.exe", "regedit.exe", "conhost.exe", "mmc.exe" };
        var shellHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var s in new[] { Path.Combine(SecUtil.System32, "cmd.exe"), Path.Combine(SecUtil.System32, @"WindowsPowerShell\v1.0\powershell.exe"), Path.Combine(SecUtil.WinDir, "explorer.exe") })
            if (Hash(s) is string h) shellHashes.Add(h);

        var replaced = new List<string>();
        var unverified = new List<string>();
        foreach (var exe in new[] { "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe", "narrator.exe", "displayswitch.exe", "atbroker.exe" })
        {
            string path = Path.Combine(SecUtil.System32, exe);
            if (!File.Exists(path)) continue;
            string original = "";
            try { original = (FileVersionInfo.GetVersionInfo(path).OriginalFilename ?? "").Replace(".mui", "", StringComparison.OrdinalIgnoreCase); } catch { }
            var sig = FileTrust.Check(path);
            bool isShell = shells.Contains(original.ToLowerInvariant()) || (Hash(path) is string h && shellHashes.Contains(h));
            // The tell-tale is a copy of a command prompt or shell, or a file changed after signing. A signature we
            // simply couldn't verify isn't enough to raise a critical alarm on its own.
            if (isShell || sig.Status == "HashMismatch") replaced.Add($"{exe}: original name {original}, signed by {(sig.Trusted ? sig.Signer : sig.Status)}");
            else if (!sig.Trusted) unverified.Add(exe);
        }
        if (unverified.Count > 0) notes.Add($"Couldn't verify Windows' signature on {string.Join(", ", unverified)}; they don't look replaced. Running System File Checker (sfc /scannow) would confirm.");
        if (replaced.Count > 0)
            Add("Critical", "Backdoor", "A login-screen tool has been replaced", string.Join("; ", replaced),
                "Swapping Sticky Keys or the Ease of Access button for a command prompt lets anyone at the sign-in screen take full control of the PC without a password.",
                "Restore Windows' own files with System File Checker, then change your passwords and run Microsoft Defender Offline.",
                replaced, new[]
                {
                    SecurityFixes.Plan("Sfc", "Restore Windows' own files (System File Checker, 10–20 minutes)", "safe", true, new()),
                    SecurityFixes.Plan("DefenderOffline", "Then restart into Microsoft Defender Offline", "caution", false, new()),
                });
        else Pass("Login-screen accessibility tools are genuine");
    }

    static string? Hash(string path)
    {
        try { using var s = File.OpenRead(path); return Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(s)); }
        catch { return null; }
    }

    void CheckRemoteAccess()
    {
        var tools = new (string name, string[] patterns)[]
        {
            ("AnyDesk", new[] { "anydesk" }), ("TeamViewer", new[] { "teamviewer" }), ("RustDesk", new[] { "rustdesk" }),
            ("UltraViewer", new[] { "ultraviewer" }), ("ScreenConnect / ConnectWise", new[] { "screenconnect", "connectwise control" }),
            ("Splashtop", new[] { "splashtop" }), ("LogMeIn", new[] { "logmein" }), ("Supremo", new[] { "supremo" }),
            ("AeroAdmin", new[] { "aeroadmin" }), ("Ammyy Admin", new[] { "ammyy" }), ("Zoho Assist", new[] { "zoho assist" }),
            ("GoTo Resolve", new[] { "goto resolve", "gotoresolve" }), ("Chrome Remote Desktop", new[] { "chrome remote desktop" }),
            ("RemotePC", new[] { "remotepc" }), ("HopToDesk", new[] { "hoptodesk" }),
        };
        var installed = new List<string>();
        foreach (var name in InstalledNames())
            foreach (var (tool, patterns) in tools)
                if (patterns.Any(p => name.Contains(p, StringComparison.OrdinalIgnoreCase)) && !installed.Contains(tool)) installed.Add(tool);

        // Incoming sessions are the tell-tale of a tech-support scam ("Microsoft called about a virus…").
        var incoming = new List<string>();
        var cutoff = DateTime.Now.AddDays(-60);
        foreach (var trace in AnyDeskTraces())
        {
            try
            {
                foreach (var line in File.ReadLines(trace).Where(l => l.StartsWith("Incoming", StringComparison.OrdinalIgnoreCase)))
                {
                    var m = Regex.Match(line, @"(\d{4}-\d{2}-\d{2}),\s*(\d{2}:\d{2})");
                    if (m.Success && DateTime.TryParse($"{m.Groups[1].Value} {m.Groups[2].Value}", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var when) && when < cutoff) continue;
                    incoming.Add("AnyDesk: " + Regex.Replace(line, @"\s+", " ").Trim());
                }
            }
            catch { }
        }
        foreach (var dir in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            string tv = Path.Combine(dir, "TeamViewer", "Connections_incoming.txt");
            try
            {
                if (File.Exists(tv))
                    incoming.AddRange(File.ReadLines(tv).Where(l => l.Trim().Length > 0).TakeLast(20).Select(l => "TeamViewer: " + Regex.Replace(l, @"\s+", " ").Trim()));
            }
            catch { }
        }

        if (incoming.Count > 0)
            Add("High", "Remote access", $"Someone connected to this PC remotely ({incoming.Count} session{(incoming.Count == 1 ? "" : "s")})", "",
                "If you let someone in after a phone call or pop-up claiming to be Microsoft, your bank, \"tech support\" or a refund department, that was a scam. They may have installed something or seen your accounts.",
                "If you don't know who these were: uninstall the remote tool, change your email and banking passwords from another device, call your bank, and run Microsoft Defender Offline.",
                incoming.TakeLast(15),
                new[]
                {
                    SecurityFixes.Plan("OpenSettings", "Open Installed apps to uninstall the remote tool", "guided", true, new() { ["uri"] = "ms-settings:appsfeatures" }),
                    SecurityFixes.Plan("DefenderOffline", "Restart into Microsoft Defender Offline", "caution", false, new()),
                }, "remote:incoming");
        if (installed.Count > 0)
            Add("Info", "Remote access", $"Remote-access tools installed: {string.Join(", ", installed)}", "",
                "These let someone see and control this PC over the internet. Fine if you use them; scammers ask people to install them.",
                "Uninstall any you don't use.", installed,
                new[] { SecurityFixes.Plan("OpenSettings", "Open Installed apps", "guided", false, new() { ["uri"] = "ms-settings:appsfeatures" }) },
                "remote:installed:" + string.Join(",", installed));
        else Pass("No remote-access tools installed");

        // Fake "verify you're human" pages ask you to press Win+R and paste a command: it shows up in the Run history.
        const string runMru = @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
        var pasted = RegValues(RegistryHive.CurrentUser, runMru)
            .Where(v => v.name != "MRUList" && Regex.IsMatch(v.data, @"(?i)(powershell|pwsh|mshta|curl|wget|bitsadmin|certutil|cmd\s*/c|https?://|iex|-e(nc)?\s)"))
            .ToList();
        if (pasted.Count > 0)
            Add("High", "Backdoor", "A suspicious command was run from the Win+R box", "",
                "Fake \"I'm not a robot\" pages tell you to press Win+R and paste a command. That command usually downloads a password stealer.",
                "If you did that: run Microsoft Defender Offline, then change your passwords (email first) from another device and sign out of all sessions.",
                pasted.Select(p => p.data.Length > 200 ? p.data[..200] + "…" : p.data),
                new[] { SecurityFixes.Plan("DefenderOffline", "Restart into Microsoft Defender Offline", "caution", true, new()) }, "runmru");
    }

    static IEnumerable<string> AnyDeskTraces()
    {
        var list = new List<string> { Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "AnyDesk", "connection_trace.txt") };
        foreach (var p in SecUtil.Profiles()) list.Add(Path.Combine(p, @"AppData\Roaming\AnyDesk\connection_trace.txt"));
        return list.Where(File.Exists);
    }

    static IEnumerable<string> InstalledNames()
    {
        foreach (var (hive, view) in new[] { (RegistryHive.LocalMachine, RegistryView.Registry64), (RegistryHive.LocalMachine, RegistryView.Registry32), (RegistryHive.CurrentUser, RegistryView.Default) })
        {
            List<string> names = new();
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var k = root.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
                if (k is not null)
                    foreach (var sub in k.GetSubKeyNames())
                    {
                        using var a = k.OpenSubKey(sub);
                        if (a?.GetValue("DisplayName") is string n) names.Add(n);
                    }
            }
            catch { }
            foreach (var n in names) yield return n;
        }
    }

    // ---- recent files ----

    static readonly HashSet<string> ExecExt = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".scr", ".com", ".pif", ".cpl", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".lnk", ".dll" };

    // Archives are left out on purpose: self-extracting "name.7z.exe" / "name.zip.exe" installers are normal (Git ships one).
    static readonly Regex DoubleExt = new(@"(?i)\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|mov|invoice|scan)\s*\.(exe|scr|com|pif|bat|cmd|vbs|js|hta|cpl|lnk)$|\s{5,}\.(exe|scr)$");

    static readonly Regex CrackName = new(@"(?i)(crack(ed)?\b|keygen|\bkms(pico|auto)?\b|activator|cheat|\bhack(s|ed)?\b|injector|executor|free.?robux|robux.?gen|repack|nulled|warez|\bkrnl\b|solara|fluxus|jjsploit|synapse.?x|celery.?exec|wave.?exec)");

    /// <summary>Script files that are normal settings or plugins, not programs.</summary>
    static readonly HashSet<string> BenignScriptNames = new(StringComparer.OrdinalIgnoreCase) { "prefs.js", "user.js", "xulstore.js", "compatibility.js" };

    static readonly Regex SkipDirs = new(@"(?i)\\AppData\\Local\\(Packages|Microsoft|Google\\Chrome|BraveSoftware|Mozilla|NVIDIA|AMD|Intel|Steam|Discord|Spotify|JetBrains|pip|npm-cache|CrashDumps|D3DSCache|Roblox|Programs\\Microsoft VS Code)|\\AppData\\Roaming\\(Microsoft\\(Windows\\Recent|Teams|Office)|npm|Code|discord|Spotify|Mozilla|Thunderbird|BetterDiscord|librewolf|Waterfox|Vencord)|\\ProgramData\\(Microsoft|Package Cache|NVIDIA|Intel|AMD|Packages|regid|USOShared|SystemForge)");

    void CheckRecentFiles()
    {
        var since = DateTime.Now.AddDays(-30);
        var roots = new List<(string root, int depth)>();
        foreach (var p in SecUtil.Profiles())
        {
            roots.Add((Path.Combine(p, "Downloads"), 2));
            roots.Add((Path.Combine(p, "Desktop"), 1));
            roots.Add((Path.Combine(p, @"AppData\Local\Temp"), 2));
            roots.Add((Path.Combine(p, @"AppData\Roaming"), 3));
            roots.Add((Path.Combine(p, @"AppData\Local"), 2));
            roots.Add((p, 0));
        }
        roots.Add((Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 2));
        roots.Add((Path.Combine(Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users", "Public"), 3));

        var files = new List<FileInfo>();
        var budget = Stopwatch.StartNew();
        foreach (var (root, depth) in roots)
        {
            if (!Directory.Exists(root) || budget.Elapsed.TotalSeconds > 40 || files.Count > 6000) continue;
            try
            {
                var opts = new System.IO.EnumerationOptions { RecurseSubdirectories = depth > 0, MaxRecursionDepth = depth, IgnoreInaccessible = true, AttributesToSkip = FileAttributes.ReparsePoint };
                foreach (var f in new DirectoryInfo(root).EnumerateFiles("*", opts))
                {
                    if (!ExecExt.Contains(f.Extension) || f.LastWriteTime < since || SkipDirs.IsMatch(f.FullName)) continue;
                    files.Add(f);
                    if (files.Count > 6000 || budget.Elapsed.TotalSeconds > 40) break;
                }
            }
            catch { }
        }
        files = files.DistinctBy(f => f.FullName.ToLowerInvariant()).OrderByDescending(f => f.LastWriteTime).ToList();
        filesChecked = files.Count;

        var high = new List<(FileInfo f, string why)>();
        var medium = new List<(FileInfo f, string why)>();
        int sigChecks = 0;
        foreach (var f in files)
        {
            if (trusted.Contains("path:" + f.FullName)) continue;
            string zone = SecUtil.Zone(f.FullName);
            string ext = f.Extension.ToLowerInvariant();
            var why = new List<string>();
            string sev = "";
            bool program = ext is ".exe" or ".scr" or ".com" or ".pif" or ".cpl";
            FileSignature? sigCache = null;
            FileSignature Sig() => sigCache ??= FileTrust.Check(f.FullName);
            if (DoubleExt.IsMatch(f.Name) && !(program && Sig().Trusted)) { why.Add("disguised as a document or picture (double extension)"); sev = "High"; }
            if (SecUtil.Masquerades(f.FullName)) { why.Add("named like a core Windows program"); sev = "High"; }
            else if (program && SecUtil.LooksLikeCoreName(f.Name) && !Sig().Trusted) { why.Add("unsigned, and named one letter off a core Windows program"); sev = "High"; }
            var adware = AdwareDb.Match(f.Name, f.FullName);
            if (adware is not null) { why.Add($"adware: {adware.Name}"); sev = SecUtil.Max(sev, adware.Severity); }
            if (ext is ".exe" or ".scr" or ".com" or ".pif" or ".cpl" && sigChecks < 400 && zone is "AppData\\Roaming" or "Users\\Public" or "ProgramData" or "RecycleBin")
            {
                sigChecks++;
                var sig = Sig();
                if (sig.Status == "HashMismatch") { why.Add("signature broken (file was modified)"); sev = SecUtil.Max(sev, "High"); }
                else if (!sig.Trusted) { why.Add($"unsigned program in {zone}"); sev = SecUtil.Max(sev, "Medium"); }
            }
            if (ext is ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".hta" && zone is "AppData\\Roaming" or "Users\\Public" or "ProgramData"
                && !BenignScriptNames.Contains(f.Name) && !f.Name.EndsWith(".plugin.js", StringComparison.OrdinalIgnoreCase))
            { why.Add($"script in {zone}"); sev = SecUtil.Max(sev, "Medium"); }
            if (zone is "Downloads" && CrackName.IsMatch(f.Name) && ext is not ".lnk" and not ".dll")
            { why.Add("name suggests a crack, cheat or game executor"); sev = SecUtil.Max(sev, "Medium"); }

            if (sev == "High" || sev == "Critical") high.Add((f, string.Join("; ", why)));
            else if (sev == "Medium") medium.Add((f, string.Join("; ", why)));
        }

        foreach (var (f, why) in high.Take(15))
            Add("High", "Suspicious files", $"Suspicious file: {f.Name}", why,
                "Disguised names and fake Windows files are how infections usually start.",
                "Move it to quarantine, then run a Defender full scan.",
                new[] { f.FullName, $"Changed {f.LastWriteTime:g}", $"{f.Length / 1024.0:N0} KB" },
                SecurityFixes.CanQuarantine(f.FullName) ? new[] { SecurityFixes.Plan("Quarantine", $"Move {f.Name} to quarantine", "caution", true, new() { ["paths"] = f.FullName }) } : null,
                "path:" + f.FullName);
        foreach (var (f, why) in medium.Take(25))
            Add("Medium", "Suspicious files", $"Worth checking: {f.Name}", why,
                "Not necessarily harmful, but this is where malware tends to live. Cracks and game executors are a very common source of password stealers.",
                "If you don't recognise it or don't need it, move it to quarantine.",
                new[] { f.FullName, $"Changed {f.LastWriteTime:g}" },
                SecurityFixes.CanQuarantine(f.FullName) ? new[] { SecurityFixes.Plan("Quarantine", $"Move {f.Name} to quarantine", "caution", false, new() { ["paths"] = f.FullName }) } : null,
                "path:" + f.FullName);
        if (high.Count + medium.Count == 0) Pass($"No suspicious programs among {files.Count} recent files");
        if (high.Count > 15 || medium.Count > 25) notes.Add("Only the first 15 high and 25 medium suspicious files are listed. Clean those, then scan again.");
    }
}

/// <summary>Runs work on a single-threaded apartment thread, which Windows Shell and Task Scheduler COM objects prefer.</summary>
static class Sta
{
    public static T Run<T>(Func<T> work)
    {
        T result = default!;
        Exception? error = null;
        var t = new Thread(() => { try { result = work(); } catch (Exception ex) { error = ex; } }) { IsBackground = true };
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        if (error is not null) throw error;
        return result;
    }
}
