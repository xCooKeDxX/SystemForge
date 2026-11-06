using System.Diagnostics;
using System.Management;

namespace SystemForge;

public sealed record AvProduct(string Name, bool Enabled, bool UpToDate);

public sealed record DefenderStatus(
    bool Available,            // Defender's management interface answered
    string Mode,               // Normal, Passive Mode, EDR Block Mode, Not running …
    bool RealTime,
    bool Tamper,
    int DefinitionAgeDays,
    DateTime? DefinitionsUpdated,
    DateTime? LastQuickScan,
    DateTime? LastFullScan,
    int PuaProtection,         // 0 off, 1 block, 2 audit
    List<string> Exclusions,
    List<AvProduct> OtherAntivirus,
    string Message);

public sealed record DefenderThreat(long Id, string Name, string Severity, string Category, bool Active, bool Executed, List<string> Resources, DateTime? Detected);

/// <summary>
/// Microsoft Defender, the antivirus built into Windows, which independent labs rate among the best. SystemForge shows its
/// state and drives it (definitions, scans, removing threats) instead of pretending to be an antivirus itself.
/// Uses the same management interface as Windows' own Defender PowerShell commands.
/// </summary>
public static class Defender
{
    const string Ns = @"root\Microsoft\Windows\Defender";

    static string MpCmdRun
    {
        get
        {
            // The platform folder holds the newest MpCmdRun; the Program Files copy is the fallback.
            try
            {
                var platform = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Windows Defender\Platform");
                var newest = Directory.Exists(platform)
                    ? Directory.GetDirectories(platform).OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                        .Select(d => Path.Combine(d, "MpCmdRun.exe")).FirstOrDefault(File.Exists)
                    : null;
                if (newest is not null) return newest;
            }
            catch { }
            return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Windows Defender\MpCmdRun.exe");
        }
    }

    public static DefenderStatus Status()
    {
        var others = OtherAntivirus();
        try
        {
            var scope = new ManagementScope(Ns);
            scope.Connect();
            using var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpComputerStatus"));
            using var results = s.Get();
            var st = results.Cast<ManagementObject>().FirstOrDefault();
            if (st is null) return Unavailable(others, "Defender didn't report its status.");
            using (st)
            {
                var pref = Preferences(scope);
                var exclusions = new List<string>();
                foreach (var (prop, label) in new[] { ("ExclusionPath", "Folder or file"), ("ExclusionProcess", "Program"), ("ExclusionExtension", "File type") })
                    if (pref?[prop] is string[] list)
                        exclusions.AddRange(list.Where(x => !string.IsNullOrWhiteSpace(x)).Select(x => $"{label}: {x}"));

                string mode = Str(st, "AMRunningMode");
                if (mode.Length == 0) mode = Bool(st, "AMServiceEnabled") ? "Normal" : "Not running";
                return new DefenderStatus(true, mode,
                    Bool(st, "RealTimeProtectionEnabled"),
                    Bool(st, "IsTamperProtected"),
                    Int(st, "AntivirusSignatureAge"),
                    Date(st, "AntivirusSignatureLastUpdated"),
                    Date(st, "QuickScanEndTime"),
                    Date(st, "FullScanEndTime"),
                    pref?["PUAProtection"] is byte b ? b : pref?["PUAProtection"] is int i ? i : 0,
                    exclusions, others, "");
            }
        }
        catch (Exception ex)
        {
            // Common when another antivirus has fully replaced Defender, or Defender was removed by a "debloat" tool.
            return Unavailable(others, others.Count > 0
                ? $"{others[0].Name} is protecting this PC, so Defender is turned off."
                : $"Couldn't reach Microsoft Defender ({ex.Message}). It may have been turned off or removed.");
        }
    }

    static DefenderStatus Unavailable(List<AvProduct> others, string msg) =>
        new(false, "Not running", false, false, -1, null, null, null, 0, new(), others, msg);

    static ManagementBaseObject? Preferences(ManagementScope scope)
    {
        try
        {
            using var s = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpPreference"));
            return s.Get().Cast<ManagementBaseObject>().FirstOrDefault();
        }
        catch { return null; }
    }

    /// <summary>Antivirus products registered with Windows Security Center (other than Defender).</summary>
    static List<AvProduct> OtherAntivirus()
    {
        var list = new List<AvProduct>();
        try
        {
            using var s = new ManagementObjectSearcher(new ManagementScope(@"root\SecurityCenter2"), new ObjectQuery("SELECT displayName, productState FROM AntiVirusProduct"));
            foreach (ManagementObject o in s.Get())
            {
                using (o)
                {
                    string name = Str(o, "displayName");
                    if (name.Contains("Windows Defender", StringComparison.OrdinalIgnoreCase) || name.Contains("Microsoft Defender", StringComparison.OrdinalIgnoreCase)) continue;
                    uint state = Convert.ToUInt32(o["productState"] ?? 0u);
                    // productState: byte 2 = scanner state (0x10 on), byte 3 = definitions (0x00 up to date).
                    bool enabled = ((state >> 8) & 0xF0) == 0x10;
                    bool upToDate = (state & 0xF0) == 0x00;
                    list.Add(new AvProduct(name, enabled, upToDate));
                }
            }
        }
        catch { }
        return list;
    }

    public static List<DefenderThreat> Threats()
    {
        var list = new List<DefenderThreat>();
        try
        {
            var scope = new ManagementScope(Ns);
            scope.Connect();
            var detections = new Dictionary<long, (DateTime? when, List<string> res, int status)>();
            using (var d = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpThreatDetection")))
            {
                foreach (ManagementObject o in d.Get())
                {
                    using (o)
                    {
                        long id = Convert.ToInt64(o["ThreatID"] ?? 0L);
                        var res = (o["Resources"] as string[] ?? Array.Empty<string>()).Select(CleanResource).ToList();
                        var when = Date(o, "InitialDetectionTime");
                        if (!detections.TryGetValue(id, out var prev) || (when ?? DateTime.MinValue) > (prev.when ?? DateTime.MinValue))
                            detections[id] = (when, res, Int(o, "ThreatStatusID"));
                    }
                }
            }
            using var t = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM MSFT_MpThreat"));
            foreach (ManagementObject o in t.Get())
            {
                using (o)
                {
                    long id = Convert.ToInt64(o["ThreatID"] ?? 0L);
                    detections.TryGetValue(id, out var det);
                    list.Add(new DefenderThreat(id, Str(o, "ThreatName"), SeverityName(Int(o, "SeverityID")), CategoryName(Int(o, "CategoryID")),
                        Bool(o, "IsActive"), Bool(o, "DidThreatExecute"),
                        det.res ?? (o["Resources"] as string[] ?? Array.Empty<string>()).Select(CleanResource).ToList(), det.when));
                }
            }
        }
        catch { }
        return list.OrderByDescending(x => x.Active).ThenByDescending(x => x.Detected).ToList();
    }

    public static string UpdateDefinitions() => RunMp("Updating virus definitions", 15, "-SignatureUpdate") switch
    {
        0 => "Virus definitions are up to date.",
        var c => $"Defender couldn't update its definitions (code {c}). Check your internet connection.",
    };

    public static string Scan(bool full)
    {
        int code = RunMp(full ? "Full scan" : "Quick scan", full ? 360 : 60, "-Scan", "-ScanType", full ? "2" : "1");
        int active = Threats().Count(t => t.Active);
        return code switch
        {
            0 when active == 0 => full ? "Full scan finished. No threats found." : "Quick scan finished. No threats found.",
            0 or 2 => $"Scan finished. Defender found {active} threat{(active == 1 ? "" : "s")}. See the list below.",
            _ => $"Defender stopped the scan (code {code}).",
        };
    }

    /// <summary>
    /// Microsoft Defender Offline: restarts the PC into a scan that runs before Windows, which finds malware
    /// that hides from scans while Windows is running. Takes about 15 minutes.
    /// </summary>
    public static string StartOfflineScan()
    {
        try
        {
            using var cls = new ManagementClass(new ManagementScope(Ns), new ManagementPath("MSFT_MpWDOScan"), null);
            cls.InvokeMethod("Start", null);
            return "Your PC is restarting into Microsoft Defender Offline. It takes about 15 minutes, then Windows starts as normal.";
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Couldn't start the offline scan: {ex.Message}");
        }
    }

    /// <summary>Has Defender clean up every threat it has found (the same as "Remove all" in Windows Security).</summary>
    public static string RemoveThreats()
    {
        try
        {
            using var cls = new ManagementClass(new ManagementScope(Ns), new ManagementPath("MSFT_MpThreat"), null);
            cls.InvokeMethod("Remove", null);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Defender couldn't remove the threats ({ex.Message}). Open Windows Security → Virus & threat protection, or run the offline scan.");
        }
        int left = Threats().Count(t => t.Active);
        return left == 0 ? "Defender removed the threats it found." : $"{left} threat{(left == 1 ? "" : "s")} still need attention. Run a full scan, or the offline scan.";
    }

    public static void SetPuaProtection(bool on)
    {
        using var cls = new ManagementClass(new ManagementScope(Ns), new ManagementPath("MSFT_MpPreference"), null);
        using var p = cls.GetMethodParameters("Set");
        p["PUAProtection"] = (byte)(on ? 1 : 0);
        cls.InvokeMethod("Set", p, null);
    }

    /// <summary>Removes (or re-adds, for undo) one exclusion of the given kind: ExclusionPath, ExclusionProcess or ExclusionExtension.</summary>
    public static void ChangeExclusion(string kind, string value, bool add)
    {
        if (kind is not ("ExclusionPath" or "ExclusionProcess" or "ExclusionExtension")) throw new ArgumentException("Unknown exclusion type.");
        using var cls = new ManagementClass(new ManagementScope(Ns), new ManagementPath("MSFT_MpPreference"), null);
        string method = add ? "Add" : "Remove";
        using var p = cls.GetMethodParameters(method);
        p[kind] = new[] { value };
        cls.InvokeMethod(method, p, null);
    }

    static int RunMp(string what, int minutes, params string[] args)
    {
        string exe = MpCmdRun;
        if (!File.Exists(exe)) throw new InvalidOperationException("Microsoft Defender isn't installed or is turned off on this PC.");
        var psi = new ProcessStartInfo(exe) { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        p.OutputDataReceived += (_, _) => { };
        p.ErrorDataReceived += (_, _) => { };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (!p.WaitForExit(TimeSpan.FromMinutes(minutes)))
        {
            try { p.Kill(); } catch { }
            throw new TimeoutException($"{what} took too long and was stopped.");
        }
        return p.ExitCode;
    }

    /// <summary>Defender writes resources as "file:_C:\path" or "regkey:_HKLM\…": keep just the location.</summary>
    static string CleanResource(string r) => System.Text.RegularExpressions.Regex.Replace(r, @"^[a-z]+:_", "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    static string SeverityName(int id) => id switch { 1 => "Low", 2 => "Moderate", 4 => "High", 5 => "Severe", _ => "Unknown" };

    static string CategoryName(int id) => id switch
    {
        1 => "Adware", 2 => "Spyware", 3 => "Password stealer", 4 => "Trojan downloader", 5 => "Worm", 6 => "Backdoor",
        7 => "Remote access trojan", 8 => "Trojan", 9 => "Email flooder", 10 => "Keylogger", 11 => "Dialer", 12 => "Monitoring software",
        13 => "Browser modifier", 14 => "Cookie", 15 => "Browser plugin", 16 => "AOL exploit", 17 => "Nuker", 18 => "Security disabler",
        19 => "Joke program", 20 => "Hostile ActiveX", 21 => "Software bundler", 22 => "Stealth notifier", 23 => "Settings modifier",
        24 => "Toolbar", 25 => "Remote control software", 26 => "Trojan FTP", 27 => "Potentially unwanted software", 28 => "ICQ exploit",
        29 => "Trojan telnet", 30 => "Exploit", 31 => "File-sharing program", 32 => "Malware creation tool", 33 => "Remote control software",
        34 => "Tool", 36 => "Trojan denial of service", 37 => "Trojan dropper", 38 => "Trojan mass mailer", 39 => "Trojan monitoring software",
        40 => "Trojan proxy server", 42 => "Virus", 43 => "Known", 44 => "Unknown", 45 => "SPP", 46 => "Behavior", 47 => "Vulnerability",
        48 => "Policy", 49 => "Enterprise unwanted software", 50 => "Ransomware", 51 => "ASR rule", _ => "Threat",
    };

    static string Str(ManagementBaseObject o, string p) { try { return o[p]?.ToString() ?? ""; } catch { return ""; } }
    static bool Bool(ManagementBaseObject o, string p) { try { return o[p] is bool b && b; } catch { return false; } }
    static int Int(ManagementBaseObject o, string p) { try { return o[p] is null ? -1 : Convert.ToInt32(o[p]); } catch { return -1; } }

    static DateTime? Date(ManagementBaseObject o, string p)
    {
        try
        {
            var v = o[p];
            if (v is null) return null;
            var d = ManagementDateTimeConverter.ToDateTime(v.ToString());
            return d.Year < 2000 ? null : d;
        }
        catch { return null; }
    }
}
