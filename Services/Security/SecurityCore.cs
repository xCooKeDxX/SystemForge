using System.Text.RegularExpressions;

namespace SystemForge;

// Security checks in SystemForge are our own code, inspired by PC Health Scan by TCPeep
// (https://github.com/TCPeep/PC-Health-Scan), used with his permission and credited in the app and README.

public sealed record SecAction(string Id, string Label, string Risk, bool Recommended);

public sealed record SecFinding(
    string Id,
    string Severity,          // Critical, High, Medium, Low, Info
    string Category,
    string Title,
    string Detail,
    string Why,
    string Fix,
    List<string> Evidence,
    List<SecAction> Actions,
    string? TrustKey);

public sealed record AutorunItem(string Type, string Location, string Name, string Command, string Target, string Signer,
    bool Signed, string Zone, string Severity, string Reasons, bool TrustedByYou);

public sealed record SecScan(List<SecFinding> Findings, List<AutorunItem> Autoruns, List<string> Passed, DateTime ScannedAt,
    int FilesChecked, double Seconds, List<string> Notes);

/// <summary>Rates where a file lives and what a launch command would run.</summary>
public static partial class SecUtil
{
    public static readonly string WinDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    public static readonly string System32 = Environment.SystemDirectory;
    static readonly string ProgramData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
    static readonly string Pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    static readonly string Pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
    static readonly string UsersRoot = Path.GetDirectoryName(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile)) ?? @"C:\Users";

    /// <summary>Real user profiles on this PC (C:\Users\name), skipping Default, Public and similar.</summary>
    public static List<string> Profiles()
    {
        var skip = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "Default", "Default User", "Public", "All Users", "defaultuser0", "WDAGUtilityAccount" };
        try
        {
            return Directory.GetDirectories(UsersRoot)
                .Where(d => !skip.Contains(Path.GetFileName(d)))
                .Where(d => { try { return !new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.ReparsePoint) && Directory.Exists(Path.Combine(d, "AppData")); } catch { return false; } })
                .ToList();
        }
        catch { return new() { Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) }; }
    }

    static bool Under(string path, string root) =>
        root.Length > 0 && path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

    /// <summary>A short name for where a file lives, used in explanations.</summary>
    public static string Zone(string? path)
    {
        if (string.IsNullOrEmpty(path)) return "Unknown";
        string p;
        try { p = Path.GetFullPath(path); } catch { return "Unknown"; }
        if (Under(p, WinDir)) return Under(p, Path.Combine(WinDir, "Temp")) ? "Temp" : "Windows";
        if (Under(p, Pf) || Under(p, Pf86)) return "Program Files";
        if (p.Contains(@"\$Recycle.Bin\", StringComparison.OrdinalIgnoreCase)) return "RecycleBin";
        if (Under(p, Path.Combine(UsersRoot, "Public"))) return "Users\\Public";
        if (Under(p, ProgramData)) return "ProgramData";
        if (Under(p, UsersRoot))
        {
            if (p.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase)) return "Temp";
            if (p.Contains(@"\AppData\Roaming\", StringComparison.OrdinalIgnoreCase)) return "AppData\\Roaming";
            if (p.Contains(@"\AppData\Local\", StringComparison.OrdinalIgnoreCase)) return "AppData\\Local";
            if (p.Contains(@"\AppData\LocalLow\", StringComparison.OrdinalIgnoreCase)) return "AppData\\LocalLow";
            if (p.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase)) return "Downloads";
            if (p.Contains(@"\Desktop\", StringComparison.OrdinalIgnoreCase)) return "Desktop";
            return "UserProfile";
        }
        return "Other";
    }

    /// <summary>Places any program running as the user can write to, so anything launched from there could have been swapped.</summary>
    public static bool UserWritable(string zone) => zone is "Temp" or "AppData\\Roaming" or "AppData\\Local" or "AppData\\LocalLow"
        or "Downloads" or "Desktop" or "UserProfile" or "Users\\Public" or "RecycleBin" or "ProgramData";

    /// <summary>Core Windows process names that only belong in the Windows folder.</summary>
    static readonly HashSet<string> CoreNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
        "taskhostw.exe", "dllhost.exe", "rundll32.exe", "conhost.exe", "dwm.exe", "explorer.exe", "ctfmon.exe", "sihost.exe",
        "runtimebroker.exe", "searchindexer.exe", "wuauclt.exe", "msmpeng.exe", "lsm.exe", "audiodg.exe", "fontdrvhost.exe",
    };

    /// <summary>A file named like a core Windows program but living somewhere else (svchost.exe in AppData, say).</summary>
    public static bool Masquerades(string path)
    {
        string name = Path.GetFileName(path);
        if (!CoreNames.Contains(name)) return false;
        return Zone(path) != "Windows";
    }

    /// <summary>Lookalike spellings of core names (svchosts.exe, scvhost.exe, lsas.exe…).</summary>
    /// <summary>Real program names one letter away from a core name.</summary>
    static readonly HashSet<string> LegitNearMisses = new(StringComparer.OrdinalIgnoreCase) { "service", "explore", "taskhost", "winlogin", "spooler", "conhost2" };

    public static bool LooksLikeCoreName(string fileName)
    {
        string n = Path.GetFileNameWithoutExtension(fileName).ToLowerInvariant();
        if (CoreNames.Contains(fileName) || LegitNearMisses.Contains(n)) return false;
        foreach (var core in CoreNames)
        {
            string c = Path.GetFileNameWithoutExtension(core);
            if (c.Length >= 5 && n.Length >= 5 && n != c && Distance(n, c) == 1) return true;
        }
        return false;
    }

    /// <summary>Edit distance where swapping two neighbouring letters (scvhost) also counts as one edit.</summary>
    static int Distance(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (int i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (int j = 0; j <= b.Length; j++) d[0, j] = j;
        for (int i = 1; i <= a.Length; i++)
            for (int j = 1; j <= b.Length; j++)
            {
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + (a[i - 1] == b[j - 1] ? 0 : 1));
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1]) d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        return d[a.Length, b.Length];
    }

    /// <summary>
    /// The file a launch command actually runs: the program itself, or the script/DLL when it starts through
    /// cmd, PowerShell, wscript, mshta or rundll32.
    /// </summary>
    public static (string target, string args) LaunchTarget(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return ("", "");
        string cmd = Environment.ExpandEnvironmentVariables(command.Trim());
        string exe, rest;
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            exe = end > 0 ? cmd[1..end] : cmd.Trim('"');
            rest = end > 0 ? cmd[(end + 1)..].Trim() : "";
        }
        else
        {
            var m = ExeRx().Match(cmd);
            if (m.Success) { exe = m.Value; rest = cmd[m.Length..].Trim(); }
            else { int sp = cmd.IndexOf(' '); exe = sp > 0 ? cmd[..sp] : cmd; rest = sp > 0 ? cmd[(sp + 1)..].Trim() : ""; }
        }
        exe = ResolveExe(exe);

        string name = Path.GetFileName(exe).ToLowerInvariant();
        if (name is "rundll32.exe")
        {
            var dll = rest.Split(',')[0].Trim().Trim('"');
            if (dll.Length > 0) return (ResolveExe(dll), rest);
        }
        if (name is "wscript.exe" or "cscript.exe" or "mshta.exe" or "regsvr32.exe")
        {
            var m = ScriptArgRx().Match(rest);
            if (m.Success) return (ResolveExe(m.Groups[1].Value.Trim('"')), rest);
        }
        if (name is "powershell.exe" or "pwsh.exe")
        {
            var m = Regex.Match(rest, @"(?i)-file\s+(""[^""]+""|\S+)");
            if (m.Success) return (ResolveExe(m.Groups[1].Value.Trim('"')), rest);
        }
        if (name is "cmd.exe")
        {
            var m = Regex.Match(rest, @"(?i)/[ck]\s+(""[^""]+\.(bat|cmd|exe)""|\S+\.(bat|cmd|exe))");
            if (m.Success) return (ResolveExe(m.Groups[1].Value.Trim('"')), rest);
        }
        return (exe, rest);
    }

    static string ResolveExe(string exe)
    {
        exe = exe.Trim().Trim('"');
        if (exe.Length == 0) return "";
        try
        {
            if (Path.IsPathFullyQualified(exe)) return exe;
            foreach (var dir in new[] { System32, WinDir, Path.Combine(System32, "WindowsPowerShell", "v1.0") })
            {
                var p = Path.Combine(dir, exe);
                if (File.Exists(p)) return p;
                if (!exe.Contains('.') && File.Exists(p + ".exe")) return p + ".exe";
            }
        }
        catch { }
        return exe;
    }

    /// <summary>Command lines that download, decode or mine: almost never seen in legitimate startup items.</summary>
    public static bool StrongCommand(string cmd) => StrongRx().IsMatch(cmd);

    /// <summary>Signs of trying not to be seen: hidden window, script policy bypass.</summary>
    public static bool StealthCommand(string cmd) => WeakRx().IsMatch(cmd);

    public static bool OpensWebPage(string cmd) => UrlLaunchRx().IsMatch(cmd);

    public static int Rank(string sev) => sev switch { "Critical" => 4, "High" => 3, "Medium" => 2, "Low" => 1, _ => 0 };
    public static string Max(string a, string b) => Rank(a) >= Rank(b) ? a : b;

    /// <summary>Rates something that launches a program (startup entry, task, service, shortcut).</summary>
    public static (string target, FileSignature sig, string zone, string severity, List<string> reasons, Adware? adware) RateLaunch(string command, string name)
    {
        var (target, _) = LaunchTarget(command);
        var sig = FileTrust.Check(target);
        string zone = Zone(target);
        var reasons = new List<string>();
        string sev = "";

        var adware = AdwareDb.Match(name, command, sig.Signer);
        if (adware is not null) { reasons.Add($"Known adware: {adware.Name}"); sev = Max(sev, adware.Severity); }

        if (target.Length > 0 && !sig.Exists && Path.IsPathFullyQualified(target))
        {
            reasons.Add("Points to a file that no longer exists (leftover)");
            sev = Max(sev, "Low");
        }
        else if (sig.Status == "HashMismatch")
        {
            reasons.Add("Its digital signature is broken: the file was changed after it was signed");
            sev = Max(sev, "High");
        }
        else if (sig.Exists && !sig.Trusted)
        {
            if (UserWritable(zone)) { reasons.Add($"Not digitally signed, and runs from {zone}"); sev = Max(sev, "Medium"); }
            else { reasons.Add("Not digitally signed"); sev = Max(sev, "Low"); }
        }
        if (sig.Exists && Masquerades(target)) { reasons.Add("Named like a core Windows program, but lives outside Windows"); sev = Max(sev, "High"); }
        if (sig.Exists && !sig.Trusted && LooksLikeCoreName(Path.GetFileName(target))) { reasons.Add("Unsigned, and its name is one letter off a core Windows program"); sev = Max(sev, "High"); }
        if (StrongCommand(command)) { reasons.Add("Command downloads, decodes or mines"); sev = Max(sev, "High"); }
        else if (StealthCommand(command)) { reasons.Add("Runs hidden or bypasses script safety"); sev = Max(sev, "Low"); }
        string ext = Path.GetExtension(target).ToLowerInvariant();
        if (ext is ".ps1" or ".vbs" or ".vbe" or ".js" or ".jse" or ".wsf" or ".hta" or ".bat" or ".cmd" or ".dll" && UserWritable(zone))
        {
            reasons.Add($"Starts a script or DLL from {zone}");
            sev = Max(sev, "Medium");
        }
        if (OpensWebPage(command)) { reasons.Add("Opens a web page automatically"); sev = Max(sev, "Medium"); }
        return (target, sig, zone, sev, reasons, adware);
    }

    [GeneratedRegex(@"^[a-zA-Z]:\\[^""<>|?*]*?\.(exe|com|bat|cmd|scr)(?=\s|$)", RegexOptions.IgnoreCase)]
    private static partial Regex ExeRx();

    [GeneratedRegex(@"(""[^""]+\.(vbs|vbe|js|jse|wsf|hta|sct|dll)""|\S+\.(vbs|vbe|js|jse|wsf|hta|sct|dll))", RegexOptions.IgnoreCase)]
    private static partial Regex ScriptArgRx();

    [GeneratedRegex(@"(?i)((powershell|pwsh)(\.exe)?[""']?\s.*?\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{40,}|frombase64string|downloadstring|downloadfile|(powershell|pwsh).*(invoke-webrequest|\biwr\s|invoke-restmethod|\birm\s)|\|\s*iex\b|\biex\s*\(|invoke-expression|mshta(\.exe)?\s+[""']?https?:|bitsadmin.*/transfer|certutil.*-urlcache|xmrig|--donate-level|stratum\+tcp|\bcurl\b.*\|\s*(cmd|powershell))")]
    private static partial Regex StrongRx();

    [GeneratedRegex(@"(?i)(-w(indowstyle)?\s+h(idden)?\b|-executionpolicy\s+bypass|-ep\s+bypass|\s-nop(rofile)?\s)")]
    private static partial Regex WeakRx();

    [GeneratedRegex(@"(?i)(explorer|cmd|rundll32|start)(\.exe)?""?\s+.*https?://|^https?://")]
    private static partial Regex UrlLaunchRx();
}

public sealed record Adware(string Name, string Severity, string About);

/// <summary>
/// Known adware, browser hijackers, fake optimizers, trojanized activators and miners. Matched against program,
/// folder, publisher and command names. Our own list; the idea of a curated family list comes from PC Health Scan.
/// </summary>
public static class AdwareDb
{
    sealed record Family(string Name, string Severity, string About, string[] Patterns);

    static readonly Family[] Families =
    {
        new("PC App Store", "High", "An adware \"app store\" that restarts itself at every sign-in, shows ads and notifications, and can cover the screen with a payment page.",
            new[] { "pcappstore", "pc app store", "fast corporation", "fastcorporation", "nw_store" }),
        new("OneLaunch", "High", "Adware search bar and browser that rides along with free downloads and starts itself with Windows.", new[] { "onelaunch" }),
        new("Wave Browser", "High", "A browser hijacker that changes your search engine and shows ads.", new[] { "wavebrowser", "wave browser", "wavesor", "swiftsearch" }),
        new("OneStart", "High", "An adware browser that installs per user and starts itself with Windows.", new[] { "onestart.exe", "onestartbar", "onestart browser", @"\onestart\" }),
        new("AppSuite PDF Editor / ManualFinder", "High", "\"Free\" utilities found in 2025 to contain a hidden backdoor.", new[] { "appsuite pdf", "appsuite-pdf", "manualfinder", "manual finder", "echo infini", "glint software" }),
        new("JustAskJacky", "High", "A trojan disguised as a helpful assistant app.", new[] { "justaskjacky", "just ask jacky" }),
        new("Segurazo (SAntivirus)", "High", "A fake antivirus that is very hard to uninstall.", new[] { "segurazo", "santivirus" }),
        new("Wajam / Social2Search", "High", "Injects ads into the websites you visit.", new[] { "wajam", "social2search", "searchawesome" }),
        new("Search hijacker / toolbar", "High", "Changes your browser's search engine and home page.", new[] { "conduit", "ask toolbar", "babylon toolbar", "delta-search", "deltasearch", "searchprotect", "search protect", "sweetpacks", "mywebsearch", "mindspark", "trovi", "snap.do" }),
        new("Piracy activator", "High", "\"Free activation\" tools for Windows/Office. Very often bundled with stealers or miners.", new[] { "kmspico", "kmsauto", "autokms", "kms_vl_all", "hwidgen", "windows loader", "re-loader", "microsoft toolkit" }),
        new("Crypto miner", "Medium", "Uses your processor or graphics card to make money for someone, slowing the PC and raising temperatures.", new[] { "xmrig", "phoenixminer", "nbminer", "lolminer", "gminer", "t-rex miner", "teamredminer", "cpuminer", "nicehash" }),
        new("Fake optimizer / scareware", "Medium", "Shows scary \"problems\" to sell a license; the fixes are of little real value.", new[] { "reimage", "restoro", "fortect", "outbyte", "pcaccelerate", "pc accelerate", "speedypc", "pc optimizer pro", "advanced system repair", "driver support one", "driversupport", "driverfix", "driver reviver", "driverdoc", "advanced driver updater", "winzip driver updater", "winzip system utilities", "pc speed maximizer", "one system care", "total system care", "advanced pc cleanup", "slimcleaner", "pc app booster" }),
        new("Bundleware", "Medium", "Installs extra programs alongside the one you wanted.", new[] { "web companion", "webcompanion", "bytefence", "installcore", "opencandy", "amonetize", "somoto", "outbrowse" }),
        new("Unwanted browser", "Medium", "Low-quality browser installed by bundles, usually with ads or tracking.", new[] { "chromstera", "olcinium", "qword browser", "crossbrowser", "torch browser", "bobrowser", "ucbrowser", "uc browser" }),
    };

    public static Adware? Match(params string?[] texts)
    {
        string hay = string.Join(" | ", texts.Where(t => !string.IsNullOrEmpty(t))).ToLowerInvariant();
        if (hay.Length == 0) return null;
        foreach (var f in Families)
            foreach (var p in f.Patterns)
                if (hay.Contains(p)) return new Adware(f.Name, f.Severity, f.About);
        return null;
    }
}
