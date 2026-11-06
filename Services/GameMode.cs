using System.Diagnostics;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SystemForge;

/// <summary>What Game Mode changed, kept on disk so a crash or power cut can't leave the PC in "game" settings.</summary>
public sealed class GameModeRestore
{
    public Guid? PrevScheme { get; set; }
    public Guid? SetScheme { get; set; }
    public Guid? PrevOverlay { get; set; }
    public Guid? SetOverlay { get; set; }
}

public record GameEntry(string Path, string Name, string? Icon);

public record GameModeStatus(
    bool Active, bool Manual, string? Game, string? GamePath, string? GameIcon, DateTime? SinceUtc, List<string> Changes,
    bool Auto, bool Power, bool Priority, bool Memory,
    List<GameEntry> Games, List<GameEntry> Ignored, bool WindowsGameMode);

/// <summary>
/// Game Mode: while a game is running, SystemForge
///  - switches Windows to its best-performance power setting (only when plugged in),
///  - gives the game "above normal" CPU priority (never "high", which can starve audio and input),
///  - frees memory once from background apps (never from the game),
///  - pauses its own update checks and pop-ups.
/// Everything is put back the moment the game closes. It doesn't stop services or close apps: that's where
/// "boosters" break things (audio, Wi-Fi, updates) for gains too small to measure.
/// </summary>
public static partial class GameMode
{
    static readonly Guid Balanced = new("381b4222-f694-41f0-9685-ff5bb260df2e");
    static readonly Guid HighPerformance = new("8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c");
    static readonly Guid UltimatePerformance = new("e9a42b02-d5df-448d-aa00-03f14749eb61");
    static readonly Guid BestPerformanceOverlay = new("ded574b5-45a0-4f42-8737-46345c09c238");

    public static event Action? Changed;

    static readonly object gate = new();
    static AppSettings settings = new();
    static bool active, manual;
    static int gamePid;
    static DateTime gameStart;
    static string? gameName, gamePath;
    static DateTime? since;
    static readonly List<string> changes = new();
    static readonly List<(int pid, DateTime start, ProcessPriorityClass prev)> raised = new();
    static int suppressedPid;
    static DateTime suppressedStart;

    public static bool Active { get { lock (gate) return active; } }
    public static int GamePid { get { lock (gate) return active ? gamePid : 0; } }

    /// <summary>Call once at start. Puts back anything a previous run left changed.</summary>
    public static void Init(AppSettings s)
    {
        lock (gate)
        {
            settings = s;
            if (s.GameModeRestore is not null) RestorePower(s.GameModeRestore);
            s.GameModeRestore = null;
            s.Save();
        }
    }

    // ---- detection ----

    /// <summary>Apps that look like games but aren't: launchers, helpers, crash reporters, and Roblox Studio.</summary>
    static readonly HashSet<string> NotGames = new(StringComparer.OrdinalIgnoreCase)
    {
        "steam", "steamwebhelper", "steamservice", "EpicGamesLauncher", "EpicWebHelper", "EADesktop", "EABackgroundService",
        "EALauncher", "Battle.net", "Agent", "RiotClientServices", "RiotClientUx", "RiotClientUxRender", "RiotClientCrashHandler",
        "GalaxyClient", "GalaxyClient Helper", "GOG Galaxy Notifications Renderer", "upc", "UbisoftConnect", "UplayWebCore",
        "RobloxStudioBeta", "RobloxPlayerLauncher", "RobloxStudioLauncherBeta", "MinecraftLauncher", "XboxPcApp", "GamingServices",
        "UnityCrashHandler64", "UnityCrashHandler32", "CrashReportClient", "CrashReporter", "crashpad_handler", "vc_redist.x64",
        "vc_redist.x86", "DXSETUP", "dotNetFx40_Full_setup", "unins000", "EasyAntiCheat", "EasyAntiCheat_EOS", "BEService", "BattlEye",
        "explorer", "SystemForge", "Discord", "obs64", "Medal", "nvcontainer", "NVIDIA Overlay", "GameBar", "GameBarFTServer",
        // Tools that Steam also installs into its library folder.
        "blender", "aseprite", "wallpaper32", "wallpaper64", "ui32", "RPGMV", "RPGMZ", "GameMaker", "Unity", "UnrealEditor",
    };

    /// <summary>Things that go full screen but aren't games: browsers and video players.</summary>
    static readonly HashSet<string> FullScreenNotGames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chrome", "msedge", "firefox", "opera", "opera_gx", "brave", "vivaldi", "librewolf", "waterfox", "zen",
        "vlc", "mpc-hc64", "mpc-hc", "mpc-be64", "PotPlayerMini64", "PotPlayer64", "mpv", "wmplayer", "Microsoft.Media.Player",
        "Video.UI", "Netflix", "ApplicationFrameHost", "PowerPnt", "POWERPNT", "Teams", "ms-teams", "Zoom", "Spotify",
    };

    static readonly HashSet<string> KnownGames = new(StringComparer.OrdinalIgnoreCase)
    {
        "RobloxPlayerBeta", "Minecraft.Windows", "FortniteClient-Win64-Shipping", "VALORANT-Win64-Shipping", "League of Legends",
        "cs2", "csgo", "dota2", "r5apex", "r5apex_dx12", "GTA5", "GTA5_Enhanced", "RDR2", "Overwatch",
    };

    [GeneratedRegex(@"(?i)\\(steamapps\\common|Epic Games|Riot Games|GOG Galaxy\\Games|GOG Games|XboxGames|Ubisoft Game Launcher\\games|EA Games|Electronic Arts|Rockstar Games|Battle\.net\\.+\\|Blizzard Entertainment|Bethesda\.net Launcher\\games|Amazon Games\\Library|itch\\apps)\\")]
    private static partial Regex LibraryRx();

    static bool IsGame(string path, string name)
    {
        if (settings.GameModeIgnored.Any(p => p.Equals(path, StringComparison.OrdinalIgnoreCase))) return false;
        if (settings.GameModeGames.Any(p => p.Equals(path, StringComparison.OrdinalIgnoreCase))) return true;
        if (NotGames.Contains(name)) return false;
        if (KnownGames.Contains(name)) return true;
        if (LibraryRx().IsMatch(path)) return true;
        if (FullScreenNotGames.Contains(name)) return false;
        return Native.SHQueryUserNotificationState(out int state) == 0 && state == Native.QUNS_RUNNING_D3D_FULL_SCREEN;
    }

    /// <summary>Runs every few seconds on a worker thread.</summary>
    public static void Poll()
    {
        bool changed = false;
        lock (gate)
        {
            if (active && !manual && gamePid != 0 && !IsAlive(gamePid, gameStart))
            {
                // Many games start through a small launcher that exits once the real game is up: follow it.
                if (ForegroundGame() is { } next) { Retarget(next.pid, next.start, next.name, next.path); changed = true; }
                else { ExitLocked(); changed = true; }
            }
            else if (!active && settings.GameModeAuto && ForegroundGame() is { } g &&
                     !(g.pid == suppressedPid && g.start == suppressedStart))
            {
                EnterLocked(g.pid, g.start, g.name, g.path, isManual: false);
                changed = true;
            }
        }
        if (changed) Changed?.Invoke();
    }

    static (int pid, DateTime start, string name, string path)? ForegroundGame()
    {
        int pid = Native.GetForegroundProcessId();
        if (pid <= 4 || pid == Environment.ProcessId) return null;
        var d = Describe(pid);
        if (d is null || !IsGame(d.Value.path, d.Value.name)) return null;
        return (pid, d.Value.start, d.Value.name, d.Value.path);
    }

    static (string name, string path, DateTime start)? Describe(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            string? path = Native.ProcessPath(pid);
            if (string.IsNullOrEmpty(path)) return null;
            DateTime start;
            try { start = p.StartTime; } catch { start = DateTime.MinValue; }
            return (p.ProcessName, path, start);
        }
        catch { return null; }
    }

    static bool IsAlive(int pid, DateTime start)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            if (p.HasExited) return false;
            try { return start == DateTime.MinValue || p.StartTime == start; } catch { return true; }
        }
        catch { return false; }
    }

    // ---- turning on and off ----

    /// <summary>From the overlay, tray or dashboard. Turning it off while a game runs keeps it off for that game.</summary>
    public static GameModeStatus Set(bool on)
    {
        lock (gate)
        {
            if (on && !active)
            {
                int pid = Native.GetForegroundProcessId();
                var d = pid > 4 && pid != Environment.ProcessId ? Describe(pid) : null;
                // From the desktop or SystemForge's own window there's no game to look after: power and memory only.
                if (d is { } x && !NotGames.Contains(x.name) && !FullScreenNotGames.Contains(x.name))
                    EnterLocked(pid, x.start, x.name, x.path, isManual: true);
                else
                    EnterLocked(0, DateTime.MinValue, null, null, isManual: true);
            }
            else if (!on && active)
            {
                if (!manual && gamePid != 0) { suppressedPid = gamePid; suppressedStart = gameStart; }
                ExitLocked();
            }
        }
        Changed?.Invoke();
        return Status();
    }

    static void EnterLocked(int pid, DateTime start, string? name, string? path, bool isManual)
    {
        active = true;
        manual = isManual;
        since = DateTime.UtcNow;
        changes.Clear();
        raised.Clear();
        gamePid = pid;
        gameStart = start;
        gamePath = path;
        gameName = path is null ? null : FriendlyName(path, name);

        if (settings.GameModePower) ApplyPower();
        if (settings.GameModePriority && pid != 0) RaisePriority(pid, start);
        if (settings.GameModeMemory)
        {
            int skip = pid;
            Task.Run(() =>
            {
                try
                {
                    var r = MemoryOptimizer.Optimize(skip);
                    lock (gate)
                        if (active && r.Note is null) changes.Add($"Freed {r.FreedMb:N0} MB from background apps");
                    Changed?.Invoke();
                }
                catch { }
            });
        }
        changes.Add("SystemForge's own update checks and pop-ups are paused");
    }

    static void Retarget(int pid, DateTime start, string name, string path)
    {
        RestorePriorities();
        gamePid = pid;
        gameStart = start;
        gamePath = path;
        gameName = FriendlyName(path, name);
        if (settings.GameModePriority) RaisePriority(pid, start);
    }

    static void ExitLocked()
    {
        RestorePriorities();
        if (settings.GameModeRestore is not null) RestorePower(settings.GameModeRestore);
        settings.GameModeRestore = null;
        settings.Save();
        active = false;
        manual = false;
        gamePid = 0;
        gameName = gamePath = null;
        since = null;
        changes.Clear();
    }

    // ---- power ----

    static void ApplyPower()
    {
        if (SystemInformation.PowerStatus.PowerLineStatus == PowerLineStatus.Offline)
        {
            changes.Add("Power settings left alone because you're on battery");
            return;
        }
        var current = Native.GetActivePowerScheme();
        if (current is not Guid cur) return;
        string curName = Native.PowerSchemeName(cur) ?? "";
        if (cur == HighPerformance || cur == UltimatePerformance ||
            curName.Contains("High performance", StringComparison.OrdinalIgnoreCase) ||
            curName.Contains("Ultimate", StringComparison.OrdinalIgnoreCase))
        {
            changes.Add($"Already on the {curName} power plan");
            return;
        }

        var restore = new GameModeRestore();
        // Balanced plan (the Windows default): raise the power-mode slider to Best performance.
        if (cur == Balanced && Native.GetPowerOverlay() is Guid overlay)
        {
            if (overlay == BestPerformanceOverlay) { changes.Add("Windows power mode is already Best performance"); return; }
            restore.PrevOverlay = overlay;
            restore.SetOverlay = BestPerformanceOverlay;
            Save(restore); // written before the change, so even a crash right after it can be undone
            if (Native.SetPowerOverlay(BestPerformanceOverlay)) { changes.Add("Windows power mode set to Best performance"); return; }
            restore.PrevOverlay = restore.SetOverlay = null;
        }

        // Power saver or another plan: switch to High performance if this PC has it.
        if (Native.PowerSchemeExists(HighPerformance))
        {
            restore.PrevScheme = cur;
            restore.SetScheme = HighPerformance;
            Save(restore);
            var hp = HighPerformance;
            if (Native.PowerSetActiveScheme(IntPtr.Zero, ref hp) == 0)
            {
                changes.Add($"Power plan switched from {(curName.Length > 0 ? curName : "your plan")} to High performance");
                return;
            }
            restore.PrevScheme = restore.SetScheme = null;
        }
        Save(restore.SetOverlay is null && restore.SetScheme is null ? null : restore);
        changes.Add("Couldn't change the power plan on this PC");
    }

    static void Save(GameModeRestore? r)
    {
        settings.GameModeRestore = r;
        settings.Save();
    }

    /// <summary>Only undoes a change that's still in place: if you picked another plan meanwhile, yours stays.</summary>
    static void RestorePower(GameModeRestore r)
    {
        try
        {
            if (r.SetOverlay is Guid so && r.PrevOverlay is Guid po && Native.GetPowerOverlay() == so)
                Native.SetPowerOverlay(po);
            if (r.SetScheme is Guid ss && r.PrevScheme is Guid ps && Native.GetActivePowerScheme() == ss)
                Native.PowerSetActiveScheme(IntPtr.Zero, ref ps);
        }
        catch { }
    }

    // ---- priority ----

    static void RaisePriority(int pid, DateTime start)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            var prev = p.PriorityClass;
            if (prev != ProcessPriorityClass.Normal)
            {
                if (prev == ProcessPriorityClass.AboveNormal || prev == ProcessPriorityClass.High) changes.Add("The game already runs at raised priority");
                return;
            }
            p.PriorityClass = ProcessPriorityClass.AboveNormal;
            raised.Add((pid, start, prev));
            changes.Add("The game gets CPU time before background apps (above normal priority)");
        }
        catch { changes.Add("The game didn't allow its priority to be changed (some anti-cheat blocks this)"); }
    }

    static void RestorePriorities()
    {
        foreach (var (pid, start, prev) in raised)
        {
            try
            {
                if (!IsAlive(pid, start)) continue;
                using var p = Process.GetProcessById(pid);
                if (p.PriorityClass == ProcessPriorityClass.AboveNormal) p.PriorityClass = prev;
            }
            catch { }
        }
        raised.Clear();
    }

    // ---- status and options ----

    public static GameModeStatus Status()
    {
        lock (gate)
        {
            var s = settings;
            return new GameModeStatus(active, manual, gameName, gamePath, gamePath is null ? null : IconService.GetDataUrl(gamePath), since,
                changes.ToList(), s.GameModeAuto, s.GameModePower, s.GameModePriority, s.GameModeMemory,
                s.GameModeGames.Select(Entry).ToList(), s.GameModeIgnored.Select(Entry).ToList(), WindowsGameModeOn());
        }
    }

    public static GameModeStatus SetOption(string key, bool value)
    {
        lock (gate)
        {
            switch (key)
            {
                case "auto": settings.GameModeAuto = value; break;
                case "power": settings.GameModePower = value; break;
                case "priority": settings.GameModePriority = value; break;
                case "memory": settings.GameModeMemory = value; break;
                default: throw new ArgumentException($"Unknown Game Mode option: {key}");
            }
            settings.Save();
        }
        return Status();
    }

    /// <summary>Always treat this program as a game (add), or never (ignore).</summary>
    public static GameModeStatus SetGame(string path, string list, bool add)
    {
        if (add)
        {
            if (!path.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) || !File.Exists(path))
                throw new ArgumentException("That program couldn't be found.");
        }
        lock (gate)
        {
            var target = list == "ignored" ? settings.GameModeIgnored : settings.GameModeGames;
            var other = list == "ignored" ? settings.GameModeGames : settings.GameModeIgnored;
            target.RemoveAll(p => p.Equals(path, StringComparison.OrdinalIgnoreCase));
            if (add)
            {
                other.RemoveAll(p => p.Equals(path, StringComparison.OrdinalIgnoreCase));
                target.Add(Path.GetFullPath(path));
            }
            settings.Save();
        }
        return Status();
    }

    /// <summary>Open programs with a window, to pick one to add as a game.</summary>
    public static List<GameEntry> Candidates()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<GameEntry>();
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (p.SessionId != ProcessManager.CurrentSessionId || p.Id == Environment.ProcessId) continue;
                    if (p.MainWindowHandle == IntPtr.Zero || ProcessManager.IsProtected(p.ProcessName)) continue;
                    string? path = Native.ProcessPath(p.Id);
                    if (path is null || !seen.Add(path)) continue;
                    if (path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase)) continue;
                    list.Add(Entry(path));
                }
                catch { }
            }
        }
        return list.OrderBy(e => e.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    static GameEntry Entry(string path) => new(path, FriendlyName(path, Path.GetFileNameWithoutExtension(path)), IconService.GetDataUrl(path));

    static string FriendlyName(string path, string? fallback)
    {
        try
        {
            var v = FileVersionInfo.GetVersionInfo(path);
            string? n = string.IsNullOrWhiteSpace(v.FileDescription) ? v.ProductName : v.FileDescription;
            if (!string.IsNullOrWhiteSpace(n)) return n.Trim();
        }
        catch { }
        return fallback ?? Path.GetFileNameWithoutExtension(path);
    }

    /// <summary>Windows' own Game Mode (Settings › Gaming). On unless someone turned it off.</summary>
    static bool WindowsGameModeOn()
    {
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\GameBar");
            return k?.GetValue("AutoGameModeEnabled") is not int v || v != 0;
        }
        catch { return true; }
    }
}
