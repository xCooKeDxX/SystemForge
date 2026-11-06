using System.Diagnostics;

namespace SystemForge;

/// <summary>One app as the user thinks of it: all processes with the same name added together.</summary>
public record AppProcessGroup(string Name, string DisplayName, int Count, double RamMb, double Cpu,
    string? ExePath, string? Icon, bool Protected);

public record EndResult(int Ended, int Failed, string Message);
public record MemoryResult(double FreedMb, int Trimmed, bool StandbyCleared, double AvailableMb, string? Note);

/// <summary>Tracks per-process CPU between calls. Each consumer keeps its own sampler.</summary>
public sealed class ProcessSampler
{
    readonly object gate = new();
    readonly Dictionary<int, (TimeSpan cpu, DateTime at)> last = new();
    readonly Dictionary<string, (string? path, string? description)> details = new(StringComparer.OrdinalIgnoreCase);

    public List<AppProcessGroup> TopApps(int max)
    {
        lock (gate)
        {
            var now = DateTime.UtcNow;
            var seen = new HashSet<int>();
            var groups = new Dictionary<string, (List<int> pids, long ram, double cpu)>(StringComparer.OrdinalIgnoreCase);
            int session = ProcessManager.CurrentSessionId;

            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        // Only apps in the signed-in user's session; services live in session 0.
                        if (p.SessionId != session || p.Id == Environment.ProcessId) continue;
                        seen.Add(p.Id);

                        double cpu = 0;
                        try
                        {
                            var t = p.TotalProcessorTime;
                            if (last.TryGetValue(p.Id, out var prev))
                            {
                                double wall = (now - prev.at).TotalMilliseconds;
                                // Max(0): a reused PID can report less CPU time than the old process had.
                                if (wall > 0) cpu = Math.Max(0, (t - prev.cpu).TotalMilliseconds / wall / Environment.ProcessorCount * 100);
                            }
                            last[p.Id] = (t, now);
                        }
                        catch { /* protected process */ }

                        string name = p.ProcessName;
                        if (!details.ContainsKey(name))
                        {
                            string? path = null, desc = null;
                            try
                            {
                                path = p.MainModule?.FileName;
                                desc = p.MainModule?.FileVersionInfo.FileDescription;
                            }
                            catch { }
                            details[name] = (path, desc);
                        }

                        if (!groups.TryGetValue(name, out var g)) g = (new List<int>(), 0L, 0d);
                        g.pids.Add(p.Id);
                        g.ram += p.WorkingSet64;
                        g.cpu += cpu;
                        groups[name] = g;
                    }
                    catch { /* process exited mid-read */ }
                }
            }

            foreach (var gone in last.Keys.Where(k => !seen.Contains(k)).ToList()) last.Remove(gone);

            return groups
                .Select(kv =>
                {
                    details.TryGetValue(kv.Key, out var d);
                    string? path = d.path, desc = d.description;
                    string display = string.IsNullOrWhiteSpace(desc) ? kv.Key : desc!.Trim();
                    return new AppProcessGroup(kv.Key, display, kv.Value.pids.Count,
                        Math.Round(kv.Value.ram / 1048576.0), Math.Round(Math.Min(kv.Value.cpu, 100), 1),
                        path, IconService.GetDataUrl(path), ProcessManager.IsProtected(kv.Key));
                })
                .OrderByDescending(a => a.RamMb)
                .Take(max)
                .ToList();
        }
    }
}

public static class ProcessManager
{
    public static readonly int CurrentSessionId = Process.GetCurrentProcess().SessionId;
    static readonly string SelfName = Process.GetCurrentProcess().ProcessName;

    // Ending any of these would crash or destabilize Windows (or this app's own window).
    static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "LsaIso",
        "svchost", "dwm", "explorer", "fontdrvhost", "sihost", "ctfmon", "taskhostw", "RuntimeBroker",
        "StartMenuExperienceHost", "ShellExperienceHost", "SearchHost", "SearchApp", "TextInputHost",
        "ApplicationFrameHost", "SecurityHealthSystray", "msedgewebview2", "conhost", "audiodg",
        "Memory Compression", "Secure System", "dllhost", "SystemSettingsBroker", "LockApp", "WUDFHost", "LogonUI", "ShellHost",
    };

    public static bool IsProtected(string name) =>
        ProtectedNames.Contains(name) || name.Equals(SelfName, StringComparison.OrdinalIgnoreCase);

    /// <summary>Force-closes every process of an app in the user's session.</summary>
    public static EndResult EndApp(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) throw new ArgumentException("No app was given.");
        if (IsProtected(name)) throw new InvalidOperationException($"{name} is part of Windows and can't be closed here.");

        int ended = 0, failed = 0;
        foreach (var p in Process.GetProcessesByName(name))
        {
            using (p)
            {
                try
                {
                    if (p.SessionId != CurrentSessionId || p.Id == Environment.ProcessId) continue;
                    p.Kill();
                    ended++;
                }
                catch { failed++; }
            }
        }

        string message = ended == 0 && failed == 0 ? $"{name} had already closed."
            : failed == 0 ? $"Closed {name}."
            : $"Closed {ended} of {ended + failed} {name} processes. The rest refused to close.";
        return new EndResult(ended, failed, message);
    }
}

public static class MemoryOptimizer
{
    /// <summary>
    /// Trimming these makes things worse: the screen compositor and audio stutter, typing lags, or Windows simply
    /// refuses. They're left alone.
    /// </summary>
    static readonly HashSet<string> Skip = new(StringComparer.OrdinalIgnoreCase)
    {
        "System", "Idle", "Registry", "Memory Compression", "Secure System", "smss", "csrss", "wininit", "winlogon",
        "services", "lsass", "LsaIso", "dwm", "audiodg", "fontdrvhost", "MsMpEng", "NisSrv", "MpDefenderCoreService",
        "ctfmon", "TextInputHost", "explorer", "StartMenuExperienceHost", "ShellExperienceHost", "SearchHost",
    };

    static readonly object gate = new();
    static DateTime lastRun = DateTime.MinValue;

    /// <summary>
    /// Trims the memory of background apps so Windows has more free right away, and drops the low-priority part of
    /// the standby cache (files Windows guessed you might open, not ones you're using). Never touches the app in
    /// front, the game Game Mode is looking after, audio or the screen compositor.
    /// Windows refills all of this as needed, so it helps most when memory is nearly full, right before starting
    /// something heavy.
    /// </summary>
    public static MemoryResult Optimize(int alsoSkipPid = 0)
    {
        lock (gate)
        {
            if (DateTime.UtcNow - lastRun < TimeSpan.FromSeconds(10))
            {
                ulong avail = Native.GetMemory().ullAvailPhys;
                return new MemoryResult(0, 0, false, Math.Round(avail / 1048576.0), "Just freed");
            }

            ulong before = Native.GetMemory().ullAvailPhys;
            int foreground = Native.GetForegroundProcessId();
            string? foregroundName = NameOf(foreground);
            string? gameName = NameOf(alsoSkipPid);
            int trimmed = 0;

            foreach (var p in Process.GetProcesses())
            {
                using (p)
                {
                    try
                    {
                        if (p.Id <= 4 || p.Id == Environment.ProcessId || p.Id == foreground || p.Id == alsoSkipPid) continue;
                        string name = p.ProcessName;
                        if (Skip.Contains(name)) continue;
                        // The app in front and its helper processes (browser tabs, game launchers' renderers).
                        if (foregroundName is not null && name.Equals(foregroundName, StringComparison.OrdinalIgnoreCase)) continue;
                        if (gameName is not null && name.Equals(gameName, StringComparison.OrdinalIgnoreCase)) continue;
                        // Not worth it for small processes; trimming them only costs page faults later.
                        if (p.WorkingSet64 < 24L * 1024 * 1024) continue;
                        // Apps that asked for high priority (audio tools, streaming) are left as they are.
                        var prio = p.PriorityClass;
                        if (prio is ProcessPriorityClass.High or ProcessPriorityClass.RealTime) continue;
                        if (Native.EmptyWorkingSet(p.Handle)) trimmed++;
                    }
                    catch { /* no access to this process, or it exited */ }
                }
            }

            bool standby = Native.PurgeLowPriorityStandby();
            Thread.Sleep(300); // let Windows move the trimmed pages to its free lists before measuring
            ulong after = Native.GetMemory().ullAvailPhys;
            lastRun = DateTime.UtcNow;
            double freed = after > before ? (after - before) / 1048576.0 : 0;
            return new MemoryResult(Math.Round(freed), trimmed, standby, Math.Round(after / 1048576.0), null);
        }
    }

    static string? NameOf(int pid)
    {
        if (pid <= 4) return null;
        try
        {
            using var p = Process.GetProcessById(pid);
            string n = p.ProcessName;
            return Skip.Contains(n) ? null : n;
        }
        catch { return null; }
    }
}
