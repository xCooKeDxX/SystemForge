using System.Runtime.InteropServices;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace SystemForge;

public sealed record AppUpdate(string Id, string Name, string Version, string Available, bool Ignored, bool Skipped);
public sealed record AppProgram(string Name, string Id, string Version, string Source, bool HasUpdate, bool Ignored);
public sealed record AppCheck(List<AppUpdate> Updates, List<AppProgram> Programs, DateTime CheckedAt);

/// <summary>Updates for installed programs, through winget. Game runtimes are left to the Drivers page.</summary>
public static class AppUpdates
{
    static readonly SemaphoreSlim Busy = new(1, 1);
    public static AppCheck? Last { get; private set; }

    public static async Task<AppCheck> CheckAsync(AppSettings settings, CancellationToken ct = default)
    {
        await Busy.WaitAsync(ct);
        try
        {
            var ignored = new HashSet<string>(settings.IgnoredApps, StringComparer.OrdinalIgnoreCase);
            var upgrades = await Winget.UpgradesAsync(ct);
            var installed = await Winget.InstalledAsync(ct);

            var updates = upgrades
                .Where(p => !p.Truncated && !DriverUpdates.IsRuntime(p.Id))
                .GroupBy(p => p.Id, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
                .Select(p => new AppUpdate(p.Id, p.Name.TrimEnd('…'), p.Version, p.Available,
                    ignored.Contains(p.Id),
                    settings.SkippedVersions.TryGetValue(p.Id, out var skip) && skip == p.Available))
                .OrderBy(u => u.Ignored || u.Skipped).ThenBy(u => u.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var withUpdate = new HashSet<string>(updates.Select(u => u.Id), StringComparer.OrdinalIgnoreCase);
            var programs = installed
                .Where(p => !DriverUpdates.IsRuntime(p.Id))
                .GroupBy(p => p.Id, StringComparer.OrdinalIgnoreCase).Select(g => g.First())
                .Select(p => new AppProgram(p.Name.TrimEnd('…'), p.Id, p.Version, p.Source, withUpdate.Contains(p.Id), ignored.Contains(p.Id)))
                .OrderBy(p => p.Name, StringComparer.OrdinalIgnoreCase)
                .ToList();

            settings.LastAppCheckUtc = DateTime.UtcNow;
            settings.Save();
            return Last = new AppCheck(updates, programs, DateTime.Now);
        }
        finally { Busy.Release(); }
    }

    public static AppSettings Ignore(AppSettings s, string id, bool ignore)
    {
        s.IgnoredApps.RemoveAll(x => x.Equals(id, StringComparison.OrdinalIgnoreCase));
        if (ignore) s.IgnoredApps.Add(id);
        s.Save();
        return s;
    }

    public static AppSettings Skip(AppSettings s, string id, string version)
    {
        if (version.Length == 0) s.SkippedVersions.Remove(id);
        else s.SkippedVersions[id] = version;
        s.Save();
        return s;
    }

    public static async Task<List<InstallItemResult>> InstallAsync(IReadOnlyList<string> ids, Action<string, int, int, string, int> progress, CancellationToken ct = default)
    {
        var results = new List<InstallItemResult>();
        var names = Last?.Updates.ToDictionary(u => u.Id, u => u.Name, StringComparer.OrdinalIgnoreCase) ?? new();
        for (int i = 0; i < ids.Count; i++)
        {
            string id = ids[i];
            string name = names.GetValueOrDefault(id, id);
            int index = i + 1;
            progress("Starting", index, ids.Count, name, -1);
            try
            {
                var (ok, message, _) = await Winget.InstallAsync(id, install: false, (phase, pct) => progress(phase, index, ids.Count, name, pct), ct);
                results.Add(new InstallItemResult(id, name, ok, message));
            }
            catch (Exception ex) { results.Add(new InstallItemResult(id, name, false, ex.Message)); }
        }
        return results;
    }

    /// <summary>Display names of everything in Windows' installed-programs list (for spotting new installs).</summary>
    public static HashSet<string> InstalledNames()
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, view, path) in InstallWatcher.Keys)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, view);
                using var key = root.OpenSubKey(path);
                if (key is null) continue;
                foreach (var sub in key.GetSubKeyNames())
                {
                    try
                    {
                        using var k = key.OpenSubKey(sub);
                        if (k?.GetValue("DisplayName") is string n && n.Trim().Length > 0 && k.GetValue("SystemComponent") is not 1)
                            names.Add(n.Trim());
                    }
                    catch { }
                }
            }
            catch { }
        }
        return names;
    }
}

/// <summary>
/// Watches Windows' installed-programs lists and raises <see cref="Changed"/> shortly after something is installed
/// or removed (debounced, since installers write many values).
/// </summary>
public sealed class InstallWatcher : IDisposable
{
    public static readonly (RegistryHive hive, RegistryView view, string path)[] Keys =
    {
        (RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (RegistryHive.CurrentUser, RegistryView.Default, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    };

    public event Action? Changed;

    readonly ManualResetEvent stop = new(false);
    readonly Thread thread;
    readonly System.Threading.Timer debounce;

    public InstallWatcher()
    {
        debounce = new System.Threading.Timer(_ => Changed?.Invoke(), null, Timeout.Infinite, Timeout.Infinite);
        thread = new Thread(Loop) { IsBackground = true, Name = "SystemForge install watcher" };
        thread.Start();
    }

    void Loop()
    {
        var opened = new List<(RegistryKey root, RegistryKey key, AutoResetEvent evt)>();
        try
        {
            foreach (var (hive, view, path) in Keys)
            {
                try
                {
                    var root = RegistryKey.OpenBaseKey(hive, view);
                    var key = root.OpenSubKey(path);
                    if (key is null) { root.Dispose(); continue; }
                    var evt = new AutoResetEvent(false);
                    if (Arm(key, evt)) opened.Add((root, key, evt));
                    else { key.Dispose(); root.Dispose(); evt.Dispose(); }
                }
                catch { }
            }
            if (opened.Count == 0) return;

            var handles = opened.Select(o => (WaitHandle)o.evt).Append(stop).ToArray();
            while (true)
            {
                int hit = WaitHandle.WaitAny(handles);
                if (hit == handles.Length - 1) return; // stop
                if (stop.WaitOne(0)) return;
                Arm(opened[hit].key, opened[hit].evt);
                try { debounce.Change(TimeSpan.FromSeconds(20), Timeout.InfiniteTimeSpan); }
                catch (ObjectDisposedException) { return; } // shutting down
            }
        }
        finally
        {
            foreach (var (root, key, evt) in opened) { key.Dispose(); root.Dispose(); evt.Dispose(); }
        }
    }

    static bool Arm(RegistryKey key, AutoResetEvent evt) =>
        RegNotifyChangeKeyValue(key.Handle, true, REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET,
            evt.SafeWaitHandle, true) == 0;

    public void Dispose()
    {
        stop.Set();
        thread.Join(TimeSpan.FromSeconds(2)); // let the loop see "stop" before the timer goes away
        debounce.Dispose();
    }

    const uint REG_NOTIFY_CHANGE_NAME = 0x1, REG_NOTIFY_CHANGE_LAST_SET = 0x4;

    [DllImport("advapi32.dll")]
    static extern int RegNotifyChangeKeyValue(SafeRegistryHandle hKey, bool watchSubtree, uint notifyFilter, SafeWaitHandle hEvent, bool asynchronous);
}
