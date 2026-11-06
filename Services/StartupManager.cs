using System.Diagnostics;
using Microsoft.Win32;

namespace SystemForge;

public record StartupItem(string Id, string Name, string Publisher, string Command, string Location, string Scope,
    bool Enabled, string? Icon);

/// <summary>
/// Lists and toggles apps that launch at sign-in. Uses the same "StartupApproved" switches as Task Manager,
/// so nothing gets deleted and everything can be turned back on there too.
/// </summary>
public static class StartupManager
{
    const string ApprovedBase = @"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\";

    sealed record Source(string Key, RegistryKey Hive, string? RunPath, Func<string>? Folder, string ApprovedPath,
        string Location, string Scope);

    static readonly Source[] Sources =
    {
        new("hkcu-run", Registry.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run", null,
            ApprovedBase + "Run", "Registry", "Just you"),
        new("hklm-run", Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", null,
            ApprovedBase + "Run", "Registry", "Everyone on this PC"),
        new("hklm-run32", Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", null,
            ApprovedBase + "Run32", "Registry", "Everyone on this PC"),
        new("user-folder", Registry.CurrentUser, null, () => Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            ApprovedBase + "StartupFolder", "Startup folder", "Just you"),
        new("common-folder", Registry.LocalMachine, null, () => Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
            ApprovedBase + "StartupFolder", "Startup folder", "Everyone on this PC"),
    };

    public static List<StartupItem> List()
    {
        var items = new List<StartupItem>();
        foreach (var s in Sources)
        {
            foreach (var (valueName, command, target) in Entries(s))
            {
                string? exe = target ?? ExtractExe(command);
                string name = Path.GetFileNameWithoutExtension(valueName);
                string publisher = "";
                try
                {
                    if (exe is not null && File.Exists(exe))
                    {
                        var vi = FileVersionInfo.GetVersionInfo(exe);
                        if (!string.IsNullOrWhiteSpace(vi.FileDescription)) name = vi.FileDescription.Trim();
                        publisher = vi.CompanyName?.Trim() ?? "";
                    }
                }
                catch { }

                items.Add(new StartupItem($"{s.Key}|{valueName}", name, publisher, command, s.Location, s.Scope,
                    IsEnabled(s, valueName), IconService.GetDataUrl(exe)));
            }
        }
        return items.OrderBy(i => i.Name, StringComparer.CurrentCultureIgnoreCase).ToList();
    }

    public static object SetEnabled(string id, bool enabled)
    {
        var (source, valueName) = Resolve(id);
        // Only write switches for entries that actually exist in that source.
        if (!Entries(source).Any(e => e.valueName == valueName)) throw new ArgumentException("Unknown startup item.");
        using var key = source.Hive.CreateSubKey(source.ApprovedPath, true);
        var data = new byte[12];
        data[0] = enabled ? (byte)0x02 : (byte)0x03;
        if (!enabled) BitConverter.GetBytes(DateTime.UtcNow.ToFileTimeUtc()).CopyTo(data, 4);
        key.SetValue(valueName, data, RegistryValueKind.Binary);
        return new { id, enabled };
    }

    public static object Reveal(string id)
    {
        var (source, valueName) = Resolve(id);
        var entry = Entries(source).FirstOrDefault(e => e.valueName == valueName);
        string? path = entry.target ?? ExtractExe(entry.command ?? "");
        if (path is null || !File.Exists(path)) throw new InvalidOperationException("Couldn't find where this app is installed.");
        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        return new { ok = true };
    }

    // ---- helpers ----

    static IEnumerable<(string valueName, string command, string? target)> Entries(Source s)
    {
        var list = new List<(string, string, string?)>();
        try
        {
            if (s.RunPath is not null)
            {
                using var key = s.Hive.OpenSubKey(s.RunPath);
                if (key is null) return list;
                foreach (var name in key.GetValueNames())
                {
                    if (string.IsNullOrEmpty(name)) continue;
                    if (key.GetValue(name) is string cmd && cmd.Length > 0) list.Add((name, cmd, null));
                }
            }
            else if (s.Folder is not null)
            {
                var folder = s.Folder();
                if (!Directory.Exists(folder)) return list;
                foreach (var file in Directory.GetFiles(folder))
                {
                    var fileName = Path.GetFileName(file);
                    if (fileName.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                    string? target = fileName.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase) ? ResolveShortcut(file) : file;
                    list.Add((fileName, target ?? file, target));
                }
            }
        }
        catch { /* unreadable source */ }
        return list;
    }

    static bool IsEnabled(Source s, string valueName)
    {
        try
        {
            using var key = s.Hive.OpenSubKey(s.ApprovedPath);
            if (key?.GetValue(valueName) is byte[] b && b.Length > 0) return (b[0] & 1) == 0;
        }
        catch { }
        return true;
    }

    static (Source source, string valueName) Resolve(string id)
    {
        int bar = id?.IndexOf('|') ?? -1;
        if (bar <= 0) throw new ArgumentException("Unknown startup item.");
        var source = Sources.FirstOrDefault(s => s.Key == id![..bar]) ?? throw new ArgumentException("Unknown startup item.");
        return (source, id![(bar + 1)..]);
    }

    static string? ExtractExe(string command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        var c = Environment.ExpandEnvironmentVariables(command.Trim());
        if (c.StartsWith('"'))
        {
            int end = c.IndexOf('"', 1);
            return end > 1 ? c[1..end] : null;
        }
        int exe = c.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? c[..(exe + 4)] : c.Split(' ')[0];
    }

    static string? ResolveShortcut(string lnk)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return null;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic shortcut = shell.CreateShortcut(lnk);
            string target = shortcut.TargetPath;
            return string.IsNullOrWhiteSpace(target) ? null : target;
        }
        catch { return null; }
    }
}

/// <summary>Starts SystemForge at sign-in via a scheduled task, so it can run as admin without a UAC prompt each boot.</summary>
public static class AutoStart
{
    const string TaskName = "SystemForge";

    public static bool IsEnabled() => Run("/Query", "/TN", TaskName) == 0;

    public static void Set(bool on)
    {
        int code = on
            ? Run("/Create", "/TN", TaskName, "/TR", $"\"{Environment.ProcessPath}\" --tray",
                  "/SC", "ONLOGON", "/RL", "HIGHEST", "/DELAY", "0000:15", "/F")
            : Run("/Delete", "/TN", TaskName, "/F");
        if (code != 0 && on) throw new InvalidOperationException("Windows didn't accept the startup task.");
    }

    static int Run(params string[] args)
    {
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "schtasks.exe"))
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        // Drain both pipes at once so a full stderr buffer can't block schtasks while we wait on stdout.
        p.OutputDataReceived += (_, _) => { };
        p.ErrorDataReceived += (_, _) => { };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();
        if (!p.WaitForExit(30_000))
        {
            try { p.Kill(); } catch { }
            return -1;
        }
        p.WaitForExit(); // flush the async readers
        return p.ExitCode;
    }
}
