using System.Diagnostics;

namespace SystemForge;

public record JunkCategory(string Id, string Name, string Description, bool DefaultOn, long Bytes, int Files);
public record CleanResult(long FreedBytes, int Deleted, int Skipped);
public record JunkFile(string Path, string Name, long Bytes, DateTime Modified, string? Origin);
public record JunkFilePage(string Id, int Total, long TotalBytes, int Offset, List<JunkFile> Files, bool CanExclude);

/// <summary>
/// Finds and removes files Windows and apps leave behind. It only ever looks inside the specific folders below,
/// never follows shortcuts or junctions out of them, and skips anything in use.
/// </summary>
public static class JunkCleaner
{
    sealed record Def(string Id, string Name, string Description, bool DefaultOn, double MinAgeHours,
        Func<IEnumerable<string>> Roots, bool RecycleBin = false);

    static string Local => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    static string Windir => Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    static string ProgramData => Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);

    static readonly Def[] Defs =
    {
        new("temp-user", "Your temporary files",
            "Leftovers from installers and apps. Files changed in the last day are kept in case something still needs them.",
            true, 24, UserTemp),

        new("temp-windows", "Windows temporary files",
            "System leftovers in the Windows Temp folder. Recent files are kept.",
            true, 24, () => new[] { Path.Combine(Windir, "Temp") }),

        new("update-cache", "Windows Update downloads",
            "Installer files for updates that are already installed.",
            true, 24, () => new[] { Path.Combine(Windir, "SoftwareDistribution", "Download") }),

        new("delivery-optimization", "Delivery Optimization cache",
            "Update pieces Windows keeps to share with other PCs.",
            true, 0, () => new[] { Path.Combine(Windir, @"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache") }),

        new("crash-reports", "Crash dumps and error reports",
            "Memory dumps and reports from apps that crashed. Only useful if you're debugging a crash.",
            true, 0, () => new[]
            {
                Path.Combine(Local, "CrashDumps"),
                Path.Combine(Windir, "Minidump"),
                Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportArchive"),
                Path.Combine(ProgramData, @"Microsoft\Windows\WER\ReportQueue"),
            }),

        new("browser-cache", "Browser caches",
            "Saved copies of web pages and images. Your logins, history and cookies aren't touched. Close your browser first for the best result.",
            true, 0, BrowserCaches),

        new("shader-cache", "Game shader caches",
            "Compiled graphics shaders. Games rebuild them on next launch, which can cause a little stutter at first. Worth clearing after a graphics driver update.",
            false, 0, () => new[]
            {
                Path.Combine(Local, "D3DSCache"),
                Path.Combine(Local, @"NVIDIA\DXCache"),
                Path.Combine(Local, @"NVIDIA\GLCache"),
                Path.Combine(Local, @"AMD\DxCache"),
                Path.Combine(Local, @"AMD\DxcCache"),
                Path.Combine(Local, @"AMD\VkCache"),
            }),

        new("recycle-bin", "Recycle Bin",
            "Files you've deleted. Emptying it removes them for good.",
            false, 0, () => Array.Empty<string>(), RecycleBin: true),
    };

    /// <summary>
    /// The user's temp folder, but only if it really looks like one. A misconfigured TEMP/TMP variable
    /// (e.g. pointing at the profile or System32) must never turn into "delete everything older than a day".
    /// </summary>
    static IEnumerable<string> UserTemp()
    {
        string path;
        try { path = Path.GetTempPath(); } catch { return Array.Empty<string>(); }
        bool looksLikeTemp = path.Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries)
            .Any(s => s.Equals("Temp", StringComparison.OrdinalIgnoreCase) || s.Equals("Tmp", StringComparison.OrdinalIgnoreCase));
        return looksLikeTemp ? new[] { path } : Array.Empty<string>();
    }

    /// <summary>Folders that a cleanup root must never be, or contain.</summary>
    static IEnumerable<string> CriticalFolders() =>
        new[]
        {
            Environment.SpecialFolder.Windows, Environment.SpecialFolder.System, Environment.SpecialFolder.SystemX86,
            Environment.SpecialFolder.ProgramFiles, Environment.SpecialFolder.ProgramFilesX86,
            Environment.SpecialFolder.UserProfile, Environment.SpecialFolder.ApplicationData,
            Environment.SpecialFolder.LocalApplicationData, Environment.SpecialFolder.CommonApplicationData,
            Environment.SpecialFolder.Desktop, Environment.SpecialFolder.MyDocuments,
        }
        .Select(f => Environment.GetFolderPath(f))
        .Where(p => !string.IsNullOrWhiteSpace(p))
        .Select(p => p.TrimEnd('\\'));

    static IEnumerable<string> BrowserCaches()
    {
        string[] chromium =
        {
            @"Google\Chrome\User Data", @"Microsoft\Edge\User Data",
            @"BraveSoftware\Brave-Browser\User Data", @"Vivaldi\User Data",
        };
        foreach (var c in chromium)
        {
            foreach (var profile in SafeSubdirs(Path.Combine(Local, c)))
            {
                yield return Path.Combine(profile, "Cache");
                yield return Path.Combine(profile, "Code Cache");
                yield return Path.Combine(profile, "GPUCache");
            }
        }
        yield return Path.Combine(Local, @"Opera Software\Opera Stable\Cache");
        yield return Path.Combine(Local, @"Opera Software\Opera GX Stable\Cache");
        foreach (var profile in SafeSubdirs(Path.Combine(Local, @"Mozilla\Firefox\Profiles")))
            yield return Path.Combine(profile, "cache2");
    }

    /// <summary>The files found by the last scan, per category, so "View files" pages through them without rescanning.</summary>
    static readonly Dictionary<string, List<JunkFile>> Cache = new();
    static readonly object CacheGate = new();

    public static List<JunkCategory> Scan()
    {
        var result = new List<JunkCategory>();
        foreach (var d in Defs)
        {
            var files = Collect(d);
            lock (CacheGate) Cache[d.Id] = files;
            result.Add(new JunkCategory(d.Id, d.Name, d.Description, d.DefaultOn, files.Sum(f => f.Bytes), files.Count));
        }
        return result;
    }

    /// <summary>One page of a category's files for the "View files" list, filtered and sorted.</summary>
    public static JunkFilePage Files(string id, int offset, int limit, string query, string sort)
    {
        var d = Defs.FirstOrDefault(x => x.Id == id) ?? throw new ArgumentException("Unknown category.");
        List<JunkFile>? all;
        lock (CacheGate) Cache.TryGetValue(id, out all);
        if (all is null)
        {
            all = Collect(d);
            lock (CacheGate) Cache[id] = all;
        }

        IEnumerable<JunkFile> q = all;
        if (!string.IsNullOrWhiteSpace(query))
            q = q.Where(f => f.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                             f.Path.Contains(query, StringComparison.OrdinalIgnoreCase) ||
                             (f.Origin?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false));
        q = sort switch
        {
            "name" => q.OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase),
            "oldest" => q.OrderBy(f => f.Modified),
            "newest" => q.OrderByDescending(f => f.Modified),
            "folder" => q.OrderBy(f => f.Origin ?? Path.GetDirectoryName(f.Path), StringComparer.OrdinalIgnoreCase).ThenBy(f => f.Name),
            _ => q.OrderByDescending(f => f.Bytes),
        };
        var list = q.ToList();
        limit = Math.Clamp(limit, 1, 1000);
        offset = Math.Clamp(offset, 0, list.Count);
        return new JunkFilePage(id, list.Count, list.Sum(f => f.Bytes), offset, list.Skip(offset).Take(limit).ToList(), CanExclude: true);
    }

    /// <summary>Opens Explorer with the file selected. Only for files the last scan found.</summary>
    public static object Reveal(string path)
    {
        bool known;
        lock (CacheGate) known = Cache.Values.Any(l => l.Any(f => f.Path.Equals(path, StringComparison.OrdinalIgnoreCase)));
        if (!known) throw new ArgumentException("That file isn't in the cleanup list any more. Scan again.");
        if (IsInRecycleBin(path))
            Process.Start(new ProcessStartInfo("explorer.exe", "shell:RecycleBinFolder") { UseShellExecute = true });
        else if (File.Exists(path) || Directory.Exists(path))
            Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{path}\"") { UseShellExecute = true });
        else throw new InvalidOperationException("That file is already gone.");
        return new { ok = true };
    }

    static List<JunkFile> Collect(Def d)
    {
        if (d.RecycleBin) return RecycleBinItems();
        var list = new List<JunkFile>();
        foreach (var f in EligibleFiles(d))
        {
            try { list.Add(new JunkFile(f.FullName, f.Name, f.Length, f.LastWriteTime, null)); }
            catch { /* vanished while scanning */ }
        }
        return list;
    }

    /// <param name="exclude">Full paths the user unticked in "View files"; these are always left alone.</param>
    public static CleanResult Clean(IEnumerable<string> ids, IEnumerable<string>? exclude = null)
    {
        var chosen = new HashSet<string>(ids);
        var keep = new HashSet<string>(exclude ?? Array.Empty<string>(), StringComparer.OrdinalIgnoreCase);
        long freed = 0; int deleted = 0, skipped = 0;

        foreach (var d in Defs.Where(d => chosen.Contains(d.Id)))
        {
            if (d.RecycleBin)
            {
                var items = RecycleBinItems();
                if (items.Count == 0) continue;
                if (!items.Any(i => keep.Contains(i.Path)))
                {
                    // Nothing excluded: let Windows empty the whole bin (all drives, all users' own bins).
                    var info = QueryRecycleBin();
                    if (Native.SHEmptyRecycleBin(IntPtr.Zero, null,
                            Native.SHERB_NOCONFIRMATION | Native.SHERB_NOPROGRESSUI | Native.SHERB_NOSOUND) == 0)
                    {
                        freed += info.i64Size;
                        deleted += (int)info.i64NumItems;
                    }
                    continue;
                }
                // Some items kept: delete the rest one by one ($R data file plus its $I info file).
                foreach (var item in items.Where(i => !keep.Contains(i.Path)))
                {
                    if (DeleteRecycledItem(item.Path)) { freed += item.Bytes; deleted++; }
                    else skipped++;
                }
                continue;
            }

            foreach (var f in EligibleFiles(d).ToList())
            {
                if (keep.Contains(f.FullName)) continue;
                long len = SafeLength(f);
                try
                {
                    if (f.IsReadOnly) f.IsReadOnly = false;
                    f.Delete();
                    freed += len;
                    deleted++;
                }
                catch { skipped++; /* in use or protected */ }
            }

            foreach (var root in SafeRoots(d)) RemoveEmptyFolders(root);
        }

        lock (CacheGate) Cache.Clear();
        return new CleanResult(freed, deleted, skipped);
    }

    // ---- Recycle Bin ----

    /// <summary>What's in the Recycle Bin, with each item's original name and folder (via the Shell, on an STA thread).</summary>
    static List<JunkFile> RecycleBinItems() => RunSta(() =>
    {
        var list = new List<JunkFile>();
        try
        {
            var type = Type.GetTypeFromProgID("Shell.Application");
            if (type is null) return list;
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic? bin = shell.NameSpace(10); // ssfBITBUCKET
            if (bin is null) return list;
            dynamic items = bin.Items();
            int count = items.Count;
            for (int i = 0; i < count; i++)
            {
                try
                {
                    dynamic item = items.Item(i);
                    string path = item.Path;
                    if (!IsInRecycleBin(path)) continue;
                    string name = item.Name;
                    string ext = Path.GetExtension(path);
                    if (Path.GetExtension(name).Length == 0 && ext.Length > 0) name += ext; // Explorer may hide extensions
                    string? origin = null;
                    try { origin = item.ExtendedProperty("System.Recycle.DeletedFrom") as string; } catch { }
                    DateTime modified = DateTime.MinValue;
                    try { modified = (DateTime)item.ModifyDate; } catch { }
                    list.Add(new JunkFile(path, name, SizeOnDisk(path), modified, origin));
                }
                catch { /* skip unreadable item */ }
            }
        }
        catch { /* shell unavailable */ }
        return list;
    });

    static bool IsInRecycleBin(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        var full = Path.GetFullPath(path);
        var root = Path.GetPathRoot(full) ?? "";
        return full.StartsWith(Path.Combine(root, "$Recycle.Bin") + "\\", StringComparison.OrdinalIgnoreCase)
               && Path.GetFileName(full).StartsWith("$R", StringComparison.OrdinalIgnoreCase);
    }

    static long SizeOnDisk(string path)
    {
        try
        {
            if (File.Exists(path)) return new FileInfo(path).Length;
            if (Directory.Exists(path))
                return new DirectoryInfo(path).EnumerateFiles("*", Walk).Sum(f => SafeLength(f));
        }
        catch { }
        return 0;
    }

    static bool DeleteRecycledItem(string dataPath)
    {
        if (!IsInRecycleBin(dataPath)) return false;
        try
        {
            var dir = Path.GetDirectoryName(dataPath)!;
            var infoPath = Path.Combine(dir, "$I" + Path.GetFileName(dataPath)[2..]);
            if (Directory.Exists(dataPath))
            {
                // Never follow a junction out of the bin: delete links without descending into them.
                var di = new DirectoryInfo(dataPath);
                if (di.Attributes.HasFlag(FileAttributes.ReparsePoint)) di.Delete();
                else DeleteTree(di);
            }
            else if (File.Exists(dataPath))
            {
                var fi = new FileInfo(dataPath);
                if (fi.IsReadOnly) fi.IsReadOnly = false;
                fi.Delete();
            }
            if (File.Exists(infoPath)) File.Delete(infoPath);
            return true;
        }
        catch { return false; }
    }

    static void DeleteTree(DirectoryInfo dir)
    {
        foreach (var sub in dir.EnumerateDirectories())
        {
            if (sub.Attributes.HasFlag(FileAttributes.ReparsePoint)) sub.Delete();
            else DeleteTree(sub);
        }
        foreach (var f in dir.EnumerateFiles())
        {
            if (f.IsReadOnly) f.IsReadOnly = false;
            f.Delete();
        }
        dir.Delete();
    }

    static T RunSta<T>(Func<T> work)
    {
        T result = default!;
        Exception? error = null;
        var thread = new Thread(() => { try { result = work(); } catch (Exception ex) { error = ex; } });
        thread.SetApartmentState(ApartmentState.STA);
        thread.IsBackground = true;
        thread.Start();
        thread.Join();
        if (error is not null) throw error;
        return result;
    }

    // ---- helpers ----

    static readonly EnumerationOptions Walk = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        AttributesToSkip = FileAttributes.ReparsePoint, // never follow junctions/symlinks out of the folder
    };

    static IEnumerable<string> SafeRoots(Def d) =>
        d.Roots()
            .Where(IsSafeRoot)
            .Select(r => Path.GetFullPath(r))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(Directory.Exists);

    /// <summary>Guards against an empty environment variable turning a path into a drive root or relative path.</summary>
    static bool IsSafeRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) return false;
        var full = Path.GetFullPath(path).TrimEnd('\\');
        var root = (Path.GetPathRoot(full) ?? "").TrimEnd('\\');
        if (!(full.Length > root.Length + 3 && full.Count(c => c == '\\') >= 2)) return false;
        // Never clean a well-known folder itself, or any parent of one.
        foreach (var critical in CriticalFolders())
        {
            if (critical.Equals(full, StringComparison.OrdinalIgnoreCase) ||
                critical.StartsWith(full + "\\", StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    static IEnumerable<FileInfo> EligibleFiles(Def d)
    {
        DateTime cutoff = DateTime.UtcNow.AddHours(-d.MinAgeHours);
        foreach (var root in SafeRoots(d))
        {
            IEnumerable<FileInfo> files;
            try { files = new DirectoryInfo(root).EnumerateFiles("*", Walk); }
            catch { continue; }

            foreach (var f in files)
            {
                bool keep;
                try { keep = d.MinAgeHours > 0 && f.LastWriteTimeUtc > cutoff; }
                catch { continue; }
                if (!keep) yield return f;
            }
        }
    }

    static void RemoveEmptyFolders(string root)
    {
        try
        {
            var dirs = new DirectoryInfo(root).EnumerateDirectories("*", Walk)
                .OrderByDescending(x => x.FullName.Length)
                .ToList();
            foreach (var dir in dirs)
            {
                try { if (!dir.EnumerateFileSystemInfos().Any()) dir.Delete(); } catch { }
            }
        }
        catch { }
    }

    static IEnumerable<string> SafeSubdirs(string path)
    {
        try { return Directory.Exists(path) ? Directory.GetDirectories(path) : Array.Empty<string>(); }
        catch { return Array.Empty<string>(); }
    }

    static long SafeLength(FileInfo f)
    {
        try { return f.Length; } catch { return 0; }
    }

    static Native.SHQUERYRBINFO QueryRecycleBin()
    {
        var info = new Native.SHQUERYRBINFO { cbSize = System.Runtime.InteropServices.Marshal.SizeOf<Native.SHQUERYRBINFO>() };
        Native.SHQueryRecycleBin(null, ref info);
        return info;
    }
}
