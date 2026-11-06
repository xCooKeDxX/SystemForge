using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace SystemForge;

/// <summary>A program winget knows about. Available is empty when it's up to date.</summary>
public sealed record WingetPackage(string Name, string Id, string Version, string Available, string Source)
{
    /// <summary>winget shortens long names/ids with "…" when its table is too wide; a cut-off id can't be targeted.</summary>
    public bool Truncated => Id.EndsWith('…');
    public bool HasUpdate => Available.Length > 0;
}

/// <summary>
/// Windows Package Manager (winget), built into Windows 10 1809+ and Windows 11. It matches installed programs
/// against its catalog, downloads installers from the publisher's own links and checks each one against the
/// SHA-256 hash recorded in the catalog before running it.
/// </summary>
public static partial class Winget
{
    static readonly string[] Agree = { "--accept-source-agreements", "--disable-interactivity" };

    public static string? FindExe()
    {
        var local = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Microsoft\WindowsApps\winget.exe");
        if (File.Exists(local)) return local;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            try { var p = Path.Combine(dir.Trim(), "winget.exe"); if (File.Exists(p)) return p; } catch { }
        }
        return null;
    }

    public static bool IsAvailable => FindExe() is not null;

    /// <summary>Programs with an update available (winget upgrade).</summary>
    public static async Task<List<WingetPackage>> UpgradesAsync(CancellationToken ct)
    {
        var (code, output) = await RunAsync(ct, null, new[] { "upgrade", "--include-unknown" }.Concat(Agree).ToArray());
        var list = ParseTables(output).Where(p => p.HasUpdate).ToList();
        if (list.Count == 0 && code != 0 && !LooksLikeNoUpdates(output))
            throw new InvalidOperationException($"winget couldn't check for updates (code 0x{code:X8}).");
        return list;
    }

    /// <summary>Every installed program, with whether winget can update it (Source is empty when it can't).</summary>
    public static async Task<List<WingetPackage>> InstalledAsync(CancellationToken ct)
    {
        var (_, output) = await RunAsync(ct, null, new[] { "list" }.Concat(Agree).ToArray());
        return ParseTables(output);
    }

    /// <summary>Updates (or, with install: true, installs) one package by its exact id, silently.</summary>
    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(string id, bool install, Action<string, int> progress, CancellationToken ct)
    {
        if (!IdRx().IsMatch(id)) return (false, "That isn't a valid package id.", false);
        var args = new List<string> { install ? "install" : "upgrade", "--id", id, "--exact", "--silent", "--accept-package-agreements" };
        if (!install) args.Add("--include-unknown");
        args.AddRange(Agree);

        var (code, output) = await RunAsync(ct, line =>
        {
            var m = PercentRx().Match(line);
            if (m.Success && int.TryParse(m.Groups[1].Value, out int pct)) { progress("Downloading", pct); return; }
            var mb = SizeProgressRx().Match(line);
            if (mb.Success && double.TryParse(mb.Groups[1].Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double a) &&
                double.TryParse(mb.Groups[3].Value, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double b) && b > 0)
            {
                double scale = Unit(mb.Groups[2].Value) / Unit(mb.Groups[4].Value);
                progress("Downloading", (int)Math.Clamp(a * scale / b * 100, 0, 100));
                return;
            }
            if (line.Contains("Starting package install", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("Installing", StringComparison.OrdinalIgnoreCase)) progress("Installing", -1);
            else if (line.Contains("hash", StringComparison.OrdinalIgnoreCase)) progress("Checking the installer", -1);
        }, args.ToArray());

        uint u = unchecked((uint)code);
        return u switch
        {
            0 => (true, "Installed", false),
            3010 or 1641 or 0x8A150109 => (true, "Installed. Restart to finish.", true),
            0x8A15002B => (true, "Already up to date.", false),
            0x8A150014 => (false, "winget couldn't find this package any more.", false),
            0x8A150011 => (false, "The download didn't match the publisher's hash, so it wasn't installed.", false),
            0x8A150008 => (false, "The download failed. Check your connection and try again.", false),
            0x8A150101 or 0x8A150102 => (false, "The program is open or another install is running. Close it and try again.", false),
            _ => (false, $"winget stopped with code 0x{u:X8}. {LastMeaningfulLine(output)}".Trim(), false),
        };
    }

    // ---- running winget ----

    static async Task<(int code, string output)> RunAsync(CancellationToken ct, Action<string>? onLine, params string[] args)
    {
        string exe = FindExe() ?? throw new InvalidOperationException(
            "winget (App Installer) isn't on this PC. Get \"App Installer\" from the Microsoft Store, then check again.");
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);

        using var p = Process.Start(psi)!;
        var all = new StringBuilder();
        var stderr = p.StandardError.ReadToEndAsync(ct);

        // winget redraws progress with carriage returns; treat \r and \n both as line ends.
        var buffer = new char[4096];
        var line = new StringBuilder();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromMinutes(onLine is null ? 4 : 45));
        try
        {
            int n;
            while ((n = await p.StandardOutput.ReadAsync(buffer.AsMemory(), cts.Token)) > 0)
            {
                for (int i = 0; i < n; i++)
                {
                    char c = buffer[i];
                    all.Append(c); // ParseTables handles \r\n and \r redraws itself
                    if (c == '\r' || c == '\n')
                    {
                        if (line.Length > 0) onLine?.Invoke(line.ToString());
                        line.Clear();
                    }
                    else line.Append(c);
                }
            }
            if (line.Length > 0) onLine?.Invoke(line.ToString());
            await p.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            try { p.Kill(true); } catch { }
            if (ct.IsCancellationRequested) throw;
            throw new TimeoutException("winget took too long and was stopped.");
        }
        all.Append(await stderr);
        return (p.ExitCode, all.ToString());
    }

    // ---- parsing winget's tables ----

    /// <summary>
    /// Reads every table winget printed (upgrade prints a second one for packages that need explicit targeting).
    /// Columns are located from the header line and the dashed line under it, measured in screen cells so that
    /// wide characters (CJK, emoji) in names don't shift the columns after them.
    /// </summary>
    public static List<WingetPackage> ParseTables(string output)
    {
        var result = new List<WingetPackage>();
        var lines = output.Replace("\r\n", "\n").Split('\n').Select(l => l[(l.LastIndexOf('\r') + 1)..].TrimEnd()).ToList();

        for (int h = 0; h + 1 < lines.Count; h++)
        {
            if (!DashesRx().IsMatch(lines[h + 1]) || lines[h].Trim().Length == 0) continue;
            var header = lines[h];
            var starts = HeaderWordRx().Matches(header).Select(m => CellIndex(header, m.Index)).ToList();
            if (starts.Count < 3) continue;
            // Column order is always Name, Id, Version, [Available], [Source]. "Available" only appears when
            // something has an update; "Source" is blank for programs winget can't update.
            bool hasAvailable = starts.Count >= 5 || (starts.Count == 4 && header.Contains("Available", StringComparison.OrdinalIgnoreCase));
            bool hasSource = starts.Count >= 5 || (starts.Count == 4 && !hasAvailable);

            for (int r = h + 2; r < lines.Count; r++)
            {
                var row = lines[r];
                if (row.Trim().Length == 0 || DashesRx().IsMatch(row)) break;
                var cells = SliceByCells(row, starts);
                if (cells[1].Length == 0) break; // footer text such as "3 upgrades available."
                result.Add(new WingetPackage(
                    cells[0], cells[1], cells[2],
                    hasAvailable ? cells[3] : "",
                    hasSource ? cells[^1] : ""));
            }
        }
        return result;
    }

    static List<string> SliceByCells(string row, List<int> starts)
    {
        // Column boundaries as character positions, nudged back to a space if one lands mid-word
        // (e.g. a name winget padded one cell short), so a value is never split across two columns.
        var bounds = new List<int>();
        foreach (int cell in starts)
        {
            int b = Math.Min(CharIndexAtCell(row, cell), row.Length);
            while (b > 0 && b < row.Length && row[b] != ' ' && row[b - 1] != ' ') b--;
            bounds.Add(b);
        }
        var cells = new List<string>();
        for (int i = 0; i < bounds.Count; i++)
        {
            int a = bounds[i];
            int e = i + 1 < bounds.Count ? Math.Max(a, bounds[i + 1]) : row.Length;
            cells.Add(a < row.Length ? row[a..e].Trim() : "");
        }
        return cells;
    }

    static int CellIndex(string s, int charIndex)
    {
        int cells = 0;
        for (int i = 0; i < charIndex && i < s.Length; i++) cells += CellWidth(s, ref i);
        return cells;
    }

    static int CharIndexAtCell(string s, int cell)
    {
        int cells = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (cells >= cell) return i;
            int start = i;
            cells += CellWidth(s, ref i);
            if (cells > cell) return start;
        }
        return s.Length;
    }

    /// <summary>How many terminal cells the character at i takes (advances i past a surrogate pair).</summary>
    static int CellWidth(string s, ref int i)
    {
        char c = s[i];
        if (char.IsHighSurrogate(c) && i + 1 < s.Length) { i++; return 2; }
        return c is >= 'ᄀ' and <= 'ᅟ' or >= '⺀' and <= '꓏' or >= '가' and <= '힣'
            or >= '豈' and <= '﫿' or >= '︰' and <= '﹏' or >= '＀' and <= '｠' or >= '￠' and <= '￦' ? 2 : 1;
    }

    static bool LooksLikeNoUpdates(string output) =>
        output.Contains("No installed package found", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No available upgrade", StringComparison.OrdinalIgnoreCase) ||
        output.Contains("No applicable upgrade", StringComparison.OrdinalIgnoreCase);

    static string LastMeaningfulLine(string output) =>
        output.Split('\n').Select(l => l[(l.LastIndexOf('\r') + 1)..].Trim())
            .LastOrDefault(l => l.Length > 3 && !l.All(ch => ch is '█' or '▒' or '-' or '\\' or '|' or '/' or ' ')) ?? "";

    static double Unit(string u) => u.ToUpperInvariant() switch { "KB" => 1e3, "MB" => 1e6, "GB" => 1e9, _ => 1 };

    [GeneratedRegex(@"^-{10,}$")]
    private static partial Regex DashesRx();

    [GeneratedRegex(@"\S+")]
    private static partial Regex HeaderWordRx();

    [GeneratedRegex(@"(\d{1,3})\s*%")]
    private static partial Regex PercentRx();

    [GeneratedRegex(@"([\d.]+)\s*(KB|MB|GB)\s*/\s*([\d.]+)\s*(KB|MB|GB)", RegexOptions.IgnoreCase)]
    private static partial Regex SizeProgressRx();

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._+\-]{1,127}$")]
    private static partial Regex IdRx();
}
