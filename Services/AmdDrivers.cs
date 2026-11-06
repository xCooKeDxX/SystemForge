using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32;

namespace SystemForge;

public sealed record AmdChipset(string Version, DateTime? Released, string DownloadUrl, string Size, string PageUrl, string Chipset);

public sealed record AmdDriver(string Version, bool Whql, bool Recommended, DateTime? Released, string DownloadUrl, string Size, string PageUrl, string? NotesUrl);

/// <summary>
/// AMD's own driver pages (amd.com/support), for Radeon cards and the Radeon graphics built into Ryzen chips.
/// amd.com embeds its whole product tree in the driver-selector page, and each product page lists the
/// Adrenalin releases for it. Those usually run ahead of Windows Update by weeks. The installer is only run after
/// Windows confirms it's signed by Advanced Micro Devices.
/// </summary>
public static partial class AmdDrivers
{
    const string SelectorPage = "https://www.amd.com/en/support/download/drivers.html";

    public static bool IsAmdGpu(DeviceInfo d) =>
        d.Present && d.Class.Equals("Display", StringComparison.OrdinalIgnoreCase) &&
        d.HardwareIds.Any(id => id.StartsWith(@"PCI\VEN_1002&", StringComparison.OrdinalIgnoreCase));

    /// <summary>Radeon graphics inside a Ryzen chip: AMD lists its driver on the processor's page.</summary>
    public static bool IsIntegrated(DeviceInfo d) =>
        Regex.IsMatch(d.Name, @"(?i)Radeon\(TM\) Graphics$|Radeon Graphics$|Vega \d+|Radeon 6\d0M|Radeon 7\d0M|Radeon 8\d0M|Radeon 8\d0S|\bRX Vega 1[01]\b");

    /// <summary>What AMD Software reports as installed, e.g. "26.5.2". Null if AMD Software isn't installed.</summary>
    public static string? InstalledVersion()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\AMD\CN");
            string? v = k?.GetValue("RadeonSoftwareVersion") as string;
            if (v is null || !AdrenalinRx().IsMatch(v)) return null;
            return AdrenalinRx().Match(v).Value;
        }
        catch { return null; }
    }

    public static Version? Parse(string? adrenalin) =>
        adrenalin is not null && AdrenalinRx().Match(adrenalin) is { Success: true } m && Version.TryParse(m.Value, out var v) ? v : null;

    public static async Task<AmdDriver?> FindAsync(DeviceInfo gpu, string cpuName, int windowsBuild, CancellationToken ct)
    {
        string? page = await ProductPageAsync(gpu, cpuName, ct);
        if (page is null) return null;

        string html = await Downloader.GetStringAsync(page, 40, ct);
        var releases = new List<AmdDriver>();
        foreach (Match a in ArticleRx().Matches(html))
        {
            string block = a.Value;
            if (!block.Contains("Adrenalin", StringComparison.OrdinalIgnoreCase)) continue;
            var link = DownloadRx().Match(block);
            var rev = RevisionRx().Match(block);
            if (!link.Success || !rev.Success) continue;
            string url = System.Net.WebUtility.HtmlDecode(link.Groups[1].Value);
            string revision = System.Net.WebUtility.HtmlDecode(rev.Groups[1].Value).Trim();
            var ver = AdrenalinRx().Match(revision);
            if (!ver.Success) continue;
            // Package for this Windows: file names carry win11 / win10 (or both).
            string file = Path.GetFileName(new Uri(url).AbsolutePath).ToLowerInvariant();
            bool forThisWindows = windowsBuild >= 22000 ? file.Contains("win11") : file.Contains("win10");
            if (!forThisWindows) continue;

            DateTime? date = DateRx().Match(block) is { Success: true } d && DateTime.TryParseExact(d.Groups[1].Value, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var dt) ? dt : null;
            string size = SizeRx().Match(block) is { Success: true } sz ? sz.Groups[1].Value : "";
            string? notes = NotesRx().Match(block) is { Success: true } n ? "https://www.amd.com" + System.Net.WebUtility.HtmlDecode(n.Groups[1].Value) : null;
            releases.Add(new AmdDriver(ver.Value, revision.Contains("WHQL", StringComparison.OrdinalIgnoreCase),
                revision.Contains("Recommended", StringComparison.OrdinalIgnoreCase), date, url, size, page, notes));
        }

        // Newest WHQL release. AMD marks a newer one "Optional" for a few weeks; it's still certified.
        var best = releases.Where(r => r.Whql).OrderByDescending(r => Parse(r.Version)).ThenByDescending(r => r.Released).FirstOrDefault();
        if (best is null) return null;

        var latest = Parse(best.Version);
        var installed = Parse(InstalledVersion());
        if (installed is not null)
        {
            if (latest is null || latest <= installed) return null;
        }
        else
        {
            // No AMD Software installed (Windows' own basic driver): go by the driver's date.
            if (gpu.Date is DateTime have && best.Released is DateTime rel && rel <= have.AddDays(3)) return null;
        }
        return best;
    }

    // ---- chipset ----

    [GeneratedRegex(@"(?i)\b(X870E|X870|B850|B840|X670E|X670|B650E|B650|A620|X570S|X570|B550|A520|X470|B450|X370|B350|A320|TRX40|WRX80|TRX50|WRX90)\b")]
    private static partial Regex ChipsetRx();

    /// <summary>The chipset named in the motherboard's model string, e.g. "B650" from "B650 AORUS ELITE AX".</summary>
    public static string? BoardChipset()
    {
        try
        {
            using var q = new System.Management.ManagementObjectSearcher("SELECT Product, Manufacturer FROM Win32_BaseBoard");
            foreach (System.Management.ManagementObject o in q.Get())
            {
                using (o)
                {
                    string product = o["Product"] as string ?? "";
                    var m = ChipsetRx().Match(product);
                    if (m.Success) return m.Groups[1].Value.ToUpperInvariant();
                }
            }
        }
        catch { }
        return null;
    }

    /// <summary>"AMD Chipset Software" as Programs and Features lists it, or null.</summary>
    public static Version? InstalledChipsetVersion()
    {
        foreach (var root in new[] { @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" })
        {
            try
            {
                using var k = Registry.LocalMachine.OpenSubKey(root);
                if (k is null) continue;
                foreach (var name in k.GetSubKeyNames())
                {
                    using var sub = k.OpenSubKey(name);
                    string dn = sub?.GetValue("DisplayName") as string ?? "";
                    if (!dn.StartsWith("AMD Chipset Software", StringComparison.OrdinalIgnoreCase)) continue;
                    if (Version.TryParse(sub?.GetValue("DisplayVersion") as string ?? "", out var v)) return v;
                }
            }
            catch { }
        }
        return null;
    }

    /// <summary>AMD's unified chipset package for this desktop board, if it's newer than what's installed.</summary>
    public static async Task<AmdChipset?> FindChipsetAsync(CancellationToken ct)
    {
        string? chipset = BoardChipset();
        if (chipset is null) return null;
        var tree = await ProductTreeAsync(ct);
        var chipsets = tree.Where(e => e.path.StartsWith("Chipsets", StringComparison.OrdinalIgnoreCase)).ToList();
        var hit = chipsets.FirstOrDefault(e => e.title.Trim().Equals(chipset, StringComparison.OrdinalIgnoreCase));
        if (hit.url is null && chipset.EndsWith('S')) // X570S boards use the X570 package
            hit = chipsets.FirstOrDefault(e => e.title.Trim().Equals(chipset[..^1], StringComparison.OrdinalIgnoreCase));
        if (hit.url is null) return null;

        string html = await Downloader.GetStringAsync(hit.url, 40, ct);
        foreach (Match a in ArticleRx().Matches(html))
        {
            string block = a.Value;
            var h4 = Regex.Match(block, @"<h4>\s*([^<]*?)\s*</h4>");
            if (!h4.Success || !h4.Groups[1].Value.StartsWith("AMD Chipset Drivers", StringComparison.OrdinalIgnoreCase)) continue;
            var link = DownloadRx().Match(block);
            var rev = RevisionRx().Match(block);
            if (!link.Success || !rev.Success || !Version.TryParse(rev.Groups[1].Value.Trim(), out var latest)) continue;
            var installed = InstalledChipsetVersion();
            if (installed is not null && latest <= installed) return null;
            DateTime? date = DateRx().Match(block) is { Success: true } d && DateTime.TryParseExact(d.Groups[1].Value, "yyyy-MM-dd",
                System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var dt) ? dt : null;
            string size = SizeRx().Match(block) is { Success: true } sz ? sz.Groups[1].Value : "";
            return new AmdChipset(latest.ToString(), date, System.Net.WebUtility.HtmlDecode(link.Groups[1].Value), size, hit.url, chipset);
        }
        return null;
    }

    public static async Task<(bool ok, string message, bool reboot)> InstallChipsetAsync(string downloadUrl, string version, string pageUrl, Action<string, int> progress, CancellationToken ct)
    {
        var uri = new Uri(downloadUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.Equals("drivers.amd.com", StringComparison.OrdinalIgnoreCase))
            return (false, "AMD's page pointed somewhere other than AMD's download servers, so nothing was installed.", false);
        string dir = Downloader.NewWorkFolder("amd-chipset");
        try
        {
            string file = Path.Combine(dir, Path.GetFileName(uri.AbsolutePath));
            await Downloader.DownloadAsync(downloadUrl, file, p => progress("Downloading", p), pageUrl, ct);
            progress("Checking AMD's signature", -1);
            if (!Downloader.IsSignedBy(file, "Advanced Micro Devices", out string signer))
                return (false, $"The installer isn't signed by AMD{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.", false);
            progress("Installing", -1);
            var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("/S");
            using var p = Process.Start(psi)!;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(20));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return (false, "AMD's chipset installer was still running after 20 minutes. Restart your PC, then check again.", false); }
            var now = InstalledChipsetVersion();
            bool done = now is not null && Version.TryParse(version, out var want) && now >= want;
            if (done || p.ExitCode is 0 or 3010 or 1641) return (true, "Installed. Restart to finish.", true);
            return (false, $"AMD's chipset installer finished with code {p.ExitCode}. Restart and check again.", false);
        }
        finally { Downloader.TryDelete(dir); }
    }

    // ---- product tree ----

    static List<(string path, string title, string url)>? treeCache;
    static DateTime treeAt;

    static async Task<List<(string path, string title, string url)>> ProductTreeAsync(CancellationToken ct)
    {
        if (treeCache is not null && DateTime.UtcNow - treeAt < TimeSpan.FromHours(6)) return treeCache;
        string html = await Downloader.GetStringAsync(SelectorPage, 40, ct);
        var m = TreeRx().Match(html);
        if (!m.Success) throw new InvalidOperationException("AMD's driver page has changed layout.");
        using var doc = JsonDocument.Parse(System.Net.WebUtility.HtmlDecode(m.Groups[1].Value));
        var entries = new List<(string path, string title, string url)>();
        void Walk(JsonElement node, string path)
        {
            string title = node.TryGetProperty("title", out var t) ? t.GetString() ?? "" : "";
            string here = path.Length == 0 ? title : path + " > " + title;
            if (node.TryGetProperty("url", out var u) && u.ValueKind == JsonValueKind.String) entries.Add((here, title, u.GetString()!));
            if (node.TryGetProperty("items", out var items) && items.ValueKind == JsonValueKind.Array)
                foreach (var c in items.EnumerateArray()) Walk(c, here);
        }
        if (doc.RootElement.TryGetProperty("productTypes", out var types))
            foreach (var t in types.EnumerateArray()) Walk(t, "");
        treeCache = entries;
        treeAt = DateTime.UtcNow;
        return entries;
    }

    /// <summary>Finds this card (or this Ryzen chip) in AMD's product tree and returns its driver page.</summary>
    static async Task<string?> ProductPageAsync(DeviceInfo gpu, string cpuName, CancellationToken ct)
    {
        var entries = await ProductTreeAsync(ct);

        static string Norm(string s) => Regex.Replace(s.Replace("™", "").Replace("(TM)", "").Replace("(R)", ""), @"\s+", " ")
            .Replace("AMD ", "", StringComparison.OrdinalIgnoreCase).Replace("Radeon ", "", StringComparison.OrdinalIgnoreCase)
            .Replace("Graphics", "", StringComparison.OrdinalIgnoreCase).Trim().ToUpperInvariant();

        if (IsIntegrated(gpu))
        {
            // "AMD Ryzen 7 4800H with Radeon Graphics" → the "AMD Ryzen™ 7 4800H" processor page.
            string cpu = Regex.Replace(cpuName, @"(?i)\s+(with|w/).*$", "").Replace("(TM)", "").Replace("(R)", "");
            cpu = Regex.Replace(cpu, @"(?i)\s+\d+-Core Processor.*$", "");
            cpu = Regex.Replace(cpu, @"\s+", " ").Trim();
            string want = cpu.Replace("AMD ", "", StringComparison.OrdinalIgnoreCase).ToUpperInvariant();
            var hit = entries.Where(e => e.path.StartsWith("Processors", StringComparison.OrdinalIgnoreCase))
                .FirstOrDefault(e => e.title.Replace("™", "").Replace("AMD ", "", StringComparison.OrdinalIgnoreCase).Trim().ToUpperInvariant() == want);
            return hit.url;
        }

        string name = Norm(gpu.Name);
        var gfx = entries.Where(e => e.path.StartsWith("Graphics", StringComparison.OrdinalIgnoreCase)).ToList();
        var exact = gfx.FirstOrDefault(e => Norm(e.title) == name);
        if (exact.url is not null) return exact.url;
        // "AMD Radeon RX 6600M" vs listing with a suffix, or Windows adding "Series": try the longest title inside the name.
        var contained = gfx.Where(e => Norm(e.title).Length >= 6 && name.Contains(Norm(e.title)))
            .OrderByDescending(e => Norm(e.title).Length).FirstOrDefault();
        return contained.url;
    }

    /// <summary>Downloads AMD's installer, checks its AMD signature, runs it unattended and confirms the version afterwards.</summary>
    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(string downloadUrl, string version, Action<string, int> progress, CancellationToken ct)
    {
        var uri = new Uri(downloadUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.Equals("drivers.amd.com", StringComparison.OrdinalIgnoreCase))
            return (false, "AMD's page pointed somewhere other than AMD's download servers, so nothing was installed.", false);

        string dir = Downloader.NewWorkFolder("amd");
        try
        {
            string file = Path.Combine(dir, Path.GetFileName(uri.AbsolutePath));
            await Downloader.DownloadAsync(downloadUrl, file, p => progress("Downloading", p), SelectorPage, ct);

            progress("Checking AMD's signature", -1);
            if (!Downloader.IsSignedBy(file, "Advanced Micro Devices", out string signer))
                return (false, $"The installer isn't signed by AMD{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.", false);

            progress("Installing (your screen will flicker)", -1);
            var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
            psi.ArgumentList.Add("-install");
            using var p = Process.Start(psi)!;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(40));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (false, "AMD's installer was still running after 40 minutes. Restart your PC, then check again.", false);
            }

            progress("Checking the result", -1);
            var now = Parse(InstalledVersion());
            var wanted = Parse(version);
            if (now is not null && wanted is not null && now >= wanted)
                return (true, p.ExitCode == 0 ? "Installed" : "Installed. Restart to finish.", p.ExitCode is 3010 or 1641 or 2 or 3);
            if (p.ExitCode is 0 or 3010 or 1641)
                return (true, "Installed. Restart to finish.", true);
            return (false, $"AMD's installer finished with code {p.ExitCode} and AMD Software still reports {(now is null ? "no version" : now.ToString())}. Restart and check again.", false);
        }
        finally { Downloader.TryDelete(dir); }
    }

    [GeneratedRegex(@"data-component=""coveo-browse-documentation""[^>]*data-json=""([^""]+)""")]
    private static partial Regex TreeRx();
    [GeneratedRegex(@"<article class=""[^""]*driver-download-details[^""]*"".*?</article>", RegexOptions.Singleline)]
    private static partial Regex ArticleRx();
    [GeneratedRegex(@"href=""(https://drivers\.amd\.com/drivers/[^""]+\.exe)""")]
    private static partial Regex DownloadRx();
    [GeneratedRegex(@"Revision Number</strong>\s*<p>\s*([^<]+?)\s*</p>", RegexOptions.Singleline)]
    private static partial Regex RevisionRx();
    [GeneratedRegex(@"Release Date</strong>\s*<p>\s*(\d{4}-\d{2}-\d{2})", RegexOptions.Singleline)]
    private static partial Regex DateRx();
    [GeneratedRegex(@"File Size</strong>\s*<p>\s*([^<]+?)\s*</p>", RegexOptions.Singleline)]
    private static partial Regex SizeRx();
    [GeneratedRegex(@"href=""(/en/resources/support-articles/release-notes/[^""]+)""")]
    private static partial Regex NotesRx();
    [GeneratedRegex(@"\d{2}\.\d{1,2}\.\d{1,2}")]
    private static partial Regex AdrenalinRx();
}
