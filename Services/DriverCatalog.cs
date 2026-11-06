using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Text.RegularExpressions;

namespace SystemForge;

/// <summary>A driver package in the Microsoft Update Catalog that fits one or more of this PC's devices.</summary>
public sealed record CatalogDriver(string UpdateId, string Title, string Version, DateTime? Date, long SizeBytes, string Provider, string Class);

/// <summary>
/// Searches the Microsoft Update Catalog (catalog.update.microsoft.com) by each device's hardware IDs. This is the
/// full set of drivers hardware makers have published through Microsoft, including many that Windows Update only
/// offers to some PCs or not at all. Every package is signed by Microsoft, and we only offer one when:
///   • it targets this PC's architecture and Windows version,
///   • it lists one of the device's own IDs, at least as specifically as the current driver does,
///   • it is newer than the installed driver (driver date first, then version — Windows' own order).
/// That way an offer is always something Windows itself would pick once it's installed.
/// </summary>
public static partial class DriverCatalog
{
    const string Base = "https://www.catalog.update.microsoft.com/";
    static readonly ConcurrentDictionary<string, Task<Details?>> DetailsCache = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Optional trace of each decision (used by diagnostics).</summary>
    public static Action<string>? Trace;

    sealed record Row(string UpdateId, string Title, string Products, DateTime? LastUpdated, Version? Version, string VersionText, long Size);
    sealed record Details(string Arch, DateTime? VersionDate, string Version, string Provider, string Class, HashSet<string> HardwareIds);

    /// <summary>Devices worth looking up: real hardware, plus unplugged devices that use a hardware maker's driver.</summary>
    public static bool IsCandidate(DeviceInfo d)
    {
        if (d.HardwareIds.Length == 0) return false;
        string en = d.Enumerator;
        // Software-only devices (ROOT, SWD, SWC, HTREE …) have no driver in the catalog worth having.
        string[] hardwareBuses = { "PCI", "HDAUDIO", "USB", "ACPI", "BTH", "BTHENUM", "INTELAUDIO", "DISPLAY", "HID", "USBSTOR", "SCSI", "MEDIA" };
        if (!hardwareBuses.Contains(en)) return false;
        if (!d.Present) return d.HasDriver && !d.IsMicrosoftDriver;   // unplugged: only third-party drivers
        if (!d.HasDriver) return true;                                // connected but no driver at all
        if (en is "PCI" or "HDAUDIO" or "INTELAUDIO" or "DISPLAY") return true;
        return !d.IsMicrosoftDriver;                                  // USB/HID/ACPI/BT: only when a maker's driver is in use
    }

    /// <summary>Finds the best catalog driver for a device, or null when there's nothing newer that Windows would pick.</summary>
    public static async Task<CatalogDriver?> FindAsync(DeviceInfo device, int windowsBuild, CancellationToken ct)
    {
        // Pool the specific and the broad search: OEM packages show up for the first, generic ones for the second.
        var rows = new Dictionary<string, Row>(StringComparer.OrdinalIgnoreCase);
        foreach (string query in Queries(device))
            foreach (var r in await SearchAsync(query, ct))
                rows.TryAdd(r.UpdateId, r);

        // Newest first; skip anything that isn't for this PC's Windows release or isn't newer than what's installed.
        // The same package is listed once per Windows release it targets (same title, version and size): keep one.
        var usable = rows.Values
            .Where(r => r.Version is not null && FitsWindows(r.Products, windowsBuild))
            .Where(r => IsNewer(null, r.Version!, device) || r.LastUpdated is null || device.Date is null || r.LastUpdated >= device.Date)
            .OrderByDescending(r => r.Version)
            .ThenByDescending(r => r.LastUpdated)
            .DistinctBy(r => (r.Title, r.VersionText, r.Size))
            .Take(10)
            .ToList();

        // Read the shortlisted details pages in parallel (shared limit below), then judge them newest first.
        var details = usable.Select(r => GetDetailsAsync(r.UpdateId, ct)).ToList();

        Trace?.Invoke($"{device.Name}: {rows.Count} rows, {usable.Count} usable");
        var valid = new List<(int rank, CatalogDriver drv)>();
        for (int i = 0; i < usable.Count; i++)
        {
            var row = usable[i];
            var det = await details[i];
            Trace?.Invoke($"  {row.VersionText} {row.UpdateId}: details={(det is null ? "null" : $"arch={det.Arch} date={det.VersionDate:d} ids={det.HardwareIds.Count}")}");
            if (det is null || !IsX64(det.Arch)) continue;

            int rank = device.HardwareIds.Concat(device.CompatibleIds)
                .Where(det.HardwareIds.Contains)
                .Select(device.Rank)
                .DefaultIfEmpty(-1)
                .Min();
            Trace?.Invoke($"    rank={rank} current={device.CurrentRank}");
            if (rank < 0 || rank > device.CurrentRank) continue;      // Windows wouldn't choose it over the current driver
            if (!IsNewer(det.VersionDate, row.Version!, device)) continue;

            valid.Add((rank, new CatalogDriver(row.UpdateId, row.Title, row.VersionText, det.VersionDate, row.Size,
                det.Provider, det.Class)));
        }
        // Windows ranks by how specifically the ID matches, then driver date, then version: pick the same way.
        return valid
            .OrderBy(v => v.rank)
            .ThenByDescending(v => v.drv.Date ?? DateTime.MinValue)
            .ThenByDescending(v => System.Version.TryParse(v.drv.Version, out var x) ? x : new Version())
            .Select(v => v.drv)
            .FirstOrDefault();
    }

    /// <summary>True when the package is newer than the driver this device has now (Windows' order: date, then version).</summary>
    public static bool IsNewerThan(CatalogDriver drv, DeviceInfo device) =>
        System.Version.TryParse(drv.Version, out var v) && IsNewer(drv.Date, v, device);

    /// <summary>Most specific hardware ID without the revision first, then the plain vendor+device ID.</summary>
    static IEnumerable<string> Queries(DeviceInfo d)
    {
        var ids = d.HardwareIds;
        string first = ids.Length > 1 && ids[0].Contains("&REV_", StringComparison.OrdinalIgnoreCase) ? ids[1] : ids[0];
        yield return first;
        var m = VenDev().Match(first);
        if (m.Success && !m.Value.Equals(first, StringComparison.OrdinalIgnoreCase)) yield return m.Value;
    }

    static bool IsNewer(DateTime? date, Version version, DeviceInfo device)
    {
        if (!device.HasDriver) return true;
        if (date is not null && device.Date is not null)
        {
            if (date.Value.Date > device.Date.Value.Date) return true;
            if (date.Value.Date < device.Date.Value.Date) return false;
        }
        return System.Version.TryParse(device.Version, out var current) && version > current;
    }

    static bool IsX64(string arch) =>
        arch.Contains("AMD64", StringComparison.OrdinalIgnoreCase) || arch.Contains("x64", StringComparison.OrdinalIgnoreCase);

    // ---- Windows targeting ----

    /// <summary>
    /// Product strings look like "Windows 11 Client, version 24H2 and later, Servicing Drivers, …". A row fits when any
    /// phrase in it names a release this PC is at or above. Unknown phrases never count as a fit.
    /// </summary>
    public static bool FitsWindows(string products, int build) =>
        ProductMinBuilds(products).Any(min => build >= min);

    static IEnumerable<int> ProductMinBuilds(string products)
    {
        foreach (Match m in Win11Version().Matches(products))
            if (Win11Releases.TryGetValue(m.Groups[1].Value.ToUpperInvariant(), out int b)) yield return b;
        foreach (Match m in Win10Version().Matches(products))
            if (Win10Releases.TryGetValue(m.Groups[1].Value.ToUpperInvariant(), out int b)) yield return b;
        if (products.Contains("Windows 10, Vibranium and later", StringComparison.OrdinalIgnoreCase)) yield return 19041;
        if (products.Contains("Windows 10 and later", StringComparison.OrdinalIgnoreCase)) yield return 10240;
        if (Regex.IsMatch(products, @"Windows 11 Client(?!(?: S)?, version)", RegexOptions.IgnoreCase)) yield return 22000;
    }

    static readonly Dictionary<string, int> Win11Releases = new()
    {
        ["21H2"] = 22000, ["22H2"] = 22621, ["23H2"] = 22631, ["24H2"] = 26100, ["25H2"] = 26200, ["26H1"] = 28000,
    };

    static readonly Dictionary<string, int> Win10Releases = new()
    {
        ["1507"] = 10240, ["1511"] = 10586, ["1607"] = 14393, ["1703"] = 15063, ["1709"] = 16299, ["1803"] = 17134,
        ["1809"] = 17763, ["1903"] = 18362, ["1909"] = 18363, ["2004"] = 19041, ["20H2"] = 19042, ["21H1"] = 19043,
        ["21H2"] = 19044, ["22H2"] = 19045,
    };

    // ---- catalog pages ----

    /// <summary>At most this many catalog requests at once, across all devices, to be polite to Microsoft's servers.</summary>
    static readonly SemaphoreSlim Gate = new(8);

    static async Task<string> FetchAsync(string url, CancellationToken ct)
    {
        await Gate.WaitAsync(ct);
        try
        {
            // One retry: the catalog occasionally drops a request under load.
            try { return await Downloader.GetStringAsync(url, 30, ct); }
            catch (Exception ex) when (ex is HttpRequestException or TimeoutException)
            {
                await Task.Delay(1500, ct);
                return await Downloader.GetStringAsync(url, 30, ct);
            }
        }
        finally { Gate.Release(); }
    }

    static async Task<List<Row>> SearchAsync(string query, CancellationToken ct)
    {
        string html = await FetchAsync(Base + "Search.aspx?q=" + Uri.EscapeDataString(query), ct);
        var rows = new List<Row>();
        foreach (Match m in RowRx().Matches(html))
        {
            var cells = CellRx().Matches(m.Groups[2].Value).Select(c => Clean(c.Groups[1].Value)).ToList();
            if (cells.Count < 7) continue;
            var sizeMatch = SizeRx().Match(m.Groups[2].Value);
            rows.Add(new Row(
                m.Groups[1].Value,
                cells[1],
                cells[2],
                ParseDate(cells[4]),
                System.Version.TryParse(cells[5], out var v) ? v : null,
                cells[5],
                sizeMatch.Success && long.TryParse(sizeMatch.Groups[1].Value, out long sz) ? sz : 0));
        }
        return rows;
    }

    /// <summary>
    /// Details pages are cached per package for the whole session. The cached load isn't tied to whoever asked first,
    /// so one cancelled scan can't poison later ones; a caller that's cancelled just stops waiting.
    /// </summary>
    static Task<Details?> GetDetailsAsync(string updateId, CancellationToken ct) =>
        DetailsCache.GetOrAdd(updateId, id => LoadDetailsAsync(id)).WaitAsync(ct);

    static async Task<Details?> LoadDetailsAsync(string updateId)
    {
        try
        {
            string html = await FetchAsync(Base + "ScopedViewInline.aspx?updateid=" + Uri.EscapeDataString(updateId), CancellationToken.None);
            string Span(string id) { var m = Regex.Match(html, $"<span id=\"ScopedViewHandler_{id}\"[^>]*>(.*?)</span>", RegexOptions.Singleline); return m.Success ? Clean(m.Groups[1].Value) : ""; }

            var archMatch = Regex.Match(html, @"labelArchitecture_Separator""[^>]*>[^<]*</span>\s*([^<]+)<", RegexOptions.Singleline);
            var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int start = html.IndexOf("id=\"driverhwIDs\"", StringComparison.Ordinal);
            if (start >= 0)
            {
                // The list ends where the next box (supported update ids) begins.
                int end = html.IndexOf("labelSupportedUpdateIDs", start, StringComparison.Ordinal);
                string block = end > start ? html[start..end] : html[start..Math.Min(html.Length, start + 200_000)];
                foreach (Match m in HwIdRx().Matches(block))
                {
                    string id = Clean(m.Groups[1].Value);
                    if (id.Contains('\\')) ids.Add(id);
                }
            }
            return new Details(archMatch.Success ? Clean(archMatch.Groups[1].Value) : "", ParseDate(Span("versionDate")),
                Span("version"), Span("driverProvider"), Span("driverClass"), ids);
        }
        catch (Exception ex)
        {
            Trace?.Invoke($"  details failed for {updateId}: {ex.Message}");
            DetailsCache.TryRemove(updateId, out _); // let a later scan retry
            return null;
        }
    }

    // ---- install ----

    /// <summary>
    /// Downloads the package, checks it against the catalog's SHA-1 digest, unpacks it and hands it to
    /// pnputil, which installs it on every device it fits better than the current driver (or stages it in
    /// the driver store for devices that are unplugged).
    /// </summary>
    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(string updateId, Action<string, int> progress, CancellationToken ct)
    {
        string dir = Downloader.NewWorkFolder("catalog");
        try
        {
            progress("Getting the download link", -1);
            var files = await DownloadLinksAsync(updateId, ct);
            if (files.Count == 0) return (false, "The catalog didn't give a download for this driver.", false);

            string extract = Path.Combine(dir, "driver");
            Directory.CreateDirectory(extract);
            for (int i = 0; i < files.Count; i++)
            {
                var (url, digest) = files[i];
                var uri = new Uri(url);
                if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.EndsWith(".windowsupdate.com", StringComparison.OrdinalIgnoreCase))
                    return (false, "The catalog pointed somewhere other than Windows Update's servers, so nothing was installed.", false);

                string file = Path.Combine(dir, $"package{i}{Path.GetExtension(uri.AbsolutePath)}");
                await Downloader.DownloadAsync(url, file, p => progress("Downloading", p), ct);
                progress("Checking the download", -1);
                if (digest.Length > 0 && !Downloader.Sha1Base64(file).Equals(digest, StringComparison.Ordinal))
                    return (false, "The download didn't match Microsoft's checksum, so it was thrown away.", false);

                progress("Unpacking", -1);
                if (file.EndsWith(".cab", StringComparison.OrdinalIgnoreCase))
                {
                    var (code, output) = await RunAsync(Path.Combine(Environment.SystemDirectory, "expand.exe"), ct, "-F:*", file, extract);
                    if (code != 0) return (false, $"Couldn't unpack the driver. {LastLine(output)}", false);
                }
                else return (false, "This catalog entry isn't a driver package SystemForge can install.", false);
            }

            if (!Directory.EnumerateFiles(extract, "*.inf", SearchOption.AllDirectories).Any())
                return (false, "The package had no driver files in it.", false);

            progress("Installing", -1);
            var (rc, log) = await RunAsync(Path.Combine(Environment.SystemDirectory, "pnputil.exe"), ct,
                "/add-driver", Path.Combine(extract, "*.inf"), "/subdirs", "/install");
            return rc switch
            {
                0 => (true, "Installed", false),
                3010 => (true, "Installed. Restart to finish.", true),
                // ERROR_NO_MORE_ITEMS: added to the driver store, but no connected device took it (yet).
                259 => (true, "Added to Windows. It will be used the next time the device is connected.", false),
                _ => (false, $"Windows didn't install it (code {rc}). {LastLine(log)}", false),
            };
        }
        finally { Downloader.TryDelete(dir); }
    }

    static async Task<List<(string url, string digest)>> DownloadLinksAsync(string updateId, CancellationToken ct)
    {
        string payload = $"[{{\"size\":0,\"languages\":\"\",\"uidInfo\":\"{updateId}\",\"updateID\":\"{updateId}\"}}]";
        using var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("updateIDs", payload) });
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(30));
        string js;
        try
        {
            using var resp = await Downloader.Http.PostAsync(Base + "DownloadDialog.aspx", content, cts.Token);
            resp.EnsureSuccessStatusCode();
            js = await resp.Content.ReadAsStringAsync(cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("The Microsoft Update Catalog didn't answer in time.");
        }

        var urls = Regex.Matches(js, @"downloadInformation\[0\]\.files\[(\d+)\]\.url\s*=\s*'([^']+)'");
        var digests = Regex.Matches(js, @"downloadInformation\[0\]\.files\[(\d+)\]\.digest\s*=\s*'([^']*)'")
            .ToDictionary(m => m.Groups[1].Value, m => m.Groups[2].Value);
        return urls.Select(m => (m.Groups[2].Value, digests.GetValueOrDefault(m.Groups[1].Value, ""))).ToList();
    }

    // ---- helpers ----

    static string Clean(string html) => Regex.Replace(WebUtility.HtmlDecode(Regex.Replace(html, "<[^>]+>", " ")), @"\s+", " ").Trim();

    static DateTime? ParseDate(string s) =>
        DateTime.TryParseExact(s.Trim(), new[] { "M/d/yyyy", "MM/dd/yyyy" }, CultureInfo.InvariantCulture, DateTimeStyles.None, out var d) ? d : null;

    static async Task<(int code, string output)> RunAsync(string exe, CancellationToken ct, params string[] args)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        var stdout = p.StandardOutput.ReadToEndAsync(ct);
        var stderr = p.StandardError.ReadToEndAsync(ct);
        await p.WaitForExitAsync(ct);
        return (p.ExitCode, await stdout + await stderr);
    }

    static string LastLine(string output) =>
        output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).LastOrDefault() ?? "";

    [GeneratedRegex(@"<tr id=""([0-9a-fA-F-]{36})_R\d+""[^>]*>(.*?)</tr>", RegexOptions.Singleline)]
    private static partial Regex RowRx();

    [GeneratedRegex(@"<td[^>]*>(.*?)</td>", RegexOptions.Singleline)]
    private static partial Regex CellRx();

    [GeneratedRegex(@"_originalSize""[^>]*>\s*(\d+)\s*<")]
    private static partial Regex SizeRx();

    [GeneratedRegex(@"<div[^>]*>\s*([^<>]+?)\s*</div>", RegexOptions.Singleline)]
    private static partial Regex HwIdRx();

    [GeneratedRegex(@"^[A-Z]+\\VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}|^HDAUDIO\\FUNC_[0-9A-F]{2}&VEN_[0-9A-F]{4}&DEV_[0-9A-F]{4}|^USB\\VID_[0-9A-F]{4}&PID_[0-9A-F]{4}", RegexOptions.IgnoreCase)]
    private static partial Regex VenDev();

    [GeneratedRegex(@"Windows 11 Client(?: S)?, version (\w{4}) and later", RegexOptions.IgnoreCase)]
    private static partial Regex Win11Version();

    [GeneratedRegex(@"Windows 10, version (\w{4}) and later", RegexOptions.IgnoreCase)]
    private static partial Regex Win10Version();
}
