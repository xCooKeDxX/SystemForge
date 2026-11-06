using System.Diagnostics;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SystemForge;

public sealed record NvidiaDriver(string Version, string Name, DateTime? Released, string DownloadUrl, string Size, string DetailsUrl, bool Notebook);

/// <summary>
/// NVIDIA's own driver lookup — the same service behind nvidia.com/drivers — for GeForce cards.
/// This usually has Game Ready drivers weeks before they reach Windows Update or the catalog.
/// The installer is only run after Windows confirms it's signed by NVIDIA Corporation.
/// </summary>
public static partial class NvidiaDrivers
{
    const string LookupProducts = "https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=3";
    const string LookupSeries = "https://www.nvidia.com/Download/API/lookupValueSearch.aspx?TypeID=2";
    const string DriverService = "https://gfwsl.geforce.com/services_toolkit/services/com/nvidia/services/AjaxDriverService.php";

    public static bool IsNvidiaGpu(DeviceInfo d) =>
        d.Present && d.Class.Equals("Display", StringComparison.OrdinalIgnoreCase) &&
        d.HardwareIds.Any(id => id.StartsWith(@"PCI\VEN_10DE&", StringComparison.OrdinalIgnoreCase));

    /// <summary>"32.0.15.9595" (how Windows shows it) → 59595, which is NVIDIA's "595.95".</summary>
    public static int? ToNvidiaNumber(string windowsVersion)
    {
        var parts = windowsVersion.Split('.');
        if (parts.Length < 4) return null;
        string digits = parts[2] + parts[3].PadLeft(4, '0');
        if (digits.Length < 5 || !int.TryParse(digits[^5..], out int n)) return null;
        return n;
    }

    public static int? ParseNvidiaVersion(string v) =>
        decimal.TryParse(v, System.Globalization.NumberStyles.Number, System.Globalization.CultureInfo.InvariantCulture, out var d)
            ? (int)Math.Round(d * 100) : null;

    public static string Format(int nvNumber) => $"{nvNumber / 100}.{nvNumber % 100:00}";

    /// <summary>The newest Game Ready (WHQL, DCH) driver for this card, or null if NVIDIA has nothing newer.</summary>
    public static async Task<NvidiaDriver?> FindAsync(DeviceInfo gpu, int windowsBuild, CancellationToken ct)
    {
        string product = ProductName(gpu.Name);
        bool laptop = IsLaptop();

        string productsXml = await Downloader.GetStringAsync(LookupProducts, 30, ct);
        string seriesXml = await Downloader.GetStringAsync(LookupSeries, 30, ct);
        var seriesNames = LookupRx().Matches(seriesXml).ToDictionary(m => m.Groups["v"].Value, m => m.Groups["n"].Value, StringComparer.Ordinal);

        var matches = LookupRx().Matches(productsXml)
            .Select(m => (psid: m.Groups["p"].Value, pfid: m.Groups["v"].Value, name: System.Net.WebUtility.HtmlDecode(m.Groups["n"].Value).Trim()))
            .Where(x => x.name.Equals(product, StringComparison.OrdinalIgnoreCase))
            .Select(x => (x.psid, x.pfid, x.name, notebook: seriesNames.GetValueOrDefault(x.psid, "").Contains("Notebook", StringComparison.OrdinalIgnoreCase)))
            .ToList();
        if (matches.Count == 0) return null;

        // Prefer the laptop or desktop listing to match this PC; fall back to whichever exists.
        var pick = matches.FirstOrDefault(x => x.notebook == laptop);
        if (pick.pfid is null) pick = matches[0];

        int osId = windowsBuild >= 22000 ? 135 : 57; // Windows 11 / Windows 10 64-bit
        string url = $"{DriverService}?func=DriverManualLookup&psid={pick.psid}&pfid={pick.pfid}&osID={osId}" +
                     "&languageCode=1033&isWHQL=1&dch=1&upCRD=0&sort1=0&numberOfResults=1";
        using var doc = JsonDocument.Parse(await Downloader.GetStringAsync(url, 30, ct));
        if (!doc.RootElement.TryGetProperty("IDS", out var ids) || ids.GetArrayLength() == 0) return null;
        var info = ids[0].GetProperty("downloadInfo");

        string S(string name) => info.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? Uri.UnescapeDataString(v.GetString() ?? "") : "";
        string version = S("Version");
        string download = S("DownloadURL");
        if (version.Length == 0 || download.Length == 0) return null;

        int? latest = ParseNvidiaVersion(version);
        int? installed = ToNvidiaNumber(gpu.Version);
        if (latest is null || (installed is not null && latest <= installed)) return null;

        DateTime? released = DateTime.TryParse(Regex.Replace(S("ReleaseDateTime"), @"^\w{3}\s", ""),
            System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var r) ? r : null;
        return new NvidiaDriver(version, S("Name").Trim(), released, download, S("DownloadURLFileSize"), S("DetailsURL"), pick.notebook);
    }

    /// <summary>"NVIDIA GeForce GTX 1660 Ti with Max-Q Design" → "GeForce GTX 1660 Ti".</summary>
    static string ProductName(string deviceName)
    {
        string n = Regex.Replace(deviceName, @"^NVIDIA\s+", "", RegexOptions.IgnoreCase);
        n = Regex.Replace(n, @"\s+with Max-Q Design$", "", RegexOptions.IgnoreCase);
        return n.Trim();
    }

    public static bool IsLaptop()
    {
        try
        {
            using var s = new ManagementObjectSearcher("SELECT ChassisTypes FROM Win32_SystemEnclosure");
            foreach (ManagementObject o in s.Get())
            {
                using (o)
                {
                    if (o["ChassisTypes"] is ushort[] types &&
                        types.Any(t => t is 8 or 9 or 10 or 11 or 12 or 14 or 18 or 21 or 30 or 31 or 32))
                        return true;
                }
            }
            using var b = new ManagementObjectSearcher("SELECT Name FROM Win32_Battery");
            return b.Get().Count > 0;
        }
        catch { return false; }
    }

    /// <summary>
    /// Downloads NVIDIA's installer, checks Windows trusts its NVIDIA Corporation signature,
    /// then runs it silently (driver only settings stay; no restart forced).
    /// </summary>
    /// <param name="deviceId">The GPU, so the result can be checked against the driver Windows actually has afterwards.</param>
    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(string downloadUrl, string version, string deviceId,
        Action<string, int> progress, CancellationToken ct)
    {
        var uri = new Uri(downloadUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.EndsWith(".download.nvidia.com", StringComparison.OrdinalIgnoreCase))
            return (false, "NVIDIA's lookup pointed somewhere other than NVIDIA's download servers, so nothing was installed.", false);

        string dir = Downloader.NewWorkFolder("nvidia");
        try
        {
            string file = Path.Combine(dir, Path.GetFileName(uri.AbsolutePath));
            await Downloader.DownloadAsync(downloadUrl, file, p => progress("Downloading", p), ct);

            progress("Checking NVIDIA's signature", -1);
            if (!Downloader.IsSignedBy(file, "NVIDIA Corporation", out string signer))
                return (false, $"The installer isn't signed by NVIDIA{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.", false);

            progress("Installing (your screen will flicker)", -1);
            var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { "-s", "-noreboot", "-noeula", "-nofinish", "-nosplash" }) psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(30));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (false, "NVIDIA's installer was still running after 30 minutes. Restart your PC, then check again.", false);
            }
            // NVIDIA's exit codes aren't documented, so check what Windows reports for the card now.
            progress("Checking the result", -1);
            var gpu = DeviceInventory.Scan().FirstOrDefault(d => d.InstanceId.Equals(deviceId, StringComparison.OrdinalIgnoreCase));
            int? now = gpu is null ? null : ToNvidiaNumber(gpu.Version);
            int? wanted = ParseNvidiaVersion(version);
            if (now is not null && wanted is not null && now >= wanted)
                return (true, p.ExitCode == 0 ? "Installed" : "Installed. Restart to finish.", p.ExitCode != 0);
            return (false, $"NVIDIA's installer finished (code {p.ExitCode}) but the card still reports {(now is null ? "the old driver" : Format(now.Value))}. Restart and check again.", false);
        }
        finally { Downloader.TryDelete(dir); }
    }

    [GeneratedRegex(@"<LookupValue ParentID=""(?<p>\d+)""[^>]*>\s*<Name>(?<n>[^<]*)</Name>\s*<Value>(?<v>\d+)</Value>")]
    private static partial Regex LookupRx();
}
