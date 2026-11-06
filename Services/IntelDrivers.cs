using System.Diagnostics;
using System.Text.RegularExpressions;

namespace SystemForge;

public sealed record IntelDriver(string Version, bool Whql, DateTime? Released, string DownloadUrl, string PageUrl);

/// <summary>
/// Intel's Download Center pages for graphics. Intel ships one driver for Arc, Iris Xe and 11th-gen-and-newer
/// Core graphics, and a separate one for 7th–10th gen. Each page carries the version and download link in its
/// metadata, and Intel's version string is the same one Windows shows, so comparing is straightforward.
/// </summary>
public static partial class IntelDrivers
{
    const string ModernPage = "https://www.intel.com/content/www/us/en/download/785597/intel-arc-iris-xe-graphics-windows.html";
    const string LegacyPage = "https://www.intel.com/content/www/us/en/download/776137/intel-7th-10th-gen-processor-graphics-windows.html";

    public static bool IsIntelGpu(DeviceInfo d) =>
        d.Present && d.Class.Equals("Display", StringComparison.OrdinalIgnoreCase) &&
        d.HardwareIds.Any(id => id.StartsWith(@"PCI\VEN_8086&", StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Device ids of 7th–10th gen graphics (Kaby Lake through Comet Lake and Ice Lake, plus Gemini/Apollo Lake),
    /// which get the legacy driver. Everything newer uses the unified Arc / Iris Xe driver.
    /// </summary>
    static bool IsLegacy(DeviceInfo d)
    {
        foreach (var id in d.HardwareIds)
        {
            var m = Regex.Match(id, @"(?i)VEN_8086&DEV_([0-9A-F]{4})");
            if (!m.Success) continue;
            int dev = Convert.ToInt32(m.Groups[1].Value, 16);
            return dev is (>= 0x1900 and <= 0x193F)   // Skylake (same driver line)
                       or (>= 0x5900 and <= 0x593F)   // Kaby Lake
                       or (>= 0x3E90 and <= 0x3EA8)   // Coffee Lake
                       or (>= 0x87C0 and <= 0x87CA)   // Amber Lake
                       or (>= 0x9B21 and <= 0x9BCC)   // Comet Lake
                       or (>= 0x8A50 and <= 0x8A71)   // Ice Lake
                       or 0x3184 or 0x3185            // Gemini Lake
                       or 0x5A84 or 0x5A85;           // Apollo Lake
        }
        return false;
    }

    public static async Task<IntelDriver?> FindAsync(DeviceInfo gpu, CancellationToken ct)
    {
        string page = IsLegacy(gpu) ? LegacyPage : ModernPage;
        string html = await Downloader.GetStringAsync(page, 40, ct);
        string Meta(string name) => Regex.Match(html, $@"<meta\s+name=""{name}""\s+content=""([^""]*)""") is { Success: true } m
            ? System.Net.WebUtility.HtmlDecode(m.Groups[1].Value) : "";
        string version = Meta("DownloadVersion").Trim();
        string url = Meta("RecommendedDownloadUrl").Trim();
        if (!Version.TryParse(version, out var latest) || url.Length == 0) return null;
        if (Version.TryParse(gpu.Version, out var have) && latest <= have) return null;

        DateTime? released = DateTime.TryParse(Meta("LastUpdate").Split(' ')[0], System.Globalization.CultureInfo.GetCultureInfo("en-US"),
            System.Globalization.DateTimeStyles.None, out var dt) ? dt : null;
        // Intel labels the release notes: ReleaseNotes_101.9175_Non-WHQL.pdf or ..._WHQL.pdf.
        bool whql = !Regex.IsMatch(html, @"(?i)ReleaseNotes_[\d.]+_Non-WHQL");
        return new IntelDriver(version, whql, released, url, page);
    }

    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(string downloadUrl, string version, string deviceId, Action<string, int> progress, CancellationToken ct)
    {
        var uri = new Uri(downloadUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !uri.Host.Equals("downloadmirror.intel.com", StringComparison.OrdinalIgnoreCase))
            return (false, "Intel's page pointed somewhere other than Intel's download servers, so nothing was installed.", false);

        string dir = Downloader.NewWorkFolder("intel");
        try
        {
            string file = Path.Combine(dir, Path.GetFileName(uri.AbsolutePath));
            await Downloader.DownloadAsync(downloadUrl, file, p => progress("Downloading", p), ct);

            progress("Checking Intel's signature", -1);
            if (!Downloader.IsSignedBy(file, "Intel", out string signer))
                return (false, $"The installer isn't signed by Intel{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.", false);

            progress("Installing (your screen will flicker)", -1);
            var psi = new ProcessStartInfo(file) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { "-s", "-o" }) psi.ArgumentList.Add(a); // silent; install even if same version is present
            using var p = Process.Start(psi)!;
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMinutes(30));
            try { await p.WaitForExitAsync(cts.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                return (false, "Intel's installer was still running after 30 minutes. Restart your PC, then check again.", false);
            }

            progress("Checking the result", -1);
            var gpu = DeviceInventory.Scan().FirstOrDefault(d => d.InstanceId.Equals(deviceId, StringComparison.OrdinalIgnoreCase));
            if (gpu is not null && Version.TryParse(gpu.Version, out var now) && Version.TryParse(version, out var wanted) && now >= wanted)
                return (true, "Installed", false);
            // Intel's installer: 0 done, 14 and 2 done but a restart is needed.
            if (p.ExitCode is 0 or 14 or 2)
                return (true, "Installed. Restart to finish.", true);
            return (false, $"Intel's installer finished with code {p.ExitCode} and the driver still reports {gpu?.Version ?? "the old version"}. Restart and check again.", false);
        }
        finally { Downloader.TryDelete(dir); }
    }
}
