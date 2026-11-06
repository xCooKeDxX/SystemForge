using System.Diagnostics;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SystemForge;

public sealed record UpdateInfo(string Version, string Notes, DateTime? Published, string MsiUrl, string ShaUrl, long SizeBytes, string PageUrl);
public sealed record UpdateCheck(string Current, bool Configured, UpdateInfo? Update, string Message, DateTime CheckedAt);

/// <summary>
/// Keeps SystemForge itself up to date from its GitHub Releases page. A release carries
/// SystemForge-Setup-x.y.z.msi and a .msi.sha256 next to it (build-msi.sh writes both). The MSI is verified
/// against that hash and, once releases are code-signed, against the signer's name, then handed to Windows
/// Installer to upgrade in place. Settings in AppData are kept.
/// </summary>
public static partial class Updater
{
    /// <summary>GitHub "owner/repo" that publishes releases. Empty until the project has a home.</summary>
    public const string Repo = "xCooKeDxX/SystemForge";

    /// <summary>Once releases are signed, put the certificate's subject name here and unsigned MSIs are refused.</summary>
    public const string ExpectedSigner = "";

    public static string CurrentVersion => typeof(Updater).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
    public static UpdateCheck? Last { get; private set; }

    public static async Task<UpdateCheck> CheckAsync(CancellationToken ct = default)
    {
        string current = CurrentVersion;
        if (Repo.Length == 0)
            return Last = new UpdateCheck(current, false, null, "Updates aren't set up yet: this build has no release page to check.", DateTime.Now);

        string json;
        try { json = await Downloader.GetStringAsync($"https://api.github.com/repos/{Repo}/releases/latest", 30, ct); }
        catch (HttpRequestException ex) when (ex.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return Last = new UpdateCheck(current, true, null, "No release has been published yet. You have the latest version.", DateTime.Now);
        }
        catch (HttpRequestException ex)
        {
            return Last = new UpdateCheck(current, true, null, $"Couldn't reach GitHub ({(ex.StatusCode is { } sc ? ((int)sc).ToString() : ex.Message)}). Try again later.", DateTime.Now);
        }
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string tag = root.GetProperty("tag_name").GetString() ?? "";
        var m = VersionRx().Match(tag);
        if (!m.Success || !Version.TryParse(m.Value, out var latest))
            return Last = new UpdateCheck(current, true, null, "The latest release has no version number in its tag.", DateTime.Now);
        if (!Version.TryParse(current, out var have)) have = new Version(0, 0, 0);

        string? msi = null, sha = null;
        long size = 0;
        if (root.TryGetProperty("assets", out var assets))
            foreach (var a in assets.EnumerateArray())
            {
                string name = a.GetProperty("name").GetString() ?? "";
                string url = a.GetProperty("browser_download_url").GetString() ?? "";
                if (name.EndsWith(".msi", StringComparison.OrdinalIgnoreCase)) { msi = url; size = a.TryGetProperty("size", out var s) ? s.GetInt64() : 0; }
                else if (name.EndsWith(".msi.sha256", StringComparison.OrdinalIgnoreCase)) sha = url;
            }

        string page = root.TryGetProperty("html_url", out var h) ? h.GetString() ?? "" : "";
        DateTime? published = root.TryGetProperty("published_at", out var p) && DateTime.TryParse(p.GetString(), out var dt) ? dt.ToLocalTime() : null;
        if (latest <= have) return Last = new UpdateCheck(current, true, null, "You have the latest version.", DateTime.Now);
        if (msi is null || sha is null) return Last = new UpdateCheck(current, true, null, $"Version {latest} is out, but its installer isn't attached to the release yet.", DateTime.Now);
        string notes = root.TryGetProperty("body", out var b) ? b.GetString() ?? "" : "";
        return Last = new UpdateCheck(current, true, new UpdateInfo(m.Value, notes, published, msi, sha, size, page), $"Version {latest} is available.", DateTime.Now);
    }

    /// <summary>Downloads and verifies the installer, then starts it and asks the app to quit so the files can be replaced.</summary>
    public static async Task<string> InstallAsync(UpdateInfo u, Action<string, int> progress, Action quitApp, CancellationToken ct = default)
    {
        foreach (var url in new[] { u.MsiUrl, u.ShaUrl })
        {
            var uri = new Uri(url);
            if (uri.Scheme != Uri.UriSchemeHttps || !(uri.Host.EndsWith("github.com", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith("githubusercontent.com", StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("The release points somewhere other than GitHub, so nothing was installed.");
        }

        string dir = Path.Combine(Downloader.DataRoot, "Updates");
        Downloader.EnsureSecureDataRoot();
        Directory.CreateDirectory(dir);
        string file = Path.Combine(dir, $"SystemForge-Setup-{u.Version}.msi");
        await Downloader.DownloadAsync(u.MsiUrl, file, p => progress("Downloading", p), ct);

        progress("Checking the download", -1);
        string expected = (await Downloader.GetStringAsync(u.ShaUrl, 30, ct)).Trim().Split(' ')[0].ToLowerInvariant();
        string actual = Downloader.Sha256Hex(file).ToLowerInvariant();
        if (!Regex.IsMatch(expected, "^[0-9a-f]{64}$") || expected != actual)
        {
            File.Delete(file);
            throw new InvalidOperationException("The downloaded installer doesn't match the release's checksum, so it wasn't run.");
        }
        if (ExpectedSigner.Length > 0 && !Downloader.IsSignedBy(file, ExpectedSigner, out string signer))
        {
            File.Delete(file);
            throw new InvalidOperationException($"The installer isn't signed by {ExpectedSigner}{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.");
        }

        progress("Starting the installer", -1);
        // /passive shows only a progress bar; the MSI closes this app itself before copying files.
        var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "msiexec.exe")) { UseShellExecute = true };
        foreach (var a in new[] { "/i", file, "/passive", "/norestart" }) psi.ArgumentList.Add(a);
        Process.Start(psi);
        _ = Task.Delay(1500, CancellationToken.None).ContinueWith(_ => quitApp());
        return $"Installing SystemForge {u.Version}. It reopens by itself when it's done.";
    }

    [GeneratedRegex(@"\d+\.\d+\.\d+")]
    private static partial Regex VersionRx();
}
