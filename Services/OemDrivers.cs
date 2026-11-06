using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace SystemForge;

/// <summary>A device driver package from the PC's maker, matched to hardware on this PC.</summary>
public sealed record OemDriver(
    string Vendor, string Title, string Category, string DeviceClass, string Version, DateTime? Released,
    string DownloadUrl, long SizeBytes, string? Sha256, string Signer,
    string Command, string? ExtractCommand, int[] OkCodes, string[] HardwareIds);

/// <summary>
/// Drivers from Lenovo's and Dell's own catalogs (the same ones System Update and Command Update read), matched
/// to this PC's devices by hardware ID. Makers often ship audio, touchpad, camera and Wi-Fi drivers tuned for the
/// exact model before Windows Update has them. Installers are checked against the maker's checksum and signature.
/// </summary>
public static partial class OemDrivers
{
    static readonly HashSet<string> SkipCategories = new(StringComparer.OrdinalIgnoreCase) { "BIOS UEFI", "Software and Utilities", "Patch", "Product Firmware", "Diagnostic", "Enterprise Management", "Storage" };

    public static async Task<List<(OemDriver driver, List<DeviceInfo> devices)>> FindAsync(PcIdentity pc, List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        return OemFirmware.VendorOf(pc) switch
        {
            "Lenovo" => await LenovoAsync(pc, devices, build, ct),
            "Dell" => await DellAsync(pc, devices, build, ct),
            _ => new(),
        };
    }

    // ---- Lenovo ----

    static async Task<List<(OemDriver, List<DeviceInfo>)>> LenovoAsync(PcIdentity pc, List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        var result = new List<(OemDriver, List<DeviceInfo>)>();
        string mt = (pc.ProductName.Length >= 4 ? pc.ProductName : pc.Model).Trim();
        if (mt.Length < 4) return result;
        mt = mt[..4].ToUpperInvariant();
        string catalog;
        try { catalog = await Downloader.GetStringAsync($"https://download.lenovo.com/catalog/{mt}_{(build >= 22000 ? "Win11" : "Win10")}.xml", 30, ct); }
        catch (HttpRequestException) { return result; }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match pkg in Regex.Matches(catalog, @"<package>(.*?)</package>", RegexOptions.Singleline))
        {
            string cat = Regex.Match(pkg.Groups[1].Value, @"<category>\s*([^<]*?)\s*</category>").Groups[1].Value;
            if (cat.Length == 0 || SkipCategories.Contains(cat)) continue;
            var loc = Regex.Match(pkg.Groups[1].Value, @"<location>\s*([^<]+?)\s*</location>");
            if (!loc.Success) continue;
            XDocument doc;
            try { doc = XDocument.Parse(await Downloader.GetStringAsync(loc.Groups[1].Value, 30, ct)); } catch { continue; }
            var root = doc.Root!;
            var detect = root.Element("DetectInstall")?.Element("_Driver");
            if (detect is null) continue; // not a plain driver package (utilities, firmware with odd detection)

            var ids = detect.Elements("HardwareID").Select(h => h.Value.Trim()).Where(h => h.Length > 0).ToArray();
            string verText = (detect.Element("Version")?.Value ?? "").TrimEnd('^').Trim();
            if (ids.Length == 0 || !Version.TryParse(verText, out var ver)) continue;

            // Devices on this PC with one of those IDs and an older driver.
            var hits = devices.Where(d => d.Present && d.HardwareIds.Concat(d.CompatibleIds).Any(h => ids.Any(id => h.Contains(id, StringComparison.OrdinalIgnoreCase))))
                .Where(d => !Version.TryParse(d.Version, out var have) || have < ver).ToList();
            if (hits.Count == 0) continue;

            var installer = root.Element("Files")?.Element("Installer")?.Element("File");
            string? fileName = installer?.Element("Name")?.Value.Trim();
            string cmd = root.Element("Install")?.Element("Cmdline")?.Value.Trim() ?? "";
            if (fileName is null || cmd.Length == 0) continue;
            string descUrl = loc.Groups[1].Value;
            string url = descUrl[..(descUrl.LastIndexOf('/') + 1)] + fileName;
            if (!seen.Add(url)) continue;
            var ok = (root.Element("Install")?.Attribute("rc")?.Value ?? "0").Split(',').Select(x => int.TryParse(x.Trim(), out int n) ? n : 0).Append(3010).Distinct().ToArray();
            DateTime? date = DateTime.TryParse(root.Element("ReleaseDate")?.Value, out var rd) ? rd : null;
            long.TryParse(installer?.Element("Size")?.Value, out long size);
            string title = root.Element("Title")?.Element("Desc")?.Value.Trim() ?? cat;
            string? extract = root.Element("ExtractCommand")?.Value.Trim();
            result.Add((new OemDriver("Lenovo", title, cat, hits[0].Class, ver.ToString(), date, url, size, installer?.Element("CRC")?.Value.Trim(), "Lenovo",
                cmd.Replace("%PACKAGEPATH%", "{dir}"),
                extract?.Replace("%PACKAGEPATH%", "{dir}").Replace(fileName, "{file}", StringComparison.OrdinalIgnoreCase), ok, ids), hits));
        }
        return result;
    }

    // ---- Dell ----

    static readonly Dictionary<string, string> DellClass = new(StringComparer.OrdinalIgnoreCase)
    {
        ["AU"] = "MEDIA", ["NI"] = "Net", ["CM"] = "Net", ["VI"] = "Display", ["IN"] = "HIDClass", ["MO"] = "Modem", ["CS"] = "System",
        ["SA"] = "SCSIAdapter", ["CM1"] = "Net",
    };

    static async Task<List<(OemDriver, List<DeviceInfo>)>> DellAsync(PcIdentity pc, List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        var result = new List<(OemDriver, List<DeviceInfo>)>();
        string sysId = pc.Sku.Trim().ToUpperInvariant();
        if (!Regex.IsMatch(sysId, @"^[0-9A-F]{4}$")) return result;

        var idx = XDocument.Parse(await OemFirmware.CabXmlAsync("https://downloads.dell.com/catalog/CatalogIndexPC.cab", "CatalogIndexPC.xml", ct));
        XNamespace ns = idx.Root!.GetDefaultNamespace();
        var group = idx.Root.Elements(ns + "GroupManifest")
            .FirstOrDefault(g => g.Descendants(ns + "Model").Any(m => (m.Attribute("systemID")?.Value ?? "").Equals(sysId, StringComparison.OrdinalIgnoreCase)));
        string? path = group?.Element(ns + "ManifestInformation")?.Attribute("path")?.Value;
        if (path is null) return result;
        var man = XDocument.Parse(await OemFirmware.CabXmlAsync("https://downloads.dell.com/" + path, null, ct));
        XNamespace mns = man.Root!.GetDefaultNamespace();

        // Newest package per device set.
        var best = new Dictionary<string, (Version v, OemDriver d, List<DeviceInfo> hits)>(StringComparer.OrdinalIgnoreCase);
        foreach (var c in man.Root.Elements(mns + "SoftwareComponent"))
        {
            if (!(c.Element(mns + "ComponentType")?.Attribute("value")?.Value ?? "").Equals("DRVR", StringComparison.OrdinalIgnoreCase)) continue;
            if (!c.Descendants(mns + "Model").Any(m => (m.Attribute("systemID")?.Value ?? "").Equals(sysId, StringComparison.OrdinalIgnoreCase))) continue;
            // Windows 10/11 64-bit packages only.
            if (!c.Descendants(mns + "OperatingSystem").Any(o => o.Attribute("majorVersion")?.Value == "10" && (o.Attribute("osArch")?.Value ?? "").Equals("x64", StringComparison.OrdinalIgnoreCase))) continue;
            string cpath = c.Attribute("path")?.Value ?? "";
            if (!cpath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) continue;
            if (!Version.TryParse(c.Attribute("vendorVersion")?.Value ?? "", out var ver)) continue;

            var pci = c.Descendants(mns + "PCIInfo").Select(p => (ven: p.Attribute("vendorID")?.Value ?? "", dev: p.Attribute("deviceID")?.Value ?? "")).Where(x => x.ven.Length == 4 && x.dev.Length == 4).ToList();
            if (pci.Count == 0) continue;
            var ids = pci.Select(x => $"VEN_{x.ven}&DEV_{x.dev}").Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var hits = devices.Where(d => d.Present && d.HardwareIds.Any(h => ids.Any(id => h.Contains(id, StringComparison.OrdinalIgnoreCase))))
                .Where(d => !Version.TryParse(d.Version, out var have) || have < ver).ToList();
            if (hits.Count == 0) continue;

            string key = string.Join("|", hits.Select(h => h.InstanceId).OrderBy(x => x));
            if (best.TryGetValue(key, out var cur) && cur.v >= ver) continue;
            string catCode = c.Element(mns + "Category")?.Attribute("value")?.Value ?? "";
            string catName = c.Element(mns + "Category")?.Element(mns + "Display")?.Value.Trim() ?? "Driver";
            long.TryParse(c.Attribute("size")?.Value, out long size);
            DateTime? date = DateTime.TryParse(c.Attribute("releaseDate")?.Value, System.Globalization.CultureInfo.GetCultureInfo("en-US"), System.Globalization.DateTimeStyles.None, out var rd) ? rd : null;
            string? sha = c.Descendants(mns + "Hash").FirstOrDefault(h => (h.Attribute("algorithm")?.Value ?? "").Equals("SHA256", StringComparison.OrdinalIgnoreCase))?.Value;
            string title = c.Element(mns + "Name")?.Element(mns + "Display")?.Value.Trim() ?? catName;
            best[key] = (ver, new OemDriver("Dell", title, catName, DellClass.GetValueOrDefault(catCode, hits[0].Class), ver.ToString(), date,
                "https://downloads.dell.com/" + cpath, size, sha, "Dell", "\"{file}\" /s", null, new[] { 0, 2, 3010 }, ids), hits);
        }
        foreach (var (_, d, hits) in best.Values) result.Add((d, hits));
        return result;
    }

    // ---- install ----

    public static async Task<(bool ok, string message, bool reboot)> InstallAsync(OemDriver u, List<string> deviceIds, Action<string, int> progress, CancellationToken ct)
    {
        var uri = new Uri(u.DownloadUrl);
        if (uri.Scheme != Uri.UriSchemeHttps || !(uri.Host.EndsWith("lenovo.com", StringComparison.OrdinalIgnoreCase) || uri.Host.EndsWith("dell.com", StringComparison.OrdinalIgnoreCase)))
            return (false, $"The package points at {uri.Host}, which isn't the maker's download server, so nothing was run.", false);

        string dir = Downloader.NewWorkFolder("oem");
        try
        {
            string file = Path.Combine(dir, Path.GetFileName(uri.AbsolutePath));
            await Downloader.DownloadAsync(u.DownloadUrl, file, p => progress("Downloading", p), ct);
            progress("Checking the file", -1);
            if (u.Sha256 is { Length: > 0 } sha && !Downloader.Sha256Hex(file).Equals(sha, StringComparison.OrdinalIgnoreCase))
                return (false, "The download doesn't match the maker's checksum, so it wasn't run.", false);
            if (!Downloader.IsSignedBy(file, u.Signer, out string signer))
                return (false, $"The installer isn't signed by {u.Vendor}{(signer.Length > 0 ? $" (signed by {signer})" : "")}, so it wasn't run.", false);

            string work = dir;
            if (u.ExtractCommand is { Length: > 0 } ex)
            {
                work = Path.Combine(dir, "pkg");
                Directory.CreateDirectory(work);
                progress("Unpacking", -1);
                int rc = await RunAsync(ex.Replace("{file}", file).Replace("{dir}", work), dir, TimeSpan.FromMinutes(5), ct);
                if (rc != 0) return (false, $"The package didn't unpack (code {rc}).", false);
            }
            progress("Installing", -1);
            int code = await RunAsync(u.Command.Replace("{file}", file).Replace("{dir}", work), work, TimeSpan.FromMinutes(20), ct);

            progress("Checking the result", -1);
            var now = DeviceInventory.Scan().Where(d => deviceIds.Contains(d.InstanceId, StringComparer.OrdinalIgnoreCase)).ToList();
            bool updated = now.Count > 0 && Version.TryParse(u.Version, out var want) && now.All(d => Version.TryParse(d.Version, out var v) && v >= want);
            if (updated) return (true, code == 3010 || code == 2 ? "Installed. Restart to finish." : "Installed", code is 3010 or 2);
            if (u.OkCodes.Contains(code)) return (true, "Installed. Restart to finish.", true);
            return (false, $"{u.Vendor}'s installer stopped with code {code} and the device still reports {now.FirstOrDefault()?.Version ?? "the old driver"}.", false);
        }
        finally { if (!u.OkCodes.Contains(3010)) Downloader.TryDelete(dir); }
    }

    static async Task<int> RunAsync(string commandLine, string workDir, TimeSpan limit, CancellationToken ct)
    {
        var psi = new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, WorkingDirectory = workDir };
        psi.ArgumentList.Add("/d"); psi.ArgumentList.Add("/c"); psi.ArgumentList.Add(commandLine);
        using var p = Process.Start(psi)!;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(limit);
        try { await p.WaitForExitAsync(cts.Token); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested) { return -1; }
        return p.ExitCode;
    }
}
