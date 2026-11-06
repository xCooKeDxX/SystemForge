using System.Diagnostics;
using System.Management;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

namespace SystemForge;

/// <summary>What this PC is, as the makers' catalogs identify it.</summary>
public sealed record PcIdentity(string Manufacturer, string Model, string Sku, string BaseBoard, string ProductName, string BiosVersion, DateTime? BiosDate, bool Laptop);

/// <summary>A BIOS/UEFI update from the PC's maker.</summary>
public sealed record FirmwareUpdate(
    string Vendor, string Title, string Version, DateTime? Released, string DownloadUrl, long SizeBytes, string? SizeText,
    string? Sha256, string? Md5, string Signer,
    string Command,              // how to run it silently; "{file}" and "{dir}" are filled in
    string? ExtractCommand,      // Lenovo: unpack first, then run Command from {dir}
    int[] OkCodes,
    bool Manual,                 // can't be run from Windows (EZ Flash zip): offer the download only
    string Note);

/// <summary>
/// BIOS updates straight from Lenovo, Dell, HP and ASUS, read from the same catalogs their own update tools use
/// (Lenovo System Update, Dell Command Update, HP Image Assistant, MyASUS). SystemForge only reports them and
/// links to the maker's download: flashing a BIOS is left to the maker's own updater on purpose.
/// </summary>
public static partial class OemFirmware
{
    public static PcIdentity Identify()
    {
        string man = "", model = "", sku = "", board = "", product = "", bios = "";
        DateTime? biosDate = null;
        try
        {
            using var cs = new ManagementObjectSearcher("SELECT Manufacturer, Model, SystemSKUNumber FROM Win32_ComputerSystem");
            foreach (ManagementObject o in cs.Get()) using (o) { man = S(o["Manufacturer"]); model = S(o["Model"]); sku = S(o["SystemSKUNumber"]); }
        }
        catch { }
        try
        {
            using var bb = new ManagementObjectSearcher("SELECT Product FROM Win32_BaseBoard");
            foreach (ManagementObject o in bb.Get()) using (o) board = S(o["Product"]);
        }
        catch { }
        try
        {
            using var cp = new ManagementObjectSearcher("SELECT Name, Version FROM Win32_ComputerSystemProduct");
            foreach (ManagementObject o in cp.Get()) using (o) product = S(o["Name"]);
        }
        catch { }
        try
        {
            using var b = new ManagementObjectSearcher("SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS");
            foreach (ManagementObject o in b.Get())
                using (o)
                {
                    bios = S(o["SMBIOSBIOSVersion"]);
                    string rd = S(o["ReleaseDate"]);
                    if (rd.Length >= 8 && DateTime.TryParseExact(rd[..8], "yyyyMMdd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var d)) biosDate = d;
                }
        }
        catch { }
        return new PcIdentity(man, model, sku, board, product, bios, biosDate, NvidiaDrivers.IsLaptop());
        static string S(object? v) => (v as string ?? "").Trim();
    }

    public static string? VendorOf(PcIdentity pc)
    {
        string m = pc.Manufacturer;
        if (m.Contains("LENOVO", StringComparison.OrdinalIgnoreCase)) return "Lenovo";
        if (m.Contains("Dell", StringComparison.OrdinalIgnoreCase)) return "Dell";
        if (m.StartsWith("HP", StringComparison.OrdinalIgnoreCase) || m.Contains("Hewlett", StringComparison.OrdinalIgnoreCase)) return "HP";
        if (m.Contains("ASUS", StringComparison.OrdinalIgnoreCase)) return "ASUS";
        return null;
    }

    public static async Task<FirmwareUpdate?> FindAsync(PcIdentity pc, CancellationToken ct) => VendorOf(pc) switch
    {
        "Lenovo" => await LenovoAsync(pc, ct),
        "Dell" => await DellAsync(pc, ct),
        "HP" => await HpAsync(pc, ct),
        "ASUS" => await AsusAsync(pc, ct),
        _ => null,
    };

    // ---- Lenovo: download.lenovo.com/catalog/<machine type>_Win11.xml ----

    static async Task<FirmwareUpdate?> LenovoAsync(PcIdentity pc, CancellationToken ct)
    {
        // ThinkPads: "20XWCTO1WW" → 20XW. IdeaPad/Legion: the model is the 4-character type itself ("82JW").
        string mt = (pc.ProductName.Length >= 4 ? pc.ProductName : pc.Model).Trim();
        if (mt.Length < 4) return null;
        mt = mt[..4].ToUpperInvariant();
        string biosPrefix = pc.BiosVersion.Split(' ')[0]; // "N32ET75W (1.51 )" → N32ET75W

        FirmwareUpdate? best = null;
        foreach (string os in new[] { "Win11", "Win10" })
        {
            string catalog;
            try { catalog = await Downloader.GetStringAsync($"https://download.lenovo.com/catalog/{mt}_{os}.xml", 30, ct); }
            catch (HttpRequestException) { continue; }
            foreach (Match pkg in Regex.Matches(catalog, @"<package>(.*?)</package>", RegexOptions.Singleline))
            {
                if (!Regex.IsMatch(pkg.Groups[1].Value, @"<category>\s*BIOS", RegexOptions.IgnoreCase)) continue;
                var loc = Regex.Match(pkg.Groups[1].Value, @"<location>\s*([^<]+?)\s*</location>");
                if (!loc.Success) continue;
                string descUrl = loc.Groups[1].Value;
                XDocument doc;
                try { doc = XDocument.Parse(await Downloader.GetStringAsync(descUrl, 30, ct)); } catch { continue; }
                var root = doc.Root!;

                // Already on this BIOS (DetectInstall), or not a BIOS this one upgrades from (Dependencies)?
                var detect = root.Element("DetectInstall")?.Descendants("Level").Select(l => l.Value.Trim()).ToList() ?? new();
                if (detect.Any(l => Wild(l, biosPrefix))) continue;
                var deps = root.Element("Dependencies")?.Descendants("_Bios").SelectMany(b => b.Elements("Level")).Select(l => l.Value.Trim()).ToList() ?? new();
                if (deps.Count > 0 && !deps.Any(l => Wild(l, biosPrefix))) continue;

                var installer = root.Element("Files")?.Element("Installer")?.Element("File");
                string? fileName = installer?.Element("Name")?.Value.Trim();
                if (fileName is null) continue;
                string url = descUrl[..(descUrl.LastIndexOf('/') + 1)] + fileName;
                string version = root.Attribute("version")?.Value ?? "";
                string cmd = root.Element("Install")?.Element("Cmdline")?.Value.Trim() ?? "";
                string? extract = root.Element("ExtractCommand")?.Value.Trim();
                var ok = (root.Element("Install")?.Attribute("rc")?.Value ?? "0").Split(',').Select(x => int.TryParse(x.Trim(), out int n) ? n : 0).Append(3010).Distinct().ToArray();
                DateTime? date = DateTime.TryParse(root.Element("ReleaseDate")?.Value, out var rd) ? rd : null;
                long.TryParse(installer?.Element("Size")?.Value, out long size);
                string title = root.Element("Title")?.Element("Desc")?.Value.Trim() ?? "BIOS Update";
                if (cmd.Length == 0) continue;
                var u = new FirmwareUpdate("Lenovo", title, version, date, url, size, null, installer?.Element("CRC")?.Value.Trim(), null, "Lenovo",
                    "", null, Array.Empty<int>(), true,
                    $"Lenovo has BIOS {version} for this {(pc.Laptop ? "laptop" : "PC")} (you have {biosPrefix}). Download runs Lenovo's own updater; plug in first and don't turn the PC off while it works.");
                if (best is null || (date ?? DateTime.MinValue) > (best.Released ?? DateTime.MinValue)) best = u;
            }
            if (best is not null) break;
        }
        return best;
    }

    internal static bool Wild(string pattern, string value)
    {
        string rx = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".") + "$";
        return Regex.IsMatch(value, rx, RegexOptions.IgnoreCase);
    }

    // ---- Dell: downloads.dell.com/catalog/CatalogIndexPC.cab → per-model cab ----

    static async Task<FirmwareUpdate?> DellAsync(PcIdentity pc, CancellationToken ct)
    {
        string sysId = pc.Sku.Trim().ToUpperInvariant();
        if (!Regex.IsMatch(sysId, @"^[0-9A-F]{4}$")) return null;

        string index = await CabXmlAsync("https://downloads.dell.com/catalog/CatalogIndexPC.cab", "CatalogIndexPC.xml", ct);
        var idx = XDocument.Parse(index);
        XNamespace ns = idx.Root!.GetDefaultNamespace();
        var group = idx.Root.Elements(ns + "GroupManifest")
            .FirstOrDefault(g => g.Descendants(ns + "Model").Any(m => (m.Attribute("systemID")?.Value ?? "").Equals(sysId, StringComparison.OrdinalIgnoreCase)));
        string? path = group?.Element(ns + "ManifestInformation")?.Attribute("path")?.Value;
        if (path is null) return null;

        string manifest = await CabXmlAsync("https://downloads.dell.com/" + path, null, ct);
        var man = XDocument.Parse(manifest);
        XNamespace mns = man.Root!.GetDefaultNamespace();
        FirmwareUpdate? best = null;
        Version? bestV = null;
        foreach (var c in man.Root.Elements(mns + "SoftwareComponent"))
        {
            if (!(c.Element(mns + "ComponentType")?.Attribute("value")?.Value ?? "").Equals("BIOS", StringComparison.OrdinalIgnoreCase)) continue;
            if (!c.Descendants(mns + "Model").Any(m => (m.Attribute("systemID")?.Value ?? "").Equals(sysId, StringComparison.OrdinalIgnoreCase))) continue;
            string ver = c.Attribute("vendorVersion")?.Value ?? "";
            var v = DellVersion(ver);
            if (v is null) continue;
            if (bestV is not null && v <= bestV) continue;
            bestV = v;
            string cpath = c.Attribute("path")?.Value ?? "";
            long.TryParse(c.Attribute("size")?.Value, out long size);
            DateTime? date = DateTime.TryParse(c.Attribute("releaseDate")?.Value, System.Globalization.CultureInfo.GetCultureInfo("en-US"), System.Globalization.DateTimeStyles.None, out var rd) ? rd : null;
            string? sha = c.Descendants(mns + "Hash").FirstOrDefault(h => (h.Attribute("algorithm")?.Value ?? "").Equals("SHA256", StringComparison.OrdinalIgnoreCase))?.Value;
            string title = c.Element(mns + "Name")?.Element(mns + "Display")?.Value.Trim() ?? "Dell System BIOS";
            best = new FirmwareUpdate("Dell", title, ver, date, "https://downloads.dell.com/" + cpath, size, null, sha, null, "Dell",
                "", null, Array.Empty<int>(), true, $"Dell has BIOS {ver} for this PC (you have {pc.BiosVersion}). Download runs Dell's own updater; plug in first and don't turn the PC off while it works.");
        }
        var have = DellVersion(pc.BiosVersion);
        if (best is null || (have is not null && bestV <= have)) return null;
        return best;
    }

    /// <summary>Dell BIOS versions are "1.6.4" on newer PCs and "A12" on older ones.</summary>
    static Version? DellVersion(string s)
    {
        var m = Regex.Match(s, @"\d+(\.\d+)+");
        if (m.Success && Version.TryParse(m.Value.Count(ch => ch == '.') == 0 ? m.Value + ".0" : m.Value, out var v)) return v;
        var a = Regex.Match(s, @"^A(\d{2})$", RegexOptions.IgnoreCase);
        return a.Success ? new Version(0, int.Parse(a.Groups[1].Value)) : null;
    }

    // ---- HP: hpia.hpcloud.hp.com/ref/<platform>/<platform>_64_<os>.<release>.cab ----

    static async Task<FirmwareUpdate?> HpAsync(PcIdentity pc, CancellationToken ct)
    {
        string platform = pc.BaseBoard.Trim().ToLowerInvariant();
        if (!Regex.IsMatch(platform, @"^[0-9a-f]{4}$")) return null;
        int build = Environment.OSVersion.Version.Build;
        string os = build >= 22000 ? "11.0" : "10.0";
        string? current = null;
        try { using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"); current = (k?.GetValue("DisplayVersion") as string)?.ToLowerInvariant(); } catch { }
        var releases = new[] { current, "25h2", "24h2", "23h2", "22h2", "21h2" }.Where(r => r is not null).Distinct().ToList();

        string? xml = null;
        foreach (var rel in releases)
        {
            try { xml = await CabXmlAsync($"https://hpia.hpcloud.hp.com/ref/{platform}/{platform}_64_{os}.{rel}.cab", null, ct); break; }
            catch (HttpRequestException) { }
        }
        if (xml is null) return null;

        var doc = XDocument.Parse(xml);
        var items = doc.Descendants().Where(e => e.Name.LocalName == "UpdateInfo");
        FirmwareUpdate? best = null;
        Version? bestV = null;
        foreach (var u in items)
        {
            string Get(string name) => u.Elements().FirstOrDefault(e => e.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase))?.Value.Trim() ?? "";
            string cat = Get("Category");
            if (!(cat.Equals("BIOS", StringComparison.OrdinalIgnoreCase) || cat.StartsWith("BIOS -", StringComparison.OrdinalIgnoreCase))) continue;
            var v = NumericVersion(Get("Version"));
            if (v is null || (bestV is not null && v <= bestV)) continue;
            bestV = v;
            string url = Get("Url");
            if (url.Length == 0) continue;
            if (!url.StartsWith("http", StringComparison.OrdinalIgnoreCase)) url = "https://" + url;
            long.TryParse(Get("Size"), out long size);
            DateTime? date = DateTime.TryParse(Get("DateReleased"), out var rd) ? rd : null;
            best = new FirmwareUpdate("HP", Get("Name").Length > 0 ? Get("Name") : "HP System BIOS", Get("Version"), date, url, size, null, null, Get("MD5"), "HP Inc.",
                "", null, Array.Empty<int>(), true, $"HP has BIOS {Get("Version")} for this PC (you have {pc.BiosVersion}). Download runs HP's own updater; plug in first and don't turn the PC off while it works.");
        }
        var have = NumericVersion(pc.BiosVersion);
        if (best is null || (have is not null && bestV <= have)) return null;
        return best;
    }

    /// <summary>"T76 Ver. 01.08.00" / "01.08.00 A 1" → 1.8.0.</summary>
    static Version? NumericVersion(string s)
    {
        var m = Regex.Match(s, @"\d+(\.\d+)+");
        return m.Success && Version.TryParse(m.Value, out var v) ? v : null;
    }

    // ---- ASUS: www.asus.com/support/api/product.asmx/GetPDBIOS ----

    static async Task<FirmwareUpdate?> AsusAsync(PcIdentity pc, CancellationToken ct)
    {
        string model = pc.BaseBoard.Trim();
        if (model.Length < 3) return null;
        string json = await Downloader.GetStringAsync($"https://www.asus.com/support/api/product.asmx/GetPDBIOS?website=global&model={Uri.EscapeDataString(model)}&pdhashedid=", 30, ct);
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty("Result", out var result) || result.ValueKind != JsonValueKind.Object) return null;

        // Installed: "FA506IV.320" → 320, desktop boards "4004" → 4004.
        var mv = Regex.Match(pc.BiosVersion, @"(\d+)\s*$");
        int have = mv.Success ? int.Parse(mv.Groups[1].Value) : -1;

        (int ver, JsonElement file, bool exe)? best = null;
        foreach (var group in result.GetProperty("Obj").EnumerateArray())
        {
            string gname = group.GetProperty("Name").GetString() ?? "";
            bool exe = gname.Contains("Windows", StringComparison.OrdinalIgnoreCase);
            foreach (var f in group.GetProperty("Files").EnumerateArray())
            {
                if (!int.TryParse(Regex.Match(f.GetProperty("Version").GetString() ?? "", @"\d+").Value, out int ver)) continue;
                string url = f.GetProperty("DownloadUrl").GetProperty("Global").GetString() ?? "";
                if (url.Length == 0) continue;
                // Prefer the Windows updater; the EZ Flash zip only when it's strictly newer than any updater.
                if (best is null || ver > best.Value.ver || (ver == best.Value.ver && exe && !best.Value.exe)) best = (ver, f, exe);
            }
        }
        if (best is null || best.Value.ver <= have) return null;
        var (bv, bf, isExe) = best.Value;
        string durl = bf.GetProperty("DownloadUrl").GetProperty("Global").GetString()!;
        DateTime? date = DateTime.TryParseExact(bf.GetProperty("ReleaseDate").GetString(), "yyyy/MM/dd", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None, out var rd) ? rd : null;
        string sha = bf.TryGetProperty("sha256", out var sh) ? sh.GetString() ?? "" : "";
        string size = bf.TryGetProperty("FileSize", out var fs) ? fs.GetString() ?? "" : "";
        if (isExe)
        {
            // "ASUS_FA506IV_320_BIOS_Update_3.exe%%/SUPPRESSMSGBOXES /VERYSILENT /NORESTART"
            string exeModule = bf.TryGetProperty("ExeModule", out var em) ? em.GetString() ?? "" : "";
            string args = exeModule.Contains("%%") ? exeModule[(exeModule.IndexOf("%%") + 2)..].Trim() : "/SUPPRESSMSGBOXES /VERYSILENT /NORESTART";
            return new FirmwareUpdate("ASUS", "BIOS Update for Windows", bv.ToString(), date, durl, 0, size, sha.Length > 0 ? sha : null, null, "ASUSTeK",
                "", null, Array.Empty<int>(), true, $"ASUS has BIOS {bv} for this PC (you have {have}). Download runs ASUS's own updater; plug in first and don't turn the PC off while it works.");
        }
        return new FirmwareUpdate("ASUS", "BIOS (ASUS EZ Flash)", bv.ToString(), date, durl, 0, size, sha.Length > 0 ? sha : null, null, "ASUSTeK",
            "", null, Array.Empty<int>(), true,
            $"ASUS has BIOS {bv} for this board (you have {have}). It's a file for EZ Flash: download it, put it on a USB stick, restart into the BIOS screen and use EZ Flash to apply it.");
    }

    // ---- no install ----
    // BIOS flashing is the one thing that can leave a PC unable to start, so SystemForge never does it. It only
    // notices that the maker has a newer BIOS and opens the maker's own download, whose updater has its own
    // battery, BitLocker and version checks.

    /// <summary>Downloads a .cab and extracts its (first, or named) XML with Windows' expand.exe.</summary>
    internal static async Task<string> CabXmlAsync(string url, string? fileName, CancellationToken ct)
    {
        string dir = Downloader.NewWorkFolder("cab");
        try
        {
            string cab = Path.Combine(dir, "a.cab");
            await Downloader.DownloadAsync(url, cab, null, ct);
            var psi = new ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "expand.exe")) { UseShellExecute = false, CreateNoWindow = true };
            foreach (var a in new[] { cab, "-F:*", dir }) psi.ArgumentList.Add(a);
            using (var p = Process.Start(psi)!) await p.WaitForExitAsync(ct);
            string? xml = fileName is not null ? Path.Combine(dir, fileName) : Directory.GetFiles(dir, "*.xml").FirstOrDefault();
            if (xml is null || !File.Exists(xml)) throw new InvalidOperationException($"{new Uri(url).Host} sent a package without the expected catalog.");
            return await File.ReadAllTextAsync(xml, ct);
        }
        finally { Downloader.TryDelete(dir); }
    }
}
