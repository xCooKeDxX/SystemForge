using System.Text.RegularExpressions;

namespace SystemForge;

/// <summary>One thing that can be updated on the Drivers page, whichever source it came from.</summary>
public sealed record UpdateOffer(
    string Key,
    string Source,          // "wu" Windows Update, "catalog" Microsoft Update Catalog, "nvidia", "winget"
    string Group,           // "device", "unplugged", "game"
    string Name,
    string Publisher,
    string DeviceClass,
    string? CurrentVersion,
    DateTime? CurrentDate,
    string NewVersion,
    DateTime? NewDate,
    long SizeBytes,
    string? SizeText,
    int DeviceCount,
    string Note)
{
    /// <summary>Boot-critical or firmware: only offered with Advanced driver options on.</summary>
    public bool Critical { get; init; }
    public string RiskNote { get; init; } = "";
    /// <summary>Can't be installed from Windows (e.g. an EZ Flash BIOS file): the dashboard offers the download only.</summary>
    public bool Manual { get; init; }
    public string? InfoUrl { get; init; }
}

public sealed record SourceStatus(string Source, bool Ok, int Found, string Message);
public sealed record DriverCheck(List<UpdateOffer> Offers, List<SourceStatus> Sources, DateTime CheckedAt, int DevicesChecked);

/// <summary>Runs every source at once, merges what they find and installs whatever the user picks.</summary>
public static partial class DriverUpdates
{
    /// <summary>winget ids that are game/app runtimes rather than programs you'd think of as apps.</summary>
    public static readonly string[] RuntimePrefixes =
    {
        "Microsoft.VCRedist.", "Microsoft.DirectX", "Nvidia.PhysX", "Microsoft.XNARedist",
        "Microsoft.DotNet.DesktopRuntime.", "Microsoft.DotNet.Runtime.", "Microsoft.DotNet.Framework.",
    };

    public static bool IsRuntime(string wingetId) =>
        RuntimePrefixes.Any(p => wingetId.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    /// <summary>What each offer needs to install: kept here, so the dashboard only ever sends back keys.</summary>
    sealed record Plan(UpdateOffer Offer, string Source, string Payload, List<DeviceInfo> Devices, bool WingetInstall = false);

    static readonly object Gate = new();
    static Dictionary<string, Plan> plans = new();

    public static async Task<DriverCheck> CheckAsync(Action<string, int, int> progress, CancellationToken ct = default)
    {
        int build = Environment.OSVersion.Version.Build;
        progress("Listing devices", 0, 0);
        var devices = await Task.Run(DeviceInventory.Scan, ct);
        var statuses = new List<SourceStatus>();
        var found = new List<Plan>();

        var wu = Task.Run(() => FromWindowsUpdate(devices), ct);
        var nv = FromNvidiaAsync(devices, build, ct);
        var amd = FromAmdAsync(devices, build, ct);
        var intel = FromIntelAsync(devices, ct);
        var oem = FromOemAsync(devices, build, ct);
        var wg = FromWingetAsync(ct);
        var cat = FromCatalogAsync(devices, build, (done, total) => progress("Searching the Microsoft Update Catalog", done, total), ct);

        async Task Collect(string source, Task<List<Plan>> task)
        {
            try
            {
                var list = await task;
                found.AddRange(list);
                statuses.Add(new SourceStatus(source, true, list.Count, ""));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                statuses.Add(new SourceStatus(source, false, 0, ex.Message));
            }
        }

        await Collect("wu", wu);
        await Collect("nvidia", nv);
        await Collect("amd", amd);
        await Collect("intel", intel);
        await Collect("oem", oem);
        await Collect("winget", wg);
        await Collect("catalog", cat);

        var merged = Merge(found);
        lock (Gate) plans = merged.GroupBy(p => p.Offer.Key).ToDictionary(g => g.Key, g => g.First());
        merged = plans.Values.ToList();

        var offers = merged.Select(p => p.Offer with
            {
                Critical = DriverGuard.IsCritical(p.Offer.DeviceClass),
                RiskNote = DriverGuard.RiskNote(p.Offer.DeviceClass),
            })
            .OrderBy(o => o.Group switch { "device" => 0, "game" => 1, _ => 2 })
            .ThenBy(o => o.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();
        int checkedCount = devices.Count(DriverCatalog.IsCandidate);
        return new DriverCheck(offers, statuses, DateTime.Now, checkedCount);
    }

    // ---- sources ----

    static List<Plan> FromWindowsUpdate(List<DeviceInfo> devices)
    {
        var plansOut = new List<Plan>();
        foreach (var u in WindowsUpdateService.FindDriverUpdates())
        {
            var dev = devices.FirstOrDefault(d => d.Present && u.HardwareId.Length > 0 &&
                          d.HardwareIds.Concat(d.CompatibleIds).Any(id => id.Equals(u.HardwareId, StringComparison.OrdinalIgnoreCase)))
                      ?? devices.FirstOrDefault(d => d.Present && u.Model.Length > 0 && d.Name.Equals(u.Model, StringComparison.OrdinalIgnoreCase));
            string version = VersionInTitle(u.Title) ?? "";
            var offer = new UpdateOffer("wu:" + u.UpdateId, "wu", "device",
                dev?.Name ?? (u.Model.Length > 0 ? u.Model : u.Title),
                FirstNonEmpty(u.Provider, u.Manufacturer, dev?.Provider),
                FirstNonEmpty(dev?.Class, u.DeviceClass),
                dev?.Version, dev?.Date, version, u.Date, u.DownloadSizeBytes, null, 1,
                dev is null ? "Windows Update offers this for your PC." : "");
            plansOut.Add(new Plan(offer, "wu", u.UpdateId, dev is null ? new() : new() { dev }));
        }
        return plansOut;
    }

    static async Task<List<Plan>> FromCatalogAsync(List<DeviceInfo> devices, int build, Action<int, int> progress, CancellationToken ct)
    {
        // Identical devices (the same mouse seen on two USB ports, an old Bluetooth pairing…) are looked up once,
        // using the connected one; the result must also be newer than every connected twin's driver.
        var groups = devices.Where(DriverCatalog.IsCandidate)
            .GroupBy(d => d.HardwareIds[0], StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Present).ThenByDescending(x => x.Date ?? DateTime.MinValue).ToList())
            .ToList();
        int done = 0;
        progress(0, groups.Count);

        var results = await Task.WhenAll(groups.Select(async g =>
        {
            var d = g[0];
            try
            {
                var drv = await DriverCatalog.FindAsync(d, build, ct);
                if (drv is not null && g.Where(x => x.Present && x.HasDriver).Any(x => !DriverCatalog.IsNewerThan(drv, x))) drv = null;
                return (d, drv);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { return (d, drv: (CatalogDriver?)null); }
            finally { progress(Interlocked.Increment(ref done), groups.Count); }
        }));

        // One package can fit several devices (an audio driver for the codec and its extension, say): offer it once.
        return results.Where(r => r.drv is not null)
            .GroupBy(r => r.drv!.UpdateId, StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var first = g.First();
                var devs = g.Select(x => x.d).ToList();
                bool unplugged = devs.All(x => !x.Present);
                var offer = new UpdateOffer("cat:" + first.drv!.UpdateId, "catalog", unplugged ? "unplugged" : "device",
                    devs.Count > 1 ? $"{first.d.Name} and {devs.Count - 1} more" : first.d.Name,
                    FirstNonEmpty(first.drv.Provider, first.d.Provider, first.d.Manufacturer),
                    FirstNonEmpty(first.d.Class, first.drv.Class),
                    first.d.HasDriver ? first.d.Version : null, first.d.Date,
                    first.drv.Version, first.drv.Date, first.drv.SizeBytes, null, devs.Count,
                    unplugged ? "Not connected now. Windows uses the new driver the next time you plug it in."
                              : first.d.HasDriver ? "" : "This device has no driver yet.");
                return new Plan(offer, "catalog", first.drv.UpdateId, devs);
            }).ToList();
    }

    static async Task<List<Plan>> FromNvidiaAsync(List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        var list = new List<Plan>();
        foreach (var gpu in devices.Where(NvidiaDrivers.IsNvidiaGpu))
        {
            var drv = await NvidiaDrivers.FindAsync(gpu, build, ct);
            if (drv is null) continue;
            int? current = NvidiaDrivers.ToNvidiaNumber(gpu.Version);
            var offer = new UpdateOffer($"nv:{gpu.InstanceId}", "nvidia", "device", gpu.Name, "NVIDIA", gpu.Class,
                current is null ? gpu.Version : NvidiaDrivers.Format(current.Value), gpu.Date,
                drv.Version, drv.Released, 0, drv.Size, 1,
                $"{drv.Name}{(drv.Notebook ? " (laptop version)" : "")}. Your screen flickers while it installs.");
            list.Add(new Plan(offer, "nvidia", drv.DownloadUrl, new() { gpu }));
        }
        return list;
    }

    static async Task<List<Plan>> FromAmdAsync(List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        var list = new List<Plan>();
        string cpu = HealthMonitor.Info.Cpu;

        // Desktop Ryzen boards: AMD's own chipset package (USB, SMBus, PCI, power plans). Laptops get theirs from the maker.
        if (cpu.Contains("AMD", StringComparison.OrdinalIgnoreCase) && !NvidiaDrivers.IsLaptop())
        {
            var chip = await AmdDrivers.FindChipsetAsync(ct);
            if (chip is not null)
            {
                var installed = AmdDrivers.InstalledChipsetVersion();
                var offer = new UpdateOffer("amdchip:" + chip.Chipset, "amd", "device", $"AMD {chip.Chipset} chipset drivers", "AMD", "Chipset",
                    installed?.ToString(), null, chip.Version, chip.Released, 0, chip.Size, 1,
                    installed is null ? "AMD's chipset package isn't installed. It adds the proper USB, SMBus and power drivers for this board and AMD's Ryzen power plan."
                                      : "AMD's chipset package: USB, SMBus, PCI and power drivers for this board. A restart finishes it.");
                list.Add(new Plan(offer, "amdchip", chip.DownloadUrl + "|" + chip.PageUrl, new()));
            }
        }

        var gpus = devices.Where(AmdDrivers.IsAmdGpu).ToList();
        if (gpus.Count == 0) return list;
        foreach (var gpu in gpus)
        {
            var drv = await AmdDrivers.FindAsync(gpu, cpu, build, ct);
            if (drv is null) continue;
            string current = AmdDrivers.InstalledVersion() ?? gpu.Version;
            var offer = new UpdateOffer($"amd:{gpu.InstanceId}", "amd", "device", gpu.Name, "AMD", gpu.Class,
                current, gpu.Date, drv.Version, drv.Released, 0, drv.Size, 1,
                $"AMD Software: Adrenalin Edition {drv.Version}{(drv.Recommended ? " (Recommended)" : " (Optional, WHQL-certified)")}. Your screen flickers while it installs.");
            list.Add(new Plan(offer, "amd", drv.DownloadUrl, new() { gpu }));
        }
        return list;
    }

    static async Task<List<Plan>> FromIntelAsync(List<DeviceInfo> devices, CancellationToken ct)
    {
        var list = new List<Plan>();
        foreach (var gpu in devices.Where(IntelDrivers.IsIntelGpu))
        {
            var drv = await IntelDrivers.FindAsync(gpu, ct);
            if (drv is null) continue;
            var offer = new UpdateOffer($"intel:{gpu.InstanceId}", "intel", "device", gpu.Name, "Intel", gpu.Class,
                gpu.Version, gpu.Date, drv.Version, drv.Released, 0, null, 1,
                drv.Whql ? "Intel's latest graphics driver. Your screen flickers while it installs."
                         : "Intel's newest driver, not yet WHQL-certified by Microsoft. Fine for most people; skip it if you'd rather wait for the certified one.");
            list.Add(new Plan(offer, "intel", drv.DownloadUrl, new() { gpu }));
        }
        return list;
    }

    /// <summary>A newer BIOS from the PC's maker, as a notice with the maker's download. Never installed by SystemForge.</summary>
    static async Task<List<Plan>> FromOemAsync(List<DeviceInfo> devices, int build, CancellationToken ct)
    {
        var list = new List<Plan>();
        var pc = OemFirmware.Identify();
        string? vendor = OemFirmware.VendorOf(pc);
        if (vendor is null) return list;

        var bios = OemFirmware.FindAsync(pc, ct);
        var drivers = OemDrivers.FindAsync(pc, devices, build, ct);
        Exception? first = null;
        try
        {
            var u = await bios;
            if (u is not null)
                list.Add(new Plan(new UpdateOffer("oem:bios", "oem", "device", $"{vendor} BIOS ({pc.Model.Trim()})", vendor, "Firmware",
                    pc.BiosVersion, pc.BiosDate, u.Version, u.Released, u.SizeBytes, u.SizeText, 1, u.Note) { Manual = true, InfoUrl = u.DownloadUrl },
                    "oem", "", new()));
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { first = ex; }
        try
        {
            foreach (var (d, hits) in await drivers)
            {
                var offer = new UpdateOffer("oemdrv:" + d.DownloadUrl.GetHashCode(), "oem", "device", hits.Count == 1 ? hits[0].Name : d.Title, vendor, d.DeviceClass,
                    hits[0].Version, hits[0].Date, d.Version, d.Released, d.SizeBytes, null, hits.Count,
                    $"{d.Title} from {vendor}, made for this model.");
                list.Add(new Plan(offer, "oemdrv", System.Text.Json.JsonSerializer.Serialize(d), hits));
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
        catch (Exception ex) { first ??= ex; }
        if (list.Count == 0 && first is not null) throw first;
        return list;
    }

    static async Task<List<Plan>> FromWingetAsync(CancellationToken ct)
    {
        var list = new List<Plan>();
        if (!Winget.IsAvailable) throw new InvalidOperationException("winget (App Installer) isn't installed, so game components can't be checked.");

        // winget can list one id twice (x86 and x64 installs of the same runtime): one offer per id.
        foreach (var p in (await Winget.UpgradesAsync(ct)).Where(p => IsRuntime(p.Id) && !p.Truncated)
                     .DistinctBy(p => p.Id, StringComparer.OrdinalIgnoreCase))
        {
            var offer = new UpdateOffer("wg:" + p.Id, "winget", "game", p.Name.TrimEnd('…'), "Microsoft", "Runtime",
                p.Version, null, p.Available, null, 0, null, 1, RuntimeNote(p.Id));
            list.Add(new Plan(offer, "winget", p.Id, new()));
        }

        // The DirectX 9 runtime isn't part of Windows 10/11 but many older games need it.
        if (!File.Exists(Path.Combine(Environment.SystemDirectory, "d3dx9_43.dll")))
        {
            var offer = new UpdateOffer("wgi:Microsoft.DirectX", "winget", "game", "DirectX End-User Runtime", "Microsoft", "Runtime",
                null, null, "June 2010", new DateTime(2010, 6, 7), 0, "about 100 MB", 1,
                "Missing. Older games (DirectX 9–11) need these files and may not start without them.");
            list.Add(new Plan(offer, "winget", "Microsoft.DirectX", new(), WingetInstall: true));
        }
        return list;
    }

    static string RuntimeNote(string id) =>
        id.StartsWith("Microsoft.VCRedist.", StringComparison.OrdinalIgnoreCase) ? "Visual C++ runtime that games and apps are built on." :
        id.StartsWith("Nvidia.PhysX", StringComparison.OrdinalIgnoreCase) ? "Physics engine used by some games." :
        id.StartsWith("Microsoft.DotNet", StringComparison.OrdinalIgnoreCase) ? ".NET runtime used by many apps and launchers." :
        id.StartsWith("Microsoft.XNARedist", StringComparison.OrdinalIgnoreCase) ? "Needed by older XNA games." : "";

    /// <summary>
    /// When several sources offer a driver for the same device, keep only the newest. On a tie, prefer Windows Update,
    /// then the catalog (both are Microsoft-signed packages), then the maker's own installer.
    /// </summary>
    static List<Plan> Merge(List<Plan> all)
    {
        var result = new List<Plan>();
        var byDevice = new Dictionary<string, Plan>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in all)
        {
            if (p.Devices.Count != 1 || p.Offer.Group == "game") { result.Add(p); continue; }
            string dev = p.Devices[0].InstanceId;
            if (!byDevice.TryGetValue(dev, out var existing)) { byDevice[dev] = p; continue; }
            byDevice[dev] = Better(existing, p);
        }
        result.AddRange(byDevice.Values);
        // A multi-device catalog package whose devices all got a better single offer elsewhere adds nothing.
        return result.Where(p => !(p.Devices.Count > 1 && p.Devices.All(d => byDevice.TryGetValue(d.InstanceId, out var b) && b != p && Score(b).CompareTo(Score(p)) >= 0)))
            .ToList();
    }

    static Plan Better(Plan a, Plan b)
    {
        var sa = Score(a);
        var sb = Score(b);
        int cmp = sa.CompareTo(sb);
        if (cmp != 0) return cmp > 0 ? a : b;
        return Preference(a.Source) <= Preference(b.Source) ? a : b;
    }

    static int Preference(string source) => source switch { "wu" => 0, "catalog" => 1, _ => 2 };

    /// <summary>Comparable newness: NVIDIA's own numbering for GeForce cards, otherwise date then version.</summary>
    static (long, Version) Score(Plan p)
    {
        if (p.Devices.Count == 1 && NvidiaDrivers.IsNvidiaGpu(p.Devices[0]))
        {
            int? nv = p.Source == "nvidia" ? NvidiaDrivers.ParseNvidiaVersion(p.Offer.NewVersion) : NvidiaDrivers.ToNvidiaNumber(p.Offer.NewVersion);
            return (nv ?? 0, new Version());
        }
        // AMD's "26.10.2" can't be compared with Windows' "32.0.21xxx" numbering: the newer release date wins.
        if (p.Source == "amd") return (p.Offer.NewDate?.Ticks ?? 0, new Version(999, 0));
        long date = p.Offer.NewDate?.Ticks ?? 0;
        return (date, Version.TryParse(p.Offer.NewVersion, out var v) ? v : new Version());
    }

    // ---- install ----

    public static async Task<InstallSummary> InstallAsync(IReadOnlyCollection<string> keys, AppSettings settings,
        Action<string, int, int, string, int> progress, CancellationToken ct = default)
    {
        List<Plan> chosen;
        lock (Gate) chosen = keys.Select(k => plans.GetValueOrDefault(k)).Where(p => p is not null).Select(p => p!).ToList();
        if (chosen.Count == 0) throw new InvalidOperationException("Those updates are no longer listed. Check for updates again.");

        // Enforced here as well as in the dashboard: without Advanced options, never touch boot-critical
        // devices, firmware or unplugged devices, and never install when a safety check fails.
        bool advanced = settings.AdvancedDrivers;
        if (!advanced && chosen.Any(p => p.Offer.Group == "unplugged" || DriverGuard.IsCritical(p.Offer.DeviceClass)))
            throw new InvalidOperationException("Some of these updates need Advanced driver options, which are off. Nothing was installed.");
        bool driverWork = chosen.Any(p => p.Offer.Group != "game");
        if (driverWork)
        {
            var pre = DriverGuard.Check(settings, advanced);
            if (pre.Blockers.Count > 0) throw new InvalidOperationException(string.Join(" ", pre.Blockers) + " Nothing was installed.");
        }

        // Graphics drivers last: the screen blanks while they install. Runtimes after device drivers.
        chosen = chosen.OrderBy(p => p.Offer.Group == "game" ? 2 : p.Offer.DeviceClass.Equals("Display", StringComparison.OrdinalIgnoreCase) ? 1 : 0).ToList();
        int total = chosen.Count;
        string restoreMessage = "";
        string? backupFolder = null;
        if (driverWork)
        {
            progress("Creating a restore point", 0, total, "", -1);
            var rp = await Task.Run(() => DriverGuard.CreateFreshRestorePoint("SystemForge driver update"), ct);
            restoreMessage = rp.Message;
            if (!rp.Created && !advanced)
            {
                // No way back means no driver changes. The dashboard offers to turn System Protection on.
                return new InstallSummary(new(), false,
                    "Nothing was installed, because Windows couldn't make a restore point. System Protection is probably off for your Windows drive. Turn it on and try again.",
                    null) { NeedsSystemProtection = true };
            }

            progress("Backing up the drivers being replaced", 0, total, "", -1);
            try
            {
                var infs = chosen.SelectMany(p => p.Devices).Select(d => d.InfName).Where(n => n.Length > 0);
                backupFolder = (await Task.Run(() => DriverSafety.BackupInfs(infs, "Before driver update"), ct))?.Folder;
            }
            catch { /* best effort; the restore point still exists */ }
        }

        var items = new List<InstallItemResult>();
        bool reboot = false;

        // Windows Update items go through Windows Update's own installer in one session.
        var wuPlans = chosen.Where(p => p.Source == "wu").ToList();
        int index = 0;
        if (wuPlans.Count > 0)
        {
            int start = index;
            try
            {
                var (wuItems, wuReboot) = await Task.Run(() => WindowsUpdateService.Install(wuPlans.Select(p => p.Payload).ToList(),
                    (i, n, title, phase) => progress(phase, start + i, total, title, -1)), ct);
                items.AddRange(wuItems);
                reboot |= wuReboot;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex)
            {
                items.AddRange(wuPlans.Select(p => new InstallItemResult(p.Offer.Key, p.Offer.Name, false, $"Windows Update didn't answer: {ex.Message}")));
            }
            index += wuPlans.Count;
        }

        foreach (var p in chosen.Where(p => p.Source != "wu"))
        {
            index++;
            int i = index;
            string title = p.Offer.Name;
            void Report(string phase, int pct) => progress(phase, i, total, title, pct);
            (bool ok, string message, bool rb) r;
            try
            {
                r = p.Source switch
                {
                    "catalog" => await DriverCatalog.InstallAsync(p.Payload, Report, ct),
                    "nvidia" => await NvidiaDrivers.InstallAsync(p.Payload, p.Offer.NewVersion, p.Devices[0].InstanceId, Report, ct),
                    "amd" => await AmdDrivers.InstallAsync(p.Payload, p.Offer.NewVersion, Report, ct),
                    "amdchip" => await AmdDrivers.InstallChipsetAsync(p.Payload.Split('|')[0], p.Offer.NewVersion, p.Payload.Split('|')[1], Report, ct),
                    "intel" => await IntelDrivers.InstallAsync(p.Payload, p.Offer.NewVersion, p.Devices[0].InstanceId, Report, ct),
                    "oem" => (false, "BIOS updates are only reported; use the maker's download.", false),
                    "oemdrv" => await OemDrivers.InstallAsync(System.Text.Json.JsonSerializer.Deserialize<OemDriver>(p.Payload)!, p.Devices.Select(d => d.InstanceId).ToList(), Report, ct),
                    "winget" => await Winget.InstallAsync(p.Payload, p.WingetInstall, Report, ct),
                    _ => (false, "Unknown source.", false),
                };
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch (Exception ex) { r = (false, ex.Message, false); }
            items.Add(new InstallItemResult(p.Offer.Key, title, r.ok, r.message));
            reboot |= r.rb;
        }

        lock (Gate) foreach (var p in chosen) plans.Remove(p.Offer.Key);
        if (reboot && driverWork) DriverGuard.NoteRestartNeeded(settings);
        return new InstallSummary(items, reboot, restoreMessage, backupFolder);
    }

    // ---- helpers ----

    static string FirstNonEmpty(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? "";

    static string? VersionInTitle(string title)
    {
        var m = TitleVersionRx().Match(title);
        return m.Success ? m.Groups[1].Value : null;
    }

    [GeneratedRegex(@"(\d+\.\d+\.\d+(?:\.\d+)?)\)?\s*$")]
    private static partial Regex TitleVersionRx();
}
