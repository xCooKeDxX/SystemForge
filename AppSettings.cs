using System.Text.Json;

namespace SystemForge;

public sealed class AppSettings
{
    public bool OverlayEnabled { get; set; } = true;
    public bool MinimizeToTray { get; set; } = true;
    public bool StartWithWindows { get; set; }
    /// <summary>Exe path the startup task was registered with, so a moved or reinstalled copy can fix it.</summary>
    public string? AutoStartPath { get; set; }

    /// <summary>Overlay position relative to the top-left of the monitor it's on. -1 = default corner.</summary>
    public int OverlayOffsetX { get; set; } = -1;
    public int OverlayOffsetY { get; set; } = -1;

    /// <summary>Overlay shrunk to its mini gauges.</summary>
    public bool OverlayCollapsed { get; set; }

    /// <summary>Overlay gauges show temperatures instead of usage (click the gauges to switch).</summary>
    public bool OverlayTemps { get; set; }

    /// <summary>How solid the overlay is, 40–100 percent.</summary>
    public int OverlayOpacity { get; set; } = 96;

    /// <summary>Check installed programs for updates once a day and notify from the tray.</summary>
    public bool AppUpdateChecks { get; set; } = true;

    /// <summary>winget ids the user never wants offered.</summary>
    public List<string> IgnoredApps { get; set; } = new();

    /// <summary>winget id → the one version the user chose to skip (offered again once a newer one exists).</summary>
    public Dictionary<string, string> SkippedVersions { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    public DateTime? LastAppCheckUtc { get; set; }

    /// <summary>Shows drivers for boot-critical devices, firmware and unplugged devices, and turns safety blocks into warnings.</summary>
    public bool AdvancedDrivers { get; set; }

    /// <summary>Security findings the user vouched for ("Trust it"), e.g. "path:C:\Tools\thing.exe".</summary>
    public List<string> SecurityTrusted { get; set; } = new();

    /// <summary>"C" or "F" for every temperature SystemForge shows.</summary>
    public string TempUnit { get; set; } = System.Globalization.RegionInfo.CurrentRegion.IsMetric ? "C" : "F";

    // Game Mode
    public bool GameModeAuto { get; set; } = true;
    public bool GameModePower { get; set; } = true;
    public bool GameModePriority { get; set; } = true;
    public bool GameModeMemory { get; set; } = true;
    /// <summary>Programs always treated as games, and ones never treated as games (full exe paths).</summary>
    public List<string> GameModeGames { get; set; } = new();
    public List<string> GameModeIgnored { get; set; } = new();
    /// <summary>What Game Mode changed and must put back; only set while it's on.</summary>
    public GameModeRestore? GameModeRestore { get; set; }

    /// <summary>When a driver install last said a restart is needed (cleared once the PC has restarted).</summary>
    public DateTime? DriverRestartNeededUtc { get; set; }

    public static string DataDir =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SystemForge");

    static string FilePath => Path.Combine(DataDir, "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
                return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
        }
        catch { /* corrupt settings: fall back to defaults */ }
        return new AppSettings();
    }

    static readonly JsonSerializerOptions SaveOptions = new() { WriteIndented = true };
    static readonly object saveGate = new();

    /// <summary>Saved from the UI thread and from Game Mode's worker, so writes go one at a time.</summary>
    public void Save()
    {
        lock (saveGate)
        {
            try
            {
                Directory.CreateDirectory(DataDir);
                string tmp = FilePath + ".tmp";
                File.WriteAllText(tmp, JsonSerializer.Serialize(this, SaveOptions));
                File.Move(tmp, FilePath, overwrite: true);
            }
            catch { /* settings are best-effort */ }
        }
    }
}
