using System.Drawing.Drawing2D;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace SystemForge;

public sealed class MainForm : Form
{
    public static readonly int WM_SHOWME = Native.RegisterWindowMessage("SystemForge_ShowMe");
    public const string HotkeyLabel = "Ctrl + Alt + O";
    const int HotkeyId = 0x5346;

    public static readonly Color Steel = Color.FromArgb(0x15, 0x1C, 0x28);
    public static readonly Color Fog = Color.FromArgb(0xDD, 0xE4, 0xEE);
    public static readonly Color Brass = Color.FromArgb(0xE0, 0xA9, 0x43);

    public AppSettings Settings { get; } = AppSettings.Load();

    readonly WebView2 web = new() { Dock = DockStyle.Fill, DefaultBackgroundColor = Steel };
    readonly NotifyIcon tray;
    readonly Bridge bridge;
    OverlayForm? overlay;
    bool startHidden;
    bool exiting;
    bool trayTipShown;

    // Program tracking: notices new installs right away and checks for updates once a day.
    InstallWatcher? watcher;
    HashSet<string> knownPrograms = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> notifiedUpdates = new(StringComparer.OrdinalIgnoreCase);
    readonly System.Windows.Forms.Timer appCheckTimer = new() { Interval = 60 * 60 * 1000 };
    string? balloonPage;

    // Game Mode: looks at the app in front every few seconds.
    readonly System.Windows.Forms.Timer gameTimer = new() { Interval = 3000 };
    volatile bool gamePolling;
    ToolStripMenuItem? gameMenuItem;

    public MainForm(bool startHidden)
    {
        this.startHidden = startHidden;
        Text = $"SystemForge {Updater.CurrentVersion}";
        BackColor = Steel;
        MinimumSize = new Size(1040, 680);
        Size = new Size(1280, 820);
        StartPosition = FormStartPosition.CenterScreen;
        Icon = BuildAppIcon(32);
        if (startHidden) Opacity = 0;

        Controls.Add(web);
        bridge = new Bridge(this);

        tray = new NotifyIcon
        {
            Icon = BuildAppIcon(16),
            Text = $"SystemForge {Updater.CurrentVersion}",
            Visible = true,
            ContextMenuStrip = BuildTrayMenu(),
        };
        tray.DoubleClick += (_, _) => ShowFromTray();
        tray.BalloonTipClicked += (_, _) =>
        {
            ShowFromTray();
            if (balloonPage is not null) bridge.Emit("nav", new { page = balloonPage });
        };
    }

    // ---- lifecycle ----

    protected override async void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        Native.SetDwmInt(Handle, Native.DWMWA_USE_IMMERSIVE_DARK_MODE, 1);
        Native.SetDwmInt(Handle, Native.DWMWA_CAPTION_COLOR, Native.ColorRef(Steel));
        Native.SetDwmInt(Handle, Native.DWMWA_TEXT_COLOR, Native.ColorRef(Fog));

        if (!Native.RegisterHotKey(Handle, HotkeyId, Native.MOD_CONTROL | Native.MOD_ALT | Native.MOD_NOREPEAT, (uint)Keys.O))
            tray.ShowBalloonTip(4000, "SystemForge", $"{HotkeyLabel} is already used by another app, so the overlay hotkey is off. Use the tray icon instead.", ToolTipIcon.Warning);

        NativeConfirm.Owner = this;
        StartGameMode();
        _ = Task.Run(RepairAutoStart);
        await InitWebViewAsync();
        StartProgramTracking();
        ShowWelcomeIfNew();
        _ = Task.Run(() => Sensors.Read(Settings.TempUnit)); // warm up the sensors so the first reading is quick
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        if (startHidden)
        {
            startHidden = false;
            Hide();
            Opacity = 1;
        }
    }

    async Task InitWebViewAsync()
    {
        try
        {
            var dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SystemForge", "WebView2");
            var env = await CoreWebView2Environment.CreateAsync(null, dataDir);
            await web.EnsureCoreWebView2Async(env);

            var core = web.CoreWebView2;
            core.Settings.AreDefaultContextMenusEnabled = false;
            core.Settings.IsStatusBarEnabled = false;
            core.Settings.IsZoomControlEnabled = false;
#if !DEBUG
            core.Settings.AreDevToolsEnabled = false;
            core.Settings.AreBrowserAcceleratorKeysEnabled = false;
#endif
            core.SetVirtualHostNameToFolderMapping("app.systemforge",
                Path.Combine(AppContext.BaseDirectory, "wwwroot"), CoreWebView2HostResourceAccessKind.Deny);
            core.WebMessageReceived += async (_, args) =>
            {
                // The bridge runs as admin: only accept commands from our own bundled page.
                if (!args.Source.StartsWith("https://app.systemforge/", StringComparison.OrdinalIgnoreCase)) return;
                await bridge.HandleAsync(args.WebMessageAsJson);
            };
            core.NewWindowRequested += (_, args) => args.Handled = true;

            // The dashboard files ship next to the exe, but WebView2 keeps an HTTP cache in AppData that outlives
            // updates, so a new SystemForge could show the previous version's page. Drop that cache on every start
            // (it only ever holds our own small local files) and tag the URL with the version as a second guard.
            try { await core.Profile.ClearBrowsingDataAsync(CoreWebView2BrowsingDataKinds.DiskCache | CoreWebView2BrowsingDataKinds.CacheStorage); }
            catch { /* older runtime: the versioned URL below still forces a fresh page */ }
            string version = typeof(MainForm).Assembly.GetName().Version?.ToString(3) ?? "0";
            core.Navigate($"https://app.systemforge/index.html?v={version}");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this,
                "SystemForge needs the Microsoft Edge WebView2 Runtime to show its dashboard.\n\n" +
                "Install it from microsoft.com/edge/webview2, then open SystemForge again.\n\n" + ex.Message,
                "SystemForge", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    public void PostToWeb(string json)
    {
        try
        {
            if (!web.IsDisposed && web.CoreWebView2 is not null) web.CoreWebView2.PostWebMessageAsJson(json);
        }
        catch { /* browser process gone or window closing; a throw here would hit the UI thread unhandled */ }
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == Native.WM_HOTKEY && m.WParam.ToInt32() == HotkeyId)
        {
            ToggleOverlay();
            return;
        }
        if (m.Msg == WM_SHOWME && WM_SHOWME != 0)
        {
            ShowFromTray();
            return;
        }
        base.WndProc(ref m);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (!exiting && Settings.MinimizeToTray && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            if (!trayTipShown)
            {
                trayTipShown = true;
                tray.ShowBalloonTip(3000, "SystemForge is still running",
                    $"The overlay ({HotkeyLabel}) keeps working. Right-click the tray icon to quit.", ToolTipIcon.Info);
            }
            return;
        }

        Native.UnregisterHotKey(Handle, HotkeyId);
        gameTimer.Dispose();
        if (GameMode.Active) GameMode.Set(false); // put the power plan and priorities back before quitting
        Sensors.Shutdown();
        appCheckTimer.Dispose();
        watcher?.Dispose();
        Settings.Save();
        tray.Visible = false;
        tray.Dispose();
        overlay?.Dispose();
        base.OnFormClosing(e);
    }

    // ---- program tracking ----

    void StartProgramTracking()
    {
        Task.Run(() =>
        {
            knownPrograms = AppUpdates.InstalledNames();
            watcher = new InstallWatcher();
            watcher.Changed += () => _ = OnProgramsChangedAsync();
        });
        appCheckTimer.Tick += (_, _) => _ = DailyCheckAsync();
        appCheckTimer.Start();
        // First check a couple of minutes after start, so sign-in isn't slowed down.
        _ = Task.Delay(TimeSpan.FromMinutes(2)).ContinueWith(_ => DailyCheckAsync());
    }

    async Task DailyCheckAsync()
    {
        if (!Settings.AppUpdateChecks || GameMode.Active) return; // runs again within the hour after the game
        _ = CheckSelfUpdateAsync();
        if (Settings.LastAppCheckUtc is DateTime last && DateTime.UtcNow - last < TimeSpan.FromHours(23)) return;
        await CheckAppsAndNotifyAsync(new List<string>());
    }

    async Task OnProgramsChangedAsync()
    {
        var now = AppUpdates.InstalledNames();
        var added = now.Except(knownPrograms, StringComparer.OrdinalIgnoreCase).ToList();
        knownPrograms = now;
        if (!Settings.AppUpdateChecks) return;
        await CheckAppsAndNotifyAsync(added);
    }

    async Task CheckAppsAndNotifyAsync(List<string> added)
    {
        AppCheck result;
        try { result = await AppUpdates.CheckAsync(Settings); }
        catch { return; /* winget missing or offline: try again next time */ }
        bridge.Emit("apps.updated", result);
        if (GameMode.Active) return; // no pop-ups over a game; they show after the next check

        var fresh = result.Updates.Where(u => !u.Ignored && !u.Skipped && notifiedUpdates.Add($"{u.Id}@{u.Available}")).ToList();
        string? title = null, body = null;

        if (added.Count > 0)
        {
            string name = added[0];
            var match = result.Programs.FirstOrDefault(p => p.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                        ?? result.Programs.FirstOrDefault(p => name.StartsWith(p.Name, StringComparison.OrdinalIgnoreCase) || p.Name.StartsWith(name, StringComparison.OrdinalIgnoreCase));
            bool tracked = match is not null && match.Source.Length > 0;
            title = tracked ? $"Now tracking {name}" : $"{name} was installed";
            body = !tracked ? "It isn't in winget's catalog, so SystemForge can't update it. It may update itself."
                 : match!.HasUpdate ? "There's already a newer version. Open SystemForge to update it."
                 : "SystemForge will tell you when an update comes out.";
            if (added.Count > 1) body += $" ({added.Count - 1} more new program{(added.Count > 2 ? "s" : "")} found.)";
        }
        else if (fresh.Count > 0)
        {
            title = fresh.Count == 1 ? $"Update for {fresh[0].Name}" : $"{fresh.Count} app updates available";
            body = fresh.Count == 1 ? $"{fresh[0].Version} → {fresh[0].Available}. Click to update."
                 : string.Join(", ", fresh.Take(3).Select(u => u.Name)) + (fresh.Count > 3 ? " and more." : ".");
        }

        if (title is null) return;
        try
        {
            BeginInvoke(() =>
            {
                balloonPage = "apps";
                tray.ShowBalloonTip(6000, title, body ?? "", ToolTipIcon.Info);
            });
        }
        catch { /* closing */ }
    }

    string? notifiedSelfUpdate;

    async Task CheckSelfUpdateAsync()
    {
        try
        {
            var r = await Updater.CheckAsync();
            if (r.Update is null || notifiedSelfUpdate == r.Update.Version) return;
            notifiedSelfUpdate = r.Update.Version;
            bridge.Emit("app.update", r);
            BeginInvoke(() =>
            {
                balloonPage = "settings";
                tray.ShowBalloonTip(6000, $"SystemForge {r.Update.Version} is available", "Click to install it from Settings.", ToolTipIcon.Info);
            });
        }
        catch { /* offline or no release yet */ }
    }

    /// <summary>First run after an install or an update: a short "installed / updated to x.y.z" screen.</summary>
    void ShowWelcomeIfNew()
    {
        string version = Updater.CurrentVersion;
        if (Settings.LastRunVersion == version) return;
        bool first = Settings.LastRunVersion is null;
        Settings.LastRunVersion = version;
        Settings.Save();
        // Only for the installed copy (the installer writes this key); a loose build just runs.
        bool installed = false;
        try { using var k = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\SystemForge"); installed = k?.GetValue("installed") is not null; } catch { }
        if (!installed) return;

        if (!Visible) { Show(); Opacity = 1; }
        using var dlg = new WelcomeDialog(version, first, File.Exists(WelcomeDialog.DesktopShortcutPath()), Settings.StartWithWindows);
        dlg.ShowDialog(this);
        if (!first) return;
        if (dlg.DesktopShortcut) WelcomeDialog.CreateDesktopShortcut();
        if (dlg.StartWithWindows != Settings.StartWithWindows)
        {
            try
            {
                AutoStart.Set(dlg.StartWithWindows);
                Settings.StartWithWindows = AutoStart.IsEnabled();
                Settings.AutoStartPath = Settings.StartWithWindows ? Environment.ProcessPath : null;
                Settings.Save();
                bridge.Emit("settings.changed", Settings);
            }
            catch { }
        }
        Activate();
    }

    // ---- Game Mode ----

    void StartGameMode()
    {
        GameMode.Init(Settings);
        GameMode.Changed += () =>
        {
            try
            {
                BeginInvoke(() =>
                {
                    if (gameMenuItem is not null) gameMenuItem.Checked = GameMode.Active;
                    overlay?.Invalidate();
                    bridge.Emit("gamemode.changed", GameMode.Status());
                });
            }
            catch { /* closing */ }
        };
        gameTimer.Tick += (_, _) =>
        {
            if (gamePolling) return;
            gamePolling = true;
            Task.Run(() =>
            {
                try { GameMode.Poll(); }
                catch { }
                finally { gamePolling = false; }
            });
        };
        gameTimer.Start();
    }

    // ---- overlay and tray ----

    public void ToggleOverlay(bool? show = null)
    {
        if (!Settings.OverlayEnabled && show != false) return;
        if (overlay is null || overlay.IsDisposed) overlay = new OverlayForm(this);
        bool want = show ?? !overlay.Visible;
        if (want) overlay.ShowOverlay();
        else overlay.Hide();
    }

    public void RefreshOverlay()
    {
        overlay?.ApplyOpacity();
        overlay?.Invalidate();
    }

    /// <summary>Opens the dashboard on a page, e.g. from the overlay's "Get CPU temp" link.</summary>
    public void ShowPage(string page)
    {
        ShowFromTray();
        bridge.Emit("nav", new { page });
    }

    void ShowFromTray()
    {
        if (!Visible) Show();
        if (WindowState == FormWindowState.Minimized) WindowState = FormWindowState.Normal;
        Activate();
    }

    void ExitApp()
    {
        exiting = true;
        Close();
    }

    /// <summary>Quits so an installer can replace the files; "Start with Windows" relaunches it after sign-in.</summary>
    public void QuitForUpdate() => ExitApp();

    /// <summary>
    /// The startup task stores the exe's full path. After an install to a new folder (the installer, or a move),
    /// re-register it so "Start with Windows" doesn't point at the old copy.
    /// </summary>
    void RepairAutoStart()
    {
        try
        {
            if (!Settings.StartWithWindows || !AutoStart.IsEnabled()) return;
            if (string.Equals(Settings.AutoStartPath, Environment.ProcessPath, StringComparison.OrdinalIgnoreCase)) return;
            AutoStart.Set(true);
            Settings.AutoStartPath = Environment.ProcessPath;
            Settings.Save();
        }
        catch { /* best effort */ }
    }

    ContextMenuStrip BuildTrayMenu()
    {
        var menu = new ContextMenuStrip();
        menu.Items.Add("Open SystemForge", null, (_, _) => ShowFromTray());
        menu.Items.Add($"Show or hide overlay   {HotkeyLabel}", null, (_, _) => ToggleOverlay());
        menu.Items.Add("Free up memory", null, async (_, _) =>
        {
            var r = await Task.Run(() => MemoryOptimizer.Optimize(GameMode.GamePid));
            tray.ShowBalloonTip(2500, r.Note ?? "Memory freed",
                $"{(r.Note is null ? $"{r.FreedMb:N0} MB freed. " : "")}{r.AvailableMb / 1024:0.0} GB now available.", ToolTipIcon.None);
        });
        gameMenuItem = new ToolStripMenuItem("Game Mode") { CheckOnClick = false };
        gameMenuItem.Click += (_, _) => Task.Run(() => GameMode.Set(!GameMode.Active));
        menu.Items.Add(gameMenuItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Quit SystemForge", null, (_, _) => ExitApp());
        return menu;
    }

    /// <summary>Draws the app mark (a gauge dial) so no .ico file is needed.</summary>
    public static Icon BuildAppIcon(int size)
    {
        using var bmp = new Bitmap(size, size);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float s = size;
            using (var bg = new SolidBrush(Color.FromArgb(0x25, 0x2F, 0x40)))
                g.FillEllipse(bg, 0, 0, s - 1, s - 1);
            using var pen = new Pen(Brass, Math.Max(1.5f, s / 10f)) { StartCap = LineCap.Round, EndCap = LineCap.Round };
            float inset = s * 0.2f;
            var arc = new RectangleF(inset, inset, s - 2 * inset, s - 2 * inset);
            g.DrawArc(pen, arc, 150, 240);
            float cx = s / 2, cy = s / 2, r = arc.Width / 2 * 0.8f;
            double angle = -40 * Math.PI / 180; // needle pointing up-right
            g.DrawLine(pen, cx, cy, cx + (float)(r * Math.Cos(angle)), cy + (float)(r * Math.Sin(angle)));
        }
        return Icon.FromHandle(bmp.GetHicon());
    }
}
