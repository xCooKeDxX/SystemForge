using System.Diagnostics;
using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace SystemForge;

/// <summary>
/// Small always-on-top panel that floats over any app (games in borderless/windowed mode included).
/// It never takes focus, so pressing the hotkey mid-game won't pull you out of it.
/// Two sizes: the full panel, and a collapsed strip of three mini gauges (CPU, GPU, memory).
/// </summary>
internal sealed class OverlayForm : Form
{
    const int Rows = 6;

    // Same palette as the dashboard (wwwroot/styles.css).
    static readonly Color Panel = Color.FromArgb(0x10, 0x15, 0x1E);
    static readonly Color PanelHi = Color.FromArgb(0x15, 0x1C, 0x27);
    static readonly Color Raised = Color.FromArgb(0x1B, 0x24, 0x31);
    static readonly Color Line = Color.FromArgb(0x26, 0x30, 0x3E);
    static readonly Color LineHi = Color.FromArgb(0x34, 0x40, 0x52);
    static readonly Color TextC = Color.FromArgb(0xE8, 0xED, 0xF5);
    static readonly Color Muted = Color.FromArgb(0x8B, 0x97, 0xA8);
    static readonly Color Dim = Color.FromArgb(0x5B, 0x66, 0x78);
    static readonly Color Accent = Color.FromArgb(0x38, 0xC8, 0xFF);
    static readonly Color Accent2 = Color.FromArgb(0x7C, 0x6C, 0xFF);
    static readonly Color Ink = Color.FromArgb(0x05, 0x10, 0x1A);
    static readonly Color Warn = Color.FromArgb(0xFF, 0xB5, 0x47);
    static readonly Color Bad = Color.FromArgb(0xFF, 0x5D, 0x6C);
    static readonly Color CpuC = Color.FromArgb(0x38, 0xC8, 0xFF);
    static readonly Color GpuC = Color.FromArgb(0xA7, 0x8B, 0xFA);
    static readonly Color RamC = Color.FromArgb(0x34, 0xE0, 0xA1);
    static readonly Color DiskC = Color.FromArgb(0x6E, 0xA8, 0xFE);

    /// <summary>
    /// Screenshot tools draw their own topmost capture layer. While one of these is in front we stop
    /// re-asserting "topmost", so the overlay stays under the snipping UI and can be captured normally.
    /// </summary>
    static readonly HashSet<string> CaptureTools = new(StringComparer.OrdinalIgnoreCase)
    {
        "SnippingTool", "ScreenClippingHost", "ScreenSketch", "ShareX", "Greenshot", "Lightshot", "Flameshot",
        "PicPick", "Snagit32", "SnagitCapture", "SnagitEditor", "Gyazo", "GyazoReplay", "CleanShot", "Monosnap",
    };

    readonly MainForm owner;
    readonly CpuSampler cpu = new();
    readonly GpuSampler gpu = new();
    readonly ProcessSampler apps = new();
    readonly System.Windows.Forms.Timer timer = new() { Interval = 1500 };
    readonly List<(Rectangle rect, string key, Action action)> hits = new();

    double cpuPct, gpuPct, ramPct, ramUsedGb, ramTotalGb;
    double? cpuTemp, gpuTemp, driveTemp;
    bool cpuNeedsDriver;

    // A press on the collapsed gauges: a click switches usage/temperatures, a drag moves the overlay.
    bool pressPending;
    Point pressAt;
    List<AppProcessGroup> top = new();
    volatile bool refreshing;
    bool boosting;
    bool capturing;         // drawing into a bitmap for "copy as image": no hover states
    string? hover;
    string? armed;          // app waiting for a second click to confirm "End"
    DateTime armedUntil;
    string? flash;          // short result message shown on the button
    string? rocketBadge;    // the same result in a few characters, shown inside the collapsed rocket
    DateTime flashUntil;

    Font fTitle = null!, fLabel = null!, fValue = null!, fButton = null!, fSmall = null!, fRing = null!, fTiny = null!, fRingSmall = null!, fMicro = null!;

    bool Collapsed => owner.Settings.OverlayCollapsed;
    bool ShowTemps => owner.Settings.OverlayTemps;

    public OverlayForm(MainForm owner)
    {
        this.owner = owner;
        FormBorderStyle = FormBorderStyle.None;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        TopMost = true;
        StartPosition = FormStartPosition.Manual;
        BackColor = Panel;
        DoubleBuffered = true;
        ApplyOpacity();
        Text = "SystemForge overlay";
        BuildFonts();
        ClientSize = ComputeSize();
        timer.Tick += (_, _) => RefreshData();
    }

    protected override bool ShowWithoutActivation => true;

    protected override CreateParams CreateParams
    {
        get
        {
            var cp = base.CreateParams;
            cp.ExStyle |= Native.WS_EX_TOOLWINDOW | Native.WS_EX_NOACTIVATE | Native.WS_EX_TOPMOST;
            return cp;
        }
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Native.SetDwmInt(Handle, Native.DWMWA_WINDOW_CORNER_PREFERENCE, 2); // rounded corners on Windows 11
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        BuildFonts();
        ClientSize = ComputeSize();
        Invalidate();
    }

    // ---- showing, hiding, position, size ----

    /// <summary>Shows the overlay on whichever monitor the mouse is on, at the spot you last dragged it to.</summary>
    public void ApplyOpacity() => Opacity = Math.Clamp(owner.Settings.OverlayOpacity, 40, 100) / 100.0;

    public void ShowOverlay()
    {
        ApplyOpacity();
        ClientSize = ComputeSize();
        var area = Screen.FromPoint(Cursor.Position).WorkingArea;
        int dx = owner.Settings.OverlayOffsetX, dy = owner.Settings.OverlayOffsetY;
        if (dx < 0 || dy < 0) { dx = area.Width - Width - S(24); dy = S(24); }
        Location = ClampTo(area, new Point(area.X + dx, area.Y + dy));

        if (!Visible) Show();
        Native.KeepTopmost(Handle);
        RefreshData();
        timer.Start();
    }

    protected override void OnVisibleChanged(EventArgs e)
    {
        base.OnVisibleChanged(e);
        if (!Visible)
        {
            timer.Stop();
            armed = null;
        }
    }

    void SetCollapsed(bool collapsed)
    {
        if (Collapsed == collapsed) return;
        // Keep the corner nearest the screen edge in place, so a panel docked top-right stays top-right.
        var area = Screen.FromControl(this).WorkingArea;
        bool anchorRight = Left + Width / 2 > area.X + area.Width / 2;
        int right = Right;

        owner.Settings.OverlayCollapsed = collapsed;
        hover = null;
        ClientSize = ComputeSize();
        var spot = new Point(anchorRight ? right - Width : Left, Top);
        Location = ClampTo(area, spot);
        SaveOffset();
        Invalidate();
    }

    Point ClampTo(Rectangle area, Point p) => new(
        Math.Clamp(p.X, area.X, Math.Max(area.X, area.Right - Width)),
        Math.Clamp(p.Y, area.Y, Math.Max(area.Y, area.Bottom - Height)));

    void SaveOffset()
    {
        var area = Screen.FromControl(this).WorkingArea;
        owner.Settings.OverlayOffsetX = Math.Max(0, Left - area.X);
        owner.Settings.OverlayOffsetY = Math.Max(0, Top - area.Y);
        owner.Settings.Save();
    }

    // ---- data ----

    void RefreshData()
    {
        if (refreshing) return;
        refreshing = true;
        bool wantApps = !Collapsed;
        Task.Run(() =>
        {
            double c = cpu.Sample();
            double g = gpu.Sample();
            var mem = Native.GetMemory();
            var list = wantApps ? apps.TopApps(Rows) : null;
            bool captureToolInFront = IsCaptureToolInFront();
            SensorReport? temps = null;
            try { temps = Sensors.Read(owner.Settings.TempUnit); } catch { }
            return (c, g, mem, list, captureToolInFront, temps);
        }).ContinueWith(t =>
        {
            refreshing = false;
            if (t.IsFaulted || IsDisposed || !IsHandleCreated) return;
            try
            {
                BeginInvoke(() =>
                {
                    var (c, g, mem, list, captureToolInFront, temps) = t.Result;
                    cpuPct = c;
                    gpuPct = g;
                    cpuTemp = temps?.CpuC;
                    gpuTemp = temps?.GpuC;
                    cpuNeedsDriver = temps?.CpuNeedsDriver ?? false;
                    var drives = temps?.Sensors.Where(x => x.Group == "Drives" && x.Kind == "temp").Select(x => x.Value).ToList();
                    driveTemp = drives is { Count: > 0 } ? drives.Max() : null;
                    ramTotalGb = mem.ullTotalPhys / 1073741824.0;
                    ramUsedGb = ramTotalGb - mem.ullAvailPhys / 1073741824.0;
                    ramPct = ramTotalGb > 0 ? 100 * ramUsedGb / ramTotalGb : 0;
                    if (list is not null) top = list;
                    // Stay above games that also want to be on top, but not above a screenshot tool's capture layer.
                    if (Visible && !captureToolInFront) Native.KeepTopmost(Handle);
                    Invalidate();
                });
            }
            catch { /* closing */ }
        });
    }

    static bool IsCaptureToolInFront()
    {
        int pid = Native.GetForegroundProcessId();
        if (pid <= 0) return false;
        try
        {
            using var p = Process.GetProcessById(pid);
            return CaptureTools.Contains(p.ProcessName);
        }
        catch { return false; }
    }

    void Boost()
    {
        if (boosting) return;
        boosting = true;
        Invalidate();
        Task.Run(() => MemoryOptimizer.Optimize(GameMode.GamePid)).ContinueWith(t =>
        {
            try
            {
                BeginInvoke(() =>
                {
                    boosting = false;
                    Flash(t.IsFaulted ? "Couldn't free memory" : t.Result.Note ?? $"Freed {FormatMb(t.Result.FreedMb)}");
                    rocketBadge = t.IsFaulted ? "!" : t.Result.Note is not null ? "✓" : ShortMb(t.Result.FreedMb);
                    RefreshData();
                });
            }
            catch { }
        });
    }

    void ToggleGameMode()
    {
        bool on = !GameMode.Active;
        Task.Run(() => GameMode.Set(on)).ContinueWith(t =>
        {
            try
            {
                BeginInvoke(() =>
                {
                    if (t.IsFaulted) Flash("Couldn't change Game Mode");
                    Invalidate();
                });
            }
            catch { }
        });
    }

    // ---- temperatures ----

    void SetShowTemps(bool on)
    {
        if (ShowTemps == on) return;
        owner.Settings.OverlayTemps = on;
        owner.Settings.Save();
        Invalidate();
    }

    /// <summary>Ring and bar fill for a temperature: 0–100 °C across the scale, whatever unit is shown.</summary>
    static double TempFill(double? c) => Math.Clamp(c ?? 0, 0, 100);

    /// <summary>Metric colour normally; amber then red when hot (drives run cooler, so their limits are lower).</summary>
    static Color TempLoadColor(double? c, Color metric, bool drive = false) =>
        c is not double t ? Dim : drive ? (t >= 70 ? Bad : t >= 60 ? Warn : metric) : (t >= 90 ? Bad : t >= 80 ? Warn : metric);

    /// <summary>"126°" for inside a ring; the unit is on the label.</summary>
    string TempShort(double? celsius) => celsius is not double c ? "–" : owner.Settings.TempUnit == "F" ? $"{c * 9 / 5 + 32:0}°" : $"{c:0}°";

    string Temp(double? celsius)
    {
        if (celsius is not double c) return "";
        return owner.Settings.TempUnit == "F" ? $"{c * 9 / 5 + 32:0}°F" : $"{c:0}°C";
    }

    /// <summary>Amber from 80 °C, red from 90 °C: where CPUs and GPUs start holding back their speed.</summary>
    static Color TempColor(double? celsius) => celsius >= 90 ? Bad : celsius >= 80 ? Warn : Muted;

    void EndApp(AppProcessGroup app)
    {
        if (armed != app.Name || DateTime.Now > armedUntil)
        {
            armed = app.Name;
            armedUntil = DateTime.Now.AddSeconds(3);
            Invalidate();
            return;
        }
        armed = null;
        Task.Run(() => ProcessManager.EndApp(app.Name)).ContinueWith(t =>
        {
            try
            {
                BeginInvoke(() =>
                {
                    Flash(t.IsFaulted ? $"Couldn't close {app.DisplayName}" : $"Closed {Shorten(app.DisplayName, 22)}");
                    RefreshData();
                });
            }
            catch { }
        });
    }

    /// <summary>
    /// Copies a picture of the overlay to the clipboard and saves it to Pictures\SystemForge,
    /// so it can be shared even when a game or capture tool won't include it in a screenshot.
    /// </summary>
    void CopyAsImage()
    {
        try
        {
            using var bmp = new Bitmap(ClientSize.Width, ClientSize.Height, PixelFormat.Format32bppArgb);
            capturing = true;
            try { DrawToBitmap(bmp, new Rectangle(Point.Empty, ClientSize)); }
            finally { capturing = false; }

            Clipboard.SetImage(bmp);
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "SystemForge");
            Directory.CreateDirectory(dir);
            var file = Path.Combine(dir, $"overlay-{DateTime.Now.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture)}.png");
            bmp.Save(file, ImageFormat.Png);
            Flash("Copied. Also saved to Pictures");
        }
        catch
        {
            Flash("Couldn't copy the image");
        }
    }

    void Flash(string message)
    {
        flash = message;
        flashUntil = DateTime.Now.AddSeconds(3);
        Invalidate();
    }

    // ---- sizing ----

    int S(int px) => (int)Math.Round(px * DeviceDpi / 96.0);

    Size ComputeSize() => Collapsed
        ? new Size(S(6) + 3 * S(50) + S(6) + 2 * S(30) + S(6) + S(6) + S(20) + S(6), S(56))
        : new Size(S(304), S(80) + 3 * S(44) + S(6) + S(36) + S(18) + S(22) + Rows * S(30) + S(36));

    void BuildFonts()
    {
        // Runs again on every DPI change; release the previous set (null on first call).
        Font?[] old = { fTitle, fLabel, fValue, fButton, fSmall, fRing, fTiny, fRingSmall, fMicro };
        fTitle = new Font("Bahnschrift", S(13), FontStyle.Regular, GraphicsUnit.Pixel);
        fLabel = new Font("Segoe UI", S(12), FontStyle.Regular, GraphicsUnit.Pixel);
        fValue = new Font("Bahnschrift", S(14), FontStyle.Regular, GraphicsUnit.Pixel);
        fButton = new Font("Bahnschrift", S(14), FontStyle.Bold, GraphicsUnit.Pixel);
        fSmall = new Font("Segoe UI", S(11), FontStyle.Regular, GraphicsUnit.Pixel);
        fRing = new Font("Bahnschrift", S(14), FontStyle.Bold, GraphicsUnit.Pixel);
        fTiny = new Font("Bahnschrift", S(10), FontStyle.Regular, GraphicsUnit.Pixel);
        fRingSmall = new Font("Bahnschrift", S(13), FontStyle.Bold, GraphicsUnit.Pixel);
        fMicro = new Font("Bahnschrift", S(9), FontStyle.Regular, GraphicsUnit.Pixel);
        foreach (var f in old) f?.Dispose();
    }

    // ---- painting ----

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.InterpolationMode = InterpolationMode.HighQualityBicubic;
        g.PixelOffsetMode = PixelOffsetMode.HighQuality;
        hits.Clear();

        int w = ClientSize.Width, h = ClientSize.Height;
        // Dark glass: a top-lit gradient, a cool glow bleeding in from the top-left, a hairline that catches
        // the light along the top edge, and a slightly brighter rim. Same language as the dashboard panels.
        using (var bg = new LinearGradientBrush(new Rectangle(0, 0, w, h), Color.FromArgb(0x16, 0x1D, 0x29), Color.FromArgb(0x0C, 0x10, 0x18), LinearGradientMode.Vertical))
            g.FillRectangle(bg, 0, 0, w, h);
        using (var glow = new GraphicsPath())
        {
            glow.AddEllipse(-w / 2, -h, w * 3 / 2, h * 3 / 2);
            using var pgb = new PathGradientBrush(glow) { CenterColor = Color.FromArgb(34, Accent), SurroundColors = new[] { Color.FromArgb(0, Accent) } };
            g.FillPath(pgb, glow);
        }
        using (var glow2 = new GraphicsPath())
        {
            glow2.AddEllipse(w / 2, h / 2, w, h);
            using var pgb = new PathGradientBrush(glow2) { CenterColor = Color.FromArgb(18, Accent2), SurroundColors = new[] { Color.FromArgb(0, Accent2) } };
            g.FillPath(pgb, glow2);
        }
        using (var top = new LinearGradientBrush(new Rectangle(0, 0, w, 2), Color.FromArgb(0, Color.White), Color.FromArgb(0, Color.White), LinearGradientMode.Horizontal))
        {
            var blend = new ColorBlend { Colors = new[] { Color.FromArgb(0, Color.White), Color.FromArgb(70, Color.White), Color.FromArgb(0, Color.White) }, Positions = new[] { 0f, 0.5f, 1f } };
            top.InterpolationColors = blend;
            g.FillRectangle(top, 1, 1, w - 2, 1);
        }
        using (var border = new Pen(Color.FromArgb(0x3A, 0x47, 0x5A))) g.DrawRectangle(border, 0, 0, w - 1, h - 1);

        if (Collapsed) PaintCollapsed(g, w, h);
        else PaintExpanded(g, w, h);
    }

    /// <summary>
    /// A slim strip: three ring gauges with their value and name inside, the rocket and Game Mode buttons,
    /// then expand and close. Click the rings to switch usage / temperatures; drag them to move the strip.
    /// </summary>
    void PaintCollapsed(Graphics g, int w, int h)
    {
        int pad = S(6), cellW = S(50), d = S(46);
        bool temps = ShowTemps;
        hits.Add((new Rectangle(pad, 0, 3 * cellW, h), "gauges", () => SetShowTemps(!ShowTemps)));

        for (int i = 0; i < 3; i++)
        {
            var ring = new Rectangle(pad + i * cellW + (cellW - d) / 2, (h - d) / 2, d, d);
            string label, value;
            double fill;
            Color color;
            bool missing = false;
            if (temps)
            {
                double? t = i switch { 0 => cpuTemp, 1 => gpuTemp, _ => driveTemp };
                label = i switch { 0 => "CPU", 1 => "GPU", _ => "DRIVE" };
                value = TempShort(t);
                fill = TempFill(t);
                color = TempLoadColor(t, i switch { 0 => CpuC, 1 => GpuC, _ => DiskC }, drive: i == 2);
                missing = t is null;
            }
            else
            {
                double pct = i switch { 0 => cpuPct, 1 => gpuPct, _ => ramPct };
                label = i switch { 0 => "CPU", 1 => "GPU", _ => "RAM" };
                value = $"{pct:0}";
                fill = pct;
                color = LoadColor(pct, i switch { 0 => CpuC, 1 => GpuC, _ => RamC });
            }
            DrawRing(g, ring, fill, color, S(4));
            // Value dead centre of the ring (the open gap at the bottom holds the name).
            float rcx = ring.X + ring.Width / 2f, rcy = ring.Y + ring.Height / 2f;
            DrawValue(g, value, fRingSmall, fMicro, missing ? Dim : TextC, rcx, rcy - S(1));
            DrawCentered(g, label, fMicro, missing ? Dim : Muted, rcx, ring.Bottom - S(5));
        }

        // Rocket (free up memory) and Game Mode side by side.
        int bx = pad + 3 * cellW + S(6);
        int by = (h - S(30)) / 2;
        bool showBadge = rocketBadge is not null && DateTime.Now < flashUntil && !boosting;
        RoundAction(g, new Rectangle(bx, by, S(30), S(30)), "boost", Boost, filled: true, lit: boosting, DrawRocket,
            showBadge ? rocketBadge : null);
        RoundAction(g, new Rectangle(bx + S(36), by, S(30), S(30)), "game", ToggleGameMode, filled: false, lit: GameMode.Active, DrawGamepad);

        // Expand above close, at the right edge.
        int cx = w - S(26);
        var expand = new Rectangle(cx, S(5), S(20), S(20));
        IconButton(g, expand, "expand", () => SetCollapsed(false), (gr, r, pen) =>
        {
            // two outward arrows (expand)
            gr.DrawLines(pen, new[] { new PointF(r.X + r.Width * .55f, r.Y + r.Height * .25f), new PointF(r.Right - r.Width * .25f, r.Y + r.Height * .25f), new PointF(r.Right - r.Width * .25f, r.Y + r.Height * .45f) });
            gr.DrawLines(pen, new[] { new PointF(r.X + r.Width * .45f, r.Bottom - r.Height * .25f), new PointF(r.X + r.Width * .25f, r.Bottom - r.Height * .25f), new PointF(r.X + r.Width * .25f, r.Bottom - r.Height * .45f) });
        });
        IconButton(g, new Rectangle(cx, h - S(25), S(20), S(20)), "close", Hide, DrawX);
    }

    /// <summary>"CPU 11%" centred in a label strip, the second part brighter.</summary>
    void DrawLabelPair(Graphics g, Rectangle r, string a, string b, Color bColor)
    {
        int lw = TextRenderer.MeasureText(g, a + " ", fTiny, Size.Empty, TextFormatFlags.NoPadding).Width;
        int tw = TextRenderer.MeasureText(g, b, fTiny, Size.Empty, TextFormatFlags.NoPadding).Width;
        int x0 = r.X + (r.Width - lw - tw) / 2;
        Draw(g, a, fTiny, Muted, new Rectangle(x0, r.Y, lw, r.Height), TextFormatFlags.Left | TextFormatFlags.Top);
        Draw(g, b, fTiny, bColor == Muted ? Dim : bColor, new Rectangle(x0 + lw, r.Y, tw + S(2), r.Height), TextFormatFlags.Left | TextFormatFlags.Top);
    }

    void PaintExpanded(Graphics g, int w, int h)
    {
        int pad = S(14);

        // Header: mark, name, then copy-image, collapse, close. The rest of the header drags the overlay.
        DrawMark(g, new Rectangle(pad, S(15), S(16), S(16)));
        Draw(g, "SystemForge", fTitle, TextC, new Rectangle(pad + S(24), S(12), S(130), S(22)), TextFormatFlags.VerticalCenter);
        if (GameMode.Active)
        {
            int tw = TextRenderer.MeasureText(g, "SystemForge", fTitle, Size.Empty, TextFormatFlags.NoPadding).Width;
            var pill = new Rectangle(pad + S(24) + tw + S(8), S(14), S(66), S(18));
            FillRound(g, pill, S(9), Color.FromArgb(40, Accent));
            using (var pen = new Pen(Color.FromArgb(150, Accent))) DrawRound(g, pen, pill, S(9));
            Draw(g, "GAME MODE", fTiny, Accent, pill, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        var close = new Rectangle(w - pad - S(24), S(11), S(24), S(24));
        var collapse = new Rectangle(close.X - S(28), S(11), S(24), S(24));
        var camera = new Rectangle(collapse.X - S(28), S(11), S(24), S(24));
        IconButton(g, camera, "copy", CopyAsImage, DrawCamera);
        IconButton(g, collapse, "collapse", () => SetCollapsed(true), (gr, r, pen) =>
            gr.DrawLine(pen, r.X + r.Width * .28f, r.Y + r.Height * .55f, r.Right - r.Width * .28f, r.Y + r.Height * .55f));
        IconButton(g, close, "close", Hide, DrawX);

        // Usage | Temperatures switch. Clicking the meters themselves does the same.
        var seg = new Rectangle(pad, S(46), w - 2 * pad, S(24));
        FillRound(g, seg, S(7), Color.FromArgb(0x0A, 0x0E, 0x14));
        using (var pen = new Pen(Line)) DrawRound(g, pen, seg, S(7));
        var segUsage = new Rectangle(seg.X + S(2), seg.Y + S(2), seg.Width / 2 - S(2), seg.Height - S(4));
        var segTemps = new Rectangle(seg.X + seg.Width / 2, seg.Y + S(2), seg.Width / 2 - S(2), seg.Height - S(4));
        foreach (var (rect, key, on, text) in new[] { (segUsage, "mode:usage", !ShowTemps, "Usage"), (segTemps, "mode:temps", ShowTemps, "Temperatures") })
        {
            if (on)
            {
                using var brush = new LinearGradientBrush(rect, Accent, Accent2, LinearGradientMode.Horizontal);
                using var path = RoundPath(rect, S(5));
                g.FillPath(brush, path);
            }
            else if (hover == key && !capturing) FillRound(g, rect, S(5), Raised);
            Draw(g, text, fSmall, on ? Ink : hover == key ? TextC : Muted, rect, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
            bool wantTemps = key == "mode:temps";
            hits.Add((rect, key, () => SetShowTemps(wantTemps)));
        }

        int y = S(80);
        hits.Add((new Rectangle(pad, y, w - 2 * pad, 3 * S(44)), "gauges", () => SetShowTemps(!ShowTemps)));
        if (ShowTemps)
        {
            string unit = owner.Settings.TempUnit == "F" ? "°F" : "°C";
            int rowY = y;
            bool driverLink = cpuTemp is null && cpuNeedsDriver;
            y = DrawMeter(g, "Processor", driverLink ? "" : cpuTemp is null ? "–" : Temp(cpuTemp),
                TempFill(cpuTemp), TempLoadColor(cpuTemp, CpuC), pad, y, w, $"{cpuPct:0}%", cpuTemp is null);
            if (driverLink)
            {
                // CPU temperature needs the optional sensor driver: link to where it's installed.
                const string link = "Get CPU temp ›";
                int tw = TextRenderer.MeasureText(g, link, fSmall, Size.Empty, TextFormatFlags.NoPadding).Width;
                var lr = new Rectangle(w - pad - tw - S(4), rowY, tw + S(4), S(20));
                Draw(g, link, fSmall, hover == "driver" && !capturing ? Lighten(Accent, 0.25) : Accent, lr, TextFormatFlags.Right | TextFormatFlags.VerticalCenter);
                hits.Insert(0, (lr, "driver", () => owner.ShowPage("performance")));
            }
            y = DrawMeter(g, "Graphics", gpuTemp is null ? "–" : Temp(gpuTemp),
                TempFill(gpuTemp), TempLoadColor(gpuTemp, GpuC), pad, y, w, $"{gpuPct:0}%", gpuTemp is null);
            y = DrawMeter(g, "Warmest drive", driveTemp is null ? "–" : Temp(driveTemp),
                TempFill(driveTemp), TempLoadColor(driveTemp, DiskC, drive: true), pad, y, w, null, driveTemp is null);
        }
        else
        {
            y = DrawMeter(g, "Processor", $"{cpuPct:0}%", cpuPct, LoadColor(cpuPct, CpuC), pad, y, w, cpuTemp is null ? null : Temp(cpuTemp), false, TempColor(cpuTemp));
            y = DrawMeter(g, "Graphics", $"{gpuPct:0}%", gpuPct, LoadColor(gpuPct, GpuC), pad, y, w, gpuTemp is null ? null : Temp(gpuTemp), false, TempColor(gpuTemp));
            y = DrawMeter(g, "Memory", $"{ramUsedGb:0.0} of {ramTotalGb:0} GB", ramPct, LoadColor(ramPct, RamC), pad, y, w);
        }

        int half = (w - 2 * pad - S(8)) / 2;
        var button = new Rectangle(pad, y + S(6), half, S(36));
        var gameButton = new Rectangle(button.Right + S(8), y + S(6), w - pad - button.Right - S(8), S(36));
        bool showFlash = flash is not null && DateTime.Now < flashUntil;
        bool hot = hover == "boost" && !boosting && !capturing;
        using (var path = RoundPath(button, S(8)))
        {
            using var brush = new LinearGradientBrush(button, hot ? Lighten(Accent, 0.12) : Accent, hot ? Lighten(Accent2, 0.12) : Accent2, LinearGradientMode.Horizontal);
            g.FillPath(brush, path);
            using var shine = new Pen(Color.FromArgb(70, Color.White));
            g.DrawLine(shine, button.X + S(8), button.Y + 1, button.Right - S(8), button.Y + 1);
        }
        string label = boosting ? "Freeing…" : showFlash ? flash! : "Free memory";
        if (!boosting && !showFlash)
        {
            // Rocket mark before the label, the pair centred in the button.
            int lw = TextRenderer.MeasureText(g, label, fButton, Size.Empty, TextFormatFlags.NoPadding).Width;
            int iw = S(18), gap = S(7);
            int x0 = button.X + (button.Width - iw - gap - lw) / 2;
            using (var pen = new Pen(Ink, Math.Max(1.4f, S(1) * 1.5f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                DrawRocket(g, new Rectangle(x0, button.Y + (button.Height - iw) / 2, iw, iw), pen);
            Draw(g, label, fButton, Ink, new Rectangle(x0 + iw + gap, button.Y, lw + S(4), button.Height), TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }
        else Draw(g, label, fButton, Ink, button, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        hits.Add((button, "boost", Boost));

        // Game Mode toggle: outlined when off, lit (with a glowing dot) when on.
        bool gameOn = GameMode.Active;
        bool gameHot = hover == "game" && !capturing;
        FillRound(g, gameButton, S(8), gameOn ? Color.FromArgb(48, Accent) : gameHot ? Raised : PanelHi);
        using (var pen = new Pen(gameOn ? Accent : gameHot ? LineHi : Line)) DrawRound(g, pen, gameButton, S(8));
        {
            Color gc = gameOn ? Accent : gameHot ? TextC : Muted;
            const string gameText = "Game Mode";
            int gw = TextRenderer.MeasureText(g, gameText, fButton, Size.Empty, TextFormatFlags.NoPadding).Width;
            int iw = S(20), gap = S(7);
            int gx = gameButton.X + (gameButton.Width - iw - gap - gw) / 2;
            using (var pen = new Pen(gc, Math.Max(1.4f, S(1) * 1.5f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                DrawGamepad(g, new Rectangle(gx, gameButton.Y + (gameButton.Height - S(16)) / 2, iw, S(16)), pen);
            Draw(g, gameText, fButton, gc, new Rectangle(gx + iw + gap, gameButton.Y, gw + S(4), gameButton.Height), TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
            if (gameOn)
            {
                var dot = new Rectangle(gameButton.Right - S(10), gameButton.Y + S(5), S(5), S(5));
                using var glow = new SolidBrush(Color.FromArgb(90, RamC));
                g.FillEllipse(glow, Rectangle.Inflate(dot, S(2), S(2)));
                using var b = new SolidBrush(RamC);
                g.FillEllipse(b, dot);
            }
        }
        hits.Add((gameButton, "game", ToggleGameMode));
        y = button.Bottom + S(18);

        Draw(g, "USING THE MOST MEMORY", fTiny, Dim, new Rectangle(pad, y, w - 2 * pad, S(16)), TextFormatFlags.Left);
        {
            int tw = TextRenderer.MeasureText(g, "USING THE MOST MEMORY", fTiny, Size.Empty, TextFormatFlags.NoPadding).Width;
            using var hair = new Pen(Color.FromArgb(0x24, 0x2D, 0x3B));
            g.DrawLine(hair, pad + tw + S(10), y + S(8), w - pad, y + S(8));
        }
        y += S(22);

        if (DateTime.Now > armedUntil) armed = null;
        foreach (var app in top.Take(Rows))
        {
            var row = new Rectangle(pad, y, w - 2 * pad, S(30));
            var icon = IconService.GetBitmap(app.ExePath);
            var iconRect = new Rectangle(row.X, row.Y + S(7), S(16), S(16));
            if (icon is not null) lock (icon) g.DrawImage(icon, iconRect);
            else FillRound(g, iconRect, S(4), Raised);

            int endW = S(54);
            var endRect = new Rectangle(row.Right - endW, row.Y + S(4), endW, S(22));
            var ramRect = new Rectangle(endRect.X - S(70), row.Y, S(64), row.Height);
            var nameRect = new Rectangle(iconRect.Right + S(8), row.Y, ramRect.X - iconRect.Right - S(12), row.Height);

            string name = app.Count > 1 ? $"{app.DisplayName} ({app.Count})" : app.DisplayName;
            Draw(g, name, fLabel, TextC, nameRect, TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            Draw(g, FormatMb(app.RamMb), fLabel, Muted, ramRect, TextFormatFlags.VerticalCenter | TextFormatFlags.Right);

            if (!app.Protected)
            {
                string key = "end:" + app.Name;
                bool isArmed = armed == app.Name && !capturing;
                bool isHover = hover == key && !capturing;
                if (isArmed) FillRound(g, endRect, S(6), Bad);
                else if (isHover) FillRound(g, endRect, S(6), Raised);
                using (var pen = new Pen(isArmed ? Bad : Line)) DrawRound(g, pen, endRect, S(6));
                Draw(g, isArmed ? "Sure?" : "End", fSmall, isArmed ? Ink : (isHover ? TextC : Muted), endRect,
                    TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
                var captured = app;
                hits.Add((endRect, key, () => EndApp(captured)));
            }
            y += S(30);
        }

        Draw(g, $"{MainForm.HotkeyLabel} shows or hides this", fSmall, Dim,
            new Rectangle(pad, h - S(28), w - 2 * pad, S(18)), TextFormatFlags.Left);
    }

    /// <summary>
    /// Label, value and a bar. <paramref name="pill"/> is the other reading in a small chip next to the label
    /// (the temperature in usage view, the usage in temperature view).
    /// </summary>
    int DrawMeter(Graphics g, string label, string value, double pct, Color color, int pad, int y, int w,
        string? pill = null, bool valueDim = false, Color? pillColor = null)
    {
        Draw(g, label, fLabel, Muted, new Rectangle(pad, y, w - 2 * pad, S(20)), TextFormatFlags.VerticalCenter);
        if (pill is not null)
        {
            int lw = TextRenderer.MeasureText(g, label, fLabel, Size.Empty, TextFormatFlags.NoPadding).Width;
            var tr = new Rectangle(pad + lw + S(8), y + S(2), S(52), S(16));
            FillRound(g, tr, S(8), Raised);
            var pc = pillColor ?? Muted;
            Draw(g, pill, fTiny, pc == Muted ? TextC : pc, tr, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
        Draw(g, value, valueDim ? fSmall : fValue, valueDim ? Dim : TextC, new Rectangle(pad, y, w - 2 * pad, S(20)), TextFormatFlags.VerticalCenter | TextFormatFlags.Right);

        // Inset track with faint quarter ticks, then a lit bar with a bright leading edge.
        var track = new Rectangle(pad, y + S(25), w - 2 * pad, S(6));
        FillRound(g, track, S(3), Color.FromArgb(0x0A, 0x0E, 0x15));
        using (var rim = new Pen(Color.FromArgb(40, Color.White))) g.DrawLine(rim, track.X + S(3), track.Bottom, track.Right - S(3), track.Bottom);
        using (var tick = new Pen(Color.FromArgb(28, Color.White)))
            for (int q = 1; q < 4; q++) g.DrawLine(tick, track.X + track.Width * q / 4f, track.Y + 1, track.X + track.Width * q / 4f, track.Bottom - 1);
        int fill = (int)(track.Width * Math.Clamp(pct, 0, 100) / 100);
        if (fill >= S(6))
        {
            var bar = new Rectangle(track.X, track.Y, fill, track.Height);
            using (var glowPen = new Pen(Color.FromArgb(70, color), S(7)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                g.DrawLine(glowPen, bar.X + S(3), bar.Y + bar.Height / 2f, bar.Right - S(3), bar.Y + bar.Height / 2f);
            using (var path = RoundPath(bar, S(3)))
            using (var brush = new LinearGradientBrush(bar, Color.FromArgb(200, color), Lighten(color, 0.25), LinearGradientMode.Horizontal))
                g.FillPath(brush, path);
            using var cap = new SolidBrush(Color.FromArgb(220, Color.White));
            g.FillEllipse(cap, bar.Right - S(4), bar.Y + 1, S(3), S(4));
        }
        return y + S(44);
    }

    /// <summary>
    /// A 270° instrument ring: a dark inset track with faint ticks, the reading as a glowing arc that
    /// brightens toward its tip, and a small bright cap where it ends.
    /// </summary>
    void DrawRing(Graphics g, Rectangle r, double pct, Color color, int thickness)
    {
        var inner = Rectangle.Inflate(r, -thickness / 2 - 1, -thickness / 2 - 1);
        const float start = 135, sweep = 270;
        float cx = inner.X + inner.Width / 2f, cy = inner.Y + inner.Height / 2f, rad = inner.Width / 2f;

        using (var track = new Pen(Color.FromArgb(0x0A, 0x0E, 0x15), thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            g.DrawArc(track, inner, start, sweep);
        using (var rim = new Pen(Color.FromArgb(26, Color.White), 1f))
            g.DrawArc(rim, Rectangle.Inflate(inner, thickness / 2, thickness / 2), start, sweep);
        using (var tick = new Pen(Color.FromArgb(40, Color.White), 1f))
            for (int i = 0; i <= 4; i++)
            {
                double a = (start + sweep * i / 4) * Math.PI / 180;
                float r1 = rad - thickness / 2f + 1, r2 = rad + thickness / 2f - 1;
                g.DrawLine(tick, cx + (float)(r1 * Math.Cos(a)), cy + (float)(r1 * Math.Sin(a)), cx + (float)(r2 * Math.Cos(a)), cy + (float)(r2 * Math.Sin(a)));
            }

        float filled = (float)(sweep * Math.Clamp(pct, 0, 100) / 100);
        if (filled < 1.5f) return;
        using (var glow = new Pen(Color.FromArgb(60, color), thickness + S(5)) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            g.DrawArc(glow, inner, start, filled);
        using (var pen = new Pen(Color.FromArgb(215, color), thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            g.DrawArc(pen, inner, start, filled);
        // Brighter toward the tip: a second, shorter pass in a lighter shade.
        float tail = Math.Min(filled, 60);
        using (var hot = new Pen(Lighten(color, 0.35), thickness) { StartCap = LineCap.Round, EndCap = LineCap.Round })
            g.DrawArc(hot, inner, start + filled - tail, tail);
        double end = (start + filled) * Math.PI / 180;
        float capR = thickness / 2f + 0.5f;
        using (var capGlow = new SolidBrush(Color.FromArgb(120, Color.White)))
            g.FillEllipse(capGlow, cx + (float)(rad * Math.Cos(end)) - capR - 1, cy + (float)(rad * Math.Sin(end)) - capR - 1, 2 * capR + 2, 2 * capR + 2);
        using var cap = new SolidBrush(Color.White);
        g.FillEllipse(cap, cx + (float)(rad * Math.Cos(end)) - capR + 1, cy + (float)(rad * Math.Sin(end)) - capR + 1, 2 * capR - 2, 2 * capR - 2);
    }

    /// <summary>Text placed by measurement so its visual centre lands exactly on (cx, cy).</summary>
    void DrawCentered(Graphics g, string text, Font font, Color color, float cx, float cy)
    {
        var size = TextRenderer.MeasureText(g, text, font, Size.Empty, TextFormatFlags.NoPadding);
        Draw(g, text, font, color, new Rectangle((int)Math.Round(cx - size.Width / 2f), (int)Math.Round(cy - size.Height / 2f), size.Width + 1, size.Height),
            TextFormatFlags.Left | TextFormatFlags.Top);
    }

    /// <summary>A number with its unit ("°" or "%") as a small superscript, the pair centred on (cx, cy).</summary>
    void DrawValue(Graphics g, string value, Font big, Font small, Color color, float cx, float cy)
    {
        string unit = value.EndsWith('°') || value.EndsWith('%') ? value[^1..] : "";
        string num = unit.Length > 0 ? value[..^1] : value;
        var ns = TextRenderer.MeasureText(g, num, big, Size.Empty, TextFormatFlags.NoPadding);
        var us = unit.Length > 0 ? TextRenderer.MeasureText(g, unit, small, Size.Empty, TextFormatFlags.NoPadding) : Size.Empty;
        int total = ns.Width + us.Width;
        int x = (int)Math.Round(cx - total / 2f), y = (int)Math.Round(cy - ns.Height / 2f);
        Draw(g, num, big, color, new Rectangle(x, y, ns.Width + 1, ns.Height), TextFormatFlags.Left | TextFormatFlags.Top);
        if (unit.Length > 0)
            Draw(g, unit, small, Color.FromArgb(180, color), new Rectangle(x + ns.Width, y, us.Width + 1, us.Height), TextFormatFlags.Left | TextFormatFlags.Top);
    }

    /// <summary>Metric colour normally; amber then red as the load climbs.</summary>
    static Color LoadColor(double pct, Color metric) => pct >= 90 ? Bad : pct >= 75 ? Warn : metric;

    void IconButton(Graphics g, Rectangle r, string key, Action action, Action<Graphics, Rectangle, Pen> icon)
    {
        bool hot = hover == key && !capturing;
        if (hot) FillRound(g, r, S(6), Raised);
        using var pen = new Pen(hot ? TextC : Muted, Math.Max(1.4f, S(1) * 1.5f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
        icon(g, r, pen);
        hits.Add((r, key, action));
    }

    /// <summary>A round button: the rocket is filled with the accent gradient, Game Mode lights up when on.</summary>
    void RoundAction(Graphics g, Rectangle r, string key, Action action, bool filled, bool lit, Action<Graphics, Rectangle, Pen> icon, string? text = null)
    {
        bool hot = hover == key && !capturing;
        Color stroke;
        if (filled)
        {
            using var brush = new LinearGradientBrush(r, hot ? Lighten(Accent, 0.15) : Accent, hot ? Lighten(Accent2, 0.15) : Accent2, LinearGradientMode.ForwardDiagonal);
            g.FillEllipse(brush, r);
            if (lit)
            {
                using var glow = new Pen(Color.FromArgb(90, Accent), S(3));
                g.DrawEllipse(glow, Rectangle.Inflate(r, S(2), S(2)));
            }
            stroke = Ink;
        }
        else
        {
            using (var fill = new SolidBrush(lit ? Color.FromArgb(48, Accent) : hot ? Raised : PanelHi)) g.FillEllipse(fill, r);
            using (var ring = new Pen(lit ? Accent : hot ? LineHi : Line)) g.DrawEllipse(ring, r);
            stroke = lit ? Accent : hot ? TextC : Muted;
        }
        if (text is not null)
            Draw(g, text, fTiny, stroke, r, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        else
        {
            using var pen = new Pen(stroke, Math.Max(1.4f, S(1) * 1.5f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            icon(g, Rectangle.Inflate(r, -r.Width / 5, -r.Height / 5), pen);
        }
        hits.Add((r, key, action));
    }

    /// <summary>A small rocket pointing up and to the right: body, window, fins and a flame.</summary>
    static void DrawRocket(Graphics g, Rectangle r, Pen pen)
    {
        var state = g.Save();
        float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, u = r.Width / 20f;
        g.TranslateTransform(cx, cy);
        g.RotateTransform(45);
        using (var body = new GraphicsPath())
        {
            body.AddBezier(0, -10 * u, 4.5f * u, -6 * u, 4.5f * u, 0, 3.6f * u, 4.5f * u);
            body.AddLine(3.6f * u, 4.5f * u, -3.6f * u, 4.5f * u);
            body.AddBezier(-3.6f * u, 4.5f * u, -4.5f * u, 0, -4.5f * u, -6 * u, 0, -10 * u);
            body.CloseFigure();
            g.DrawPath(pen, body);
        }
        g.DrawEllipse(pen, -1.6f * u, -4.2f * u, 3.2f * u, 3.2f * u);
        g.DrawLines(pen, new[] { new PointF(-3.8f * u, 1.5f * u), new PointF(-6.5f * u, 5.5f * u), new PointF(-3.6f * u, 4.5f * u) });
        g.DrawLines(pen, new[] { new PointF(3.8f * u, 1.5f * u), new PointF(6.5f * u, 5.5f * u), new PointF(3.6f * u, 4.5f * u) });
        g.DrawLines(pen, new[] { new PointF(-1.6f * u, 6.2f * u), new PointF(0, 9.5f * u), new PointF(1.6f * u, 6.2f * u) });
        g.Restore(state);
    }

    /// <summary>A game controller: rounded body with grips, a d-pad and two buttons.</summary>
    static void DrawGamepad(Graphics g, Rectangle r, Pen pen)
    {
        float x = r.X, y = r.Y, w = r.Width, h = r.Height;
        float top = y + h * 0.18f, bottom = y + h * 0.88f;
        using (var body = new GraphicsPath())
        {
            body.AddBezier(x + w * 0.22f, top, x + w * 0.05f, top, x - w * 0.02f, bottom, x + w * 0.14f, bottom);
            body.AddBezier(x + w * 0.14f, bottom, x + w * 0.24f, bottom, x + w * 0.3f, y + h * 0.66f, x + w * 0.38f, y + h * 0.66f);
            body.AddLine(x + w * 0.38f, y + h * 0.66f, x + w * 0.62f, y + h * 0.66f);
            body.AddBezier(x + w * 0.62f, y + h * 0.66f, x + w * 0.7f, y + h * 0.66f, x + w * 0.76f, bottom, x + w * 0.86f, bottom);
            body.AddBezier(x + w * 0.86f, bottom, x + w * 1.02f, bottom, x + w * 0.95f, top, x + w * 0.78f, top);
            body.CloseFigure();
            g.DrawPath(pen, body);
        }
        float dx = x + w * 0.28f, dy = y + h * 0.44f, d = w * 0.08f;
        g.DrawLine(pen, dx - d, dy, dx + d, dy);
        g.DrawLine(pen, dx, dy - d, dx, dy + d);
        float b = Math.Max(1f, w * 0.035f);
        g.DrawEllipse(pen, x + w * 0.66f - b, y + h * 0.4f - b, 2 * b, 2 * b);
        g.DrawEllipse(pen, x + w * 0.76f - b, y + h * 0.5f - b, 2 * b, 2 * b);
    }

    static void DrawX(Graphics g, Rectangle r, Pen pen)
    {
        float a = r.Width * 0.32f;
        g.DrawLine(pen, r.X + a, r.Y + a, r.Right - a, r.Bottom - a);
        g.DrawLine(pen, r.Right - a, r.Y + a, r.X + a, r.Bottom - a);
    }

    static void DrawCamera(Graphics g, Rectangle r, Pen pen)
    {
        var body = RectangleF.FromLTRB(r.X + r.Width * .22f, r.Y + r.Height * .35f, r.Right - r.Width * .22f, r.Bottom - r.Height * .28f);
        using (var path = RoundPathF(body, r.Width * .08f)) g.DrawPath(pen, path);
        g.DrawLine(pen, r.X + r.Width * .42f, body.Top, r.X + r.Width * .46f, r.Y + r.Height * .27f);
        g.DrawLine(pen, r.X + r.Width * .46f, r.Y + r.Height * .27f, r.X + r.Width * .58f, r.Y + r.Height * .27f);
        g.DrawLine(pen, r.X + r.Width * .58f, r.Y + r.Height * .27f, r.X + r.Width * .62f, body.Top);
        float cd = body.Height * .5f;
        g.DrawEllipse(pen, body.X + (body.Width - cd) / 2, body.Y + (body.Height - cd) / 2, cd, cd);
    }

    void DrawMark(Graphics g, Rectangle r)
    {
        using var brush = new LinearGradientBrush(r, Accent, Accent2, LinearGradientMode.ForwardDiagonal);
        using var pen = new Pen(brush, Math.Max(1.5f, S(2))) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        g.DrawArc(pen, r, 150, 240);
        float cx = r.X + r.Width / 2f, cy = r.Y + r.Height / 2f, len = r.Width * 0.38f;
        double a = -40 * Math.PI / 180;
        g.DrawLine(pen, cx, cy, cx + (float)(len * Math.Cos(a)), cy + (float)(len * Math.Sin(a)));
    }

    static Color Lighten(Color c, double amount) => Color.FromArgb(c.A,
        (int)(c.R + (255 - c.R) * amount), (int)(c.G + (255 - c.G) * amount), (int)(c.B + (255 - c.B) * amount));

    static void Draw(Graphics g, string text, Font font, Color color, Rectangle rect, TextFormatFlags flags) =>
        TextRenderer.DrawText(g, text, font, rect, color, flags | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine);

    static GraphicsPath RoundPath(Rectangle r, int radius) => RoundPathF(r, radius);

    static GraphicsPath RoundPathF(RectangleF r, float radius)
    {
        float d = Math.Max(1, Math.Min(radius * 2, Math.Min(r.Width, r.Height)));
        var p = new GraphicsPath();
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    static void FillRound(Graphics g, Rectangle r, int radius, Color color)
    {
        using var path = RoundPath(r, radius);
        using var brush = new SolidBrush(color);
        g.FillPath(brush, path);
    }

    static void DrawRound(Graphics g, Pen pen, Rectangle r, int radius)
    {
        using var path = RoundPath(r, radius);
        g.DrawPath(pen, path);
    }

    static string ShortMb(double mb) => mb >= 1024 ? $"{mb / 1024:0.0}G" : $"{mb:0}M";

    static string FormatMb(double mb) => mb >= 1024 ? $"{mb / 1024:0.0} GB" : $"{mb:0} MB";
    static string Shorten(string s, int max) => s.Length <= max ? s : s[..(max - 1)] + "…";

    // ---- mouse ----

    string? HitKey(Point p) => hits.FirstOrDefault(h => h.rect.Contains(p)).key;

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (pressPending && e.Button == MouseButtons.Left &&
            (Math.Abs(e.X - pressAt.X) > S(4) || Math.Abs(e.Y - pressAt.Y) > S(4)))
        {
            pressPending = false;
            Native.ReleaseCapture();
            Native.SendMessage(Handle, Native.WM_NCLBUTTONDOWN, (IntPtr)Native.HTCAPTION, IntPtr.Zero);
            SaveOffset();
            return;
        }
        var key = HitKey(e.Location);
        if (key == hover) return;
        hover = key;
        Cursor = key is null ? Cursors.Default : Cursors.Hand;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        hover = null;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left) return;

        var hit = hits.FirstOrDefault(h => h.rect.Contains(e.Location));
        if (hit.key == "gauges" && Collapsed)
        {
            // Wait to see whether this is a click (switch view) or the start of a drag (move the overlay).
            pressPending = true;
            pressAt = e.Location;
            return;
        }
        if (hit.action is not null)
        {
            hit.action();
            return;
        }

        // Collapsed: drag from anywhere. Expanded: drag by the header.
        if (Collapsed || e.Y < S(46))
        {
            // This call returns when the mouse is released.
            Native.ReleaseCapture();
            Native.SendMessage(Handle, Native.WM_NCLBUTTONDOWN, (IntPtr)Native.HTCAPTION, IntPtr.Zero);
            SaveOffset();
        }
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        if (!pressPending) return;
        pressPending = false;
        if (e.Button == MouseButtons.Left) SetShowTemps(!ShowTemps);
    }

    protected override void WndProc(ref Message m)
    {
        // Dragging works by pretending the header is a title bar, so a double-click arrives as a title-bar
        // double-click. Use it to switch size instead of letting Windows try to maximize the overlay.
        const int WM_NCLBUTTONDBLCLK = 0x00A3;
        if (m.Msg == WM_NCLBUTTONDBLCLK)
        {
            SetCollapsed(!Collapsed);
            return;
        }
        base.WndProc(ref m);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            timer.Dispose();
            gpu.Dispose();
            foreach (var f in new Font?[] { fTitle, fLabel, fValue, fButton, fSmall, fRing, fTiny, fRingSmall, fMicro }) f?.Dispose();
        }
        base.Dispose(disposing);
    }
}
