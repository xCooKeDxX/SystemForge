using System.Drawing.Drawing2D;

namespace SystemForge;

/// <summary>
/// Shown once after an install or an update, in SystemForge's own colours: "SystemForge x.y.z has been installed"
/// with a desktop-shortcut and start-with-Windows choice, or "updated to x.y.z" after a self-update.
/// </summary>
internal sealed class WelcomeDialog : Form
{
    static readonly Color Panel = Color.FromArgb(0x10, 0x15, 0x1E);
    static readonly Color TextC = Color.FromArgb(0xE8, 0xED, 0xF5);
    static readonly Color Muted = Color.FromArgb(0x8B, 0x97, 0xA8);
    static readonly Color Accent = Color.FromArgb(0x38, 0xC8, 0xFF);
    static readonly Color Accent2 = Color.FromArgb(0x7C, 0x6C, 0xFF);

    public bool DesktopShortcut => cbDesktop.Checked;
    public bool StartWithWindows => cbStart.Checked;

    readonly CheckBox cbDesktop = new();
    readonly CheckBox cbStart = new();

    public WelcomeDialog(string version, bool firstInstall, bool hasDesktopShortcut, bool autoStartOn)
    {
        Text = "SystemForge";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Panel;
        ForeColor = TextC;
        Font = new Font("Segoe UI", 10f);
        ClientSize = new Size(440, firstInstall ? 262 : 196);
        Icon = MainForm.BuildAppIcon(32);

        var title = new Label
        {
            Text = firstInstall ? $"SystemForge {version} has been installed" : $"SystemForge has been updated to {version}",
            Font = new Font("Bahnschrift", 15f, FontStyle.Regular),
            ForeColor = TextC, AutoSize = false, Location = new Point(24, 22), Size = new Size(392, 30),
        };
        var sub = new Label
        {
            Text = firstInstall
                ? "It lives in the Start menu and keeps an eye on drivers, security and your game sessions from the tray."
                : "Settings and history were kept. The Settings page shows what's new.",
            ForeColor = Muted, AutoSize = false, Location = new Point(24, 56), Size = new Size(392, 44),
        };
        Controls.Add(title);
        Controls.Add(sub);

        int y = 108;
        if (firstInstall)
        {
            cbDesktop.Text = "Add a shortcut to the desktop";
            cbDesktop.Checked = !hasDesktopShortcut;
            cbDesktop.Location = new Point(28, y);
            cbDesktop.AutoSize = true;
            cbDesktop.ForeColor = TextC;
            Controls.Add(cbDesktop);
            y += 32;
            cbStart.Text = "Start with Windows (quietly, in the tray)";
            cbStart.Checked = autoStartOn;
            cbStart.Location = new Point(28, y);
            cbStart.AutoSize = true;
            cbStart.ForeColor = TextC;
            Controls.Add(cbStart);
            y += 40;
        }
        else y += 4;

        var ok = new Button
        {
            Text = firstInstall ? "Open SystemForge" : "OK",
            DialogResult = DialogResult.OK, FlatStyle = FlatStyle.Flat, ForeColor = Color.FromArgb(0x05, 0x10, 0x1A),
            Font = new Font("Bahnschrift", 11f, FontStyle.Bold), Size = new Size(190, 38), Location = new Point(ClientSize.Width - 24 - 190, y),
        };
        ok.FlatAppearance.BorderSize = 0;
        ok.Paint += (_, e) =>
        {
            using var brush = new LinearGradientBrush(ok.ClientRectangle, Accent, Accent2, LinearGradientMode.Horizontal);
            e.Graphics.FillRectangle(brush, ok.ClientRectangle);
            TextRenderer.DrawText(e.Graphics, ok.Text, ok.Font, ok.ClientRectangle, ok.ForeColor, TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        };
        Controls.Add(ok);
        AcceptButton = ok;
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Native.SetDwmInt(Handle, Native.DWMWA_USE_IMMERSIVE_DARK_MODE, 1);
        Native.SetDwmInt(Handle, Native.DWMWA_CAPTION_COLOR, Native.ColorRef(Panel));
    }

    /// <summary>Creates SystemForge.lnk on the desktop pointing at the running exe.</summary>
    public static void CreateDesktopShortcut()
    {
        string path = DesktopShortcutPath();
        var t = new Thread(() =>
        {
            try
            {
                dynamic shell = Activator.CreateInstance(Type.GetTypeFromProgID("WScript.Shell")!)!;
                dynamic lnk = shell.CreateShortcut(path);
                lnk.TargetPath = Environment.ProcessPath;
                lnk.WorkingDirectory = AppContext.BaseDirectory;
                lnk.Description = "PC care: drivers, security, cleanup, performance";
                lnk.IconLocation = Environment.ProcessPath + ",0";
                lnk.Save();
            }
            catch { }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join(10000);
    }

    public static string DesktopShortcutPath() =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "SystemForge.lnk");
}
