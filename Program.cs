namespace SystemForge;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        using var mutex = new Mutex(true, "SystemForge.SingleInstance", out bool isFirst);
        if (!isFirst)
        {
            // Already running: ask the existing window to come forward.
            Native.PostMessage(Native.HWND_BROADCAST, MainForm.WM_SHOWME, IntPtr.Zero, IntPtr.Zero);
            return;
        }

        ApplicationConfiguration.Initialize();
        bool startInTray = args.Contains("--tray", StringComparer.OrdinalIgnoreCase);
        Application.Run(new MainForm(startInTray));
    }
}
