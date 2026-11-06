# SystemForge

PC care for Windows 10 and 11, in one app: driver updates, a security scan that actually cleans up, junk cleanup, startup control, Game Mode, temperatures, and a small in-game overlay. Built to do what Driver Booster and Advanced SystemCare do, without the upsells and without the risky stuff.

![.NET 9](https://img.shields.io/badge/.NET-9-512BD4) ![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D4) ![License MIT](https://img.shields.io/badge/license-MIT-green)

## Install

Download `SystemForge-Setup-x.y.z.msi` from the [latest release](https://github.com/xCooKeDxX/SystemForge/releases/latest) and run it. It installs to Program Files and adds a Start menu entry. SystemForge checks for its own updates once a day and from Settings → Updates.

The installer isn't code-signed yet, so Windows SmartScreen shows "unknown publisher" the first time: click **More info → Run anyway**.

Needs the [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/), which Windows 11 and most Windows 10 PCs already have.

## What it does

- **Drivers.** Checks Windows Update, the Microsoft Update Catalog, NVIDIA, AMD (Radeon, Ryzen graphics and chipset), Intel, and Lenovo/Dell model-specific drivers, then offers only drivers Windows would pick for your exact hardware. Game components (Visual C++, DirectX, .NET runtimes) too. A restore point and a driver backup are made before anything changes, and every install can be rolled back.
- **BIOS notices.** Tells you when Lenovo, Dell, HP or ASUS has a newer BIOS and links to the maker's download. SystemForge never flashes a BIOS itself.
- **Security.** Microsoft Defender status and scans, plus its own checks for adware, browser hijacks, hidden auto-start tricks, scam remote-access sessions and weakened settings. Fixes quarantine instead of delete, and everything can be undone from the History tab.
- **Apps.** Tracks the programs you install and updates them through winget.
- **Cleanup.** Shows exactly which files would go before it removes anything.
- **Startup.** Turn startup apps off and on; nothing is uninstalled.
- **Performance.** Live CPU, GPU and memory, a "Free up memory" button that only trims background apps, and a list of open apps with a two-click "End" for stuck ones.
- **Game Mode.** Turns on by itself when a game starts: Best performance power mode (plugged in only), priority for the game, one memory trim, and no pop-ups. Everything goes back when the game closes. It doesn't stop services or close apps.
- **Temperatures.** CPU, graphics, motherboard and drives, in °C or °F. CPU and motherboard sensors need the optional [PawnIO](https://pawnio.eu/) driver, which SystemForge can install for you.
- **Overlay.** Ctrl + Alt + O over any game: usage or temperatures, a rocket to free memory, and a Game Mode button. It never takes focus.

## Safety first

SystemForge is meant to be handed to someone who has never updated a driver. So by default it hides drivers for storage controllers, chipset, firmware and unplugged devices, refuses to install anything unsigned, makes a fresh restore point first, and never pre-selects anything marked critical. Experienced users can turn on **Advanced driver options** in Settings. Security fixes never delete: files go to quarantine with an undo history, and Windows' own files are never touched.

## Credits

- **[PC Health Scan](https://github.com/TCPeep/PC-Health-Scan) by TCPeep.** The Security page's checks and its safety rules (quarantine instead of delete, an undo history, never touching Windows' own files) are inspired by his open-source scanner and used with his permission. SystemForge's implementation is its own code. Thanks, Peep.
- [LibreHardwareMonitor](https://github.com/LibreHardwareMonitor/LibreHardwareMonitor) (MPL-2.0) reads temperatures and fan speeds; [PawnIO](https://pawnio.eu/) by namazso is the optional sensor driver.
- Drivers come from Windows Update, the Microsoft Update Catalog, NVIDIA, AMD, Intel, Lenovo, Dell, HP and ASUS's own catalogs; apps from winget; virus scanning is Microsoft Defender's.

## Build it yourself

Needs the .NET 9 SDK.

```
cd source
dotnet publish -c Release -r win-x64 --self-contained true -o ..\publish
```

The MSI is built with `installer/build-msi.sh <publish folder> <version>` (msitools' `wixl`, on Linux or WSL), and `installer/sign.ps1` signs it once there's a code-signing certificate. Releases carry the MSI and its `.sha256`; the app verifies that checksum before installing an update.

## Project layout

```
Program.cs / MainForm.cs   entry point, main window (WebView2), tray, hotkey, Game Mode timer
OverlayForm.cs             the in-game overlay (custom drawn)
Bridge.cs                  messages between the dashboard and C#
Services/                  drivers (per source), security, cleanup, startup, Game Mode, sensors, updater
Services/Security/         Defender, the scanner, fixes with quarantine and undo
wwwroot/                   the dashboard (HTML, CSS, JS)
installer/                 MSI build, icon, signing script
```

## License

MIT. Use it, fork it, share it with your friends.
