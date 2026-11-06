using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace SystemForge;

/// <summary>One HTTP client for the whole app, plus download/verify helpers used by the driver sources.</summary>
public static class Downloader
{
    public static readonly HttpClient Http = CreateClient();

    static HttpClient CreateClient()
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(20),
        };
        var client = new HttpClient(handler) { Timeout = Timeout.InfiniteTimeSpan };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) SystemForge/0.2");
        return client;
    }

    public static string DataRoot =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SystemForge");

    public static string WorkRoot => Path.Combine(DataRoot, "Downloads");

    static readonly object SecureGate = new();
    static bool secured;

    /// <summary>
    /// ProgramData lets ordinary users create files in new subfolders by default. Drivers and installers are
    /// unpacked and run from here as admin, so lock ProgramData\SystemForge to SYSTEM and Administrators only
    /// (and make Administrators the owner, in case something else created the folder first).
    /// </summary>
    public static void EnsureSecureDataRoot()
    {
        lock (SecureGate)
        {
            if (secured) return;
            var dir = new DirectoryInfo(DataRoot);
            if (!dir.Exists) dir.Create();

            var admins = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var sec = new DirectorySecurity();
            sec.SetOwner(admins);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            const InheritanceFlags all = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            sec.AddAccessRule(new FileSystemAccessRule(admins, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            sec.AddAccessRule(new FileSystemAccessRule(system, FileSystemRights.FullControl, all, PropagationFlags.None, AccessControlType.Allow));
            try { dir.SetAccessControl(sec); }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Couldn't protect SystemForge's folder in ProgramData, so nothing was downloaded. {ex.Message}");
            }
            secured = true;
        }
    }

    /// <summary>A fresh, empty folder under ProgramData\SystemForge\Downloads, which only admins can write to.</summary>
    public static string NewWorkFolder(string name)
    {
        EnsureSecureDataRoot();
        var dir = Path.Combine(WorkRoot, $"{name}-{Guid.NewGuid():N}"[..Math.Min(64, name.Length + 33)]);
        Directory.CreateDirectory(dir);
        return dir;
    }

    public static void TryDelete(string? dir)
    {
        if (string.IsNullOrEmpty(dir)) return;
        try { if (Directory.Exists(dir)) Directory.Delete(dir, true); } catch { /* best effort */ }
    }

    /// <summary>Text from a page, with a per-request timeout.</summary>
    public static async Task<string> GetStringAsync(string url, int timeoutSeconds = 30, CancellationToken ct = default)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseContentRead, cts.Token);
            resp.EnsureSuccessStatusCode();
            return await resp.Content.ReadAsStringAsync(cts.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Our own time limit, not the caller cancelling: report it as a timeout so callers can treat it as a failure.
            throw new TimeoutException($"{new Uri(url).Host} didn't answer in time.");
        }
    }

    /// <summary>Downloads to a file, reporting 0–100. Only https URLs are accepted.</summary>
    public static Task DownloadAsync(string url, string file, Action<int>? progress, CancellationToken ct = default) =>
        DownloadAsync(url, file, progress, null, ct);

    /// <param name="referer">Some vendors (AMD) only serve installers to requests that come from their own site.</param>
    public static async Task DownloadAsync(string url, string file, Action<int>? progress, string? referer, CancellationToken ct = default)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new InvalidOperationException("Refused a download that isn't https.");

        using var req = new HttpRequestMessage(HttpMethod.Get, uri);
        if (referer is not null) req.Headers.Referrer = new Uri(referer);
        using var resp = await Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        resp.EnsureSuccessStatusCode();
        long? total = resp.Content.Headers.ContentLength;
        await using var src = await resp.Content.ReadAsStreamAsync(ct);
        await using var dst = new FileStream(file, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 16, useAsync: true);

        var buffer = new byte[1 << 16];
        long done = 0;
        int lastPct = -1;
        var idle = TimeSpan.FromSeconds(60);
        while (true)
        {
            using var readCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            readCts.CancelAfter(idle); // a stalled connection fails instead of hanging forever
            int n;
            try { n = await src.ReadAsync(buffer, readCts.Token); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                throw new TimeoutException("The download stalled for a minute and was stopped. Try again.");
            }
            if (n == 0) break;
            await dst.WriteAsync(buffer.AsMemory(0, n), ct);
            done += n;
            if (total is > 0)
            {
                int pct = (int)(done * 100 / total.Value);
                if (pct != lastPct) { lastPct = pct; progress?.Invoke(pct); }
            }
        }
        if (total is > 0 && done != total) throw new IOException("The download was cut short. Try again.");
    }

    public static string Sha1Base64(string file)
    {
        using var s = File.OpenRead(file);
        return Convert.ToBase64String(SHA1.HashData(s));
    }

    public static string Sha256Hex(string file)
    {
        using var s = File.OpenRead(file);
        return Convert.ToHexString(SHA256.HashData(s));
    }

    /// <summary>
    /// True when Windows trusts the file's Authenticode signature (valid chain, not revoked, not tampered)
    /// and the signer's name contains <paramref name="expectedPublisher"/>.
    /// </summary>
    public static bool IsSignedBy(string file, string expectedPublisher, out string signer)
    {
        signer = "";
        try
        {
#pragma warning disable SYSLIB0057 // reading the embedded signer certificate is exactly what we want here
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            signer = cert.GetNameInfo(X509NameType.SimpleName, false);
            if (!cert.Subject.Contains(expectedPublisher, StringComparison.OrdinalIgnoreCase)) return false;
        }
        catch { return false; }
        return WinVerifyTrustFile(file);
    }

    // ---- WinVerifyTrust ----

    static bool WinVerifyTrustFile(string file)
    {
        var fileInfo = new WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(),
            pcwszFilePath = file,
        };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = new WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
                dwUIChoice = 2,              // WTD_UI_NONE
                fdwRevocationChecks = 0,     // WTD_REVOKE_NONE (chain policy still checks)
                dwUnionChoice = 1,           // WTD_CHOICE_FILE
                pFile = pFile,
                dwStateAction = 0,
                dwProvFlags = 0x80,          // WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            };
            var action = new Guid("00AAC56B-CD44-11d0-8CC2-00C04FC295EE"); // WINTRUST_ACTION_GENERIC_VERIFY_V2
            return WinVerifyTrust(new IntPtr(-1), ref action, ref data) == 0;
        }
        catch { return false; }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pFile;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);
}
