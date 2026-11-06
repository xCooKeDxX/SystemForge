using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace SystemForge;

/// <summary>Whether Windows trusts a file's digital signature, and who signed it.</summary>
public sealed record FileSignature(bool Exists, bool Trusted, string Signer, bool IsMicrosoft, bool Catalog, string Status)
{
    public static readonly FileSignature Missing = new(false, false, "", false, false, "Missing");
}

/// <summary>
/// Signature checks for the Security page. Most Windows files aren't signed inside the file itself but through a
/// security catalog (a .cat file Windows keeps), so both kinds are checked; otherwise every system file would look unsigned.
/// Results are cached per path + size + date for the scan.
/// </summary>
public static class FileTrust
{
    static readonly ConcurrentDictionary<string, FileSignature> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static void ClearCache() => Cache.Clear();

    public static FileSignature Check(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return FileSignature.Missing;
        FileInfo fi;
        try { fi = new FileInfo(path); if (!fi.Exists) return FileSignature.Missing; }
        catch { return FileSignature.Missing; }
        string key = $"{fi.FullName}|{fi.Length}|{fi.LastWriteTimeUtc.Ticks}";
        return Cache.GetOrAdd(key, _ => Evaluate(fi.FullName));
    }

    static FileSignature Evaluate(string path)
    {
        // 1) Signature inside the file.
        int embedded = VerifyEmbedded(path);
        if (embedded == 0)
        {
            string signer = SignerOf(path);
            return new FileSignature(true, true, signer, IsMicrosoftName(signer), false, "Valid");
        }
        if (embedded == TRUST_E_BAD_DIGEST)
            return new FileSignature(true, false, SignerOf(path), false, false, "HashMismatch"); // changed after signing

        // 2) Signature through a Windows security catalog.
        var (catOk, catalogFile) = VerifyCatalog(path);
        if (catOk)
        {
            // If the catalog's signer can't be read, don't assume it's Microsoft: trusted, but not "Microsoft".
            string signer = catalogFile.Length > 0 ? SignerOf(catalogFile) : "";
            return new FileSignature(true, true, signer, IsMicrosoftName(signer), true, "Valid");
        }

        string status = embedded switch
        {
            TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => "NotSigned",
            CERT_E_EXPIRED => "Expired",
            CERT_E_REVOKED => "Revoked",
            CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING => "UntrustedRoot",
            _ => "NotTrusted",
        };
        return new FileSignature(true, false, status == "NotSigned" ? "" : SignerOf(path), false, false, status);
    }

    /// <summary>
    /// Microsoft's own signing identities. Deliberately exact: "Microsoft Windows Hardware Compatibility Publisher" is how
    /// Microsoft signs other companies' drivers (WHQL and attestation), and malware drivers have been signed that way too.
    /// </summary>
    static readonly HashSet<string> MicrosoftSigners = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft Windows", "Microsoft Windows Publisher", "Microsoft Corporation", "Microsoft Windows Production PCA 2011",
        "Microsoft Windows Early Launch Anti-malware Publisher", "Microsoft Windows Third Party Component CA 2012",
    };

    public static bool IsMicrosoftName(string signer) => MicrosoftSigners.Contains(signer.Trim());

    static string SignerOf(string file)
    {
        try
        {
#pragma warning disable SYSLIB0057
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
#pragma warning restore SYSLIB0057
            return cert.GetNameInfo(X509NameType.SimpleName, false);
        }
        catch { return ""; }
    }

    // ---- WinVerifyTrust: embedded signature ----

    static int VerifyEmbedded(string path)
    {
        var fileInfo = new WINTRUST_FILE_INFO { cbStruct = (uint)Marshal.SizeOf<WINTRUST_FILE_INFO>(), pcwszFilePath = path };
        IntPtr pFile = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pFile, false);
            var data = NewTrustData(1 /* WTD_CHOICE_FILE */, pFile);
            var action = GenericVerifyV2;
            int result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
            Close(ref data);
            return result;
        }
        catch { return -1; }
        finally
        {
            Marshal.DestroyStructure<WINTRUST_FILE_INFO>(pFile);
            Marshal.FreeHGlobal(pFile);
        }
    }

    // ---- WinVerifyTrust: catalog signature ----

    static (bool ok, string catalogFile) VerifyCatalog(string path)
    {
        // SHA-256 catalogs first (Windows 8+), then SHA-1 for older ones.
        foreach (string alg in new[] { "SHA256", null! })
        {
            var r = VerifyCatalogWith(path, alg);
            if (r.ok) return r;
        }
        return (false, "");
    }

    static (bool ok, string catalogFile) VerifyCatalogWith(string path, string? hashAlg)
    {
        IntPtr admin = IntPtr.Zero, catInfo = IntPtr.Zero;
        var driverAction = DriverActionVerify;
        try
        {
            bool acquired = hashAlg is null
                ? CryptCATAdminAcquireContext(out admin, ref driverAction, 0)
                : CryptCATAdminAcquireContext2(out admin, ref driverAction, hashAlg, IntPtr.Zero, 0);
            if (!acquired) return (false, "");

            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            IntPtr handle = fs.SafeFileHandle.DangerousGetHandle();
            uint size = 0;
            bool sized = hashAlg is null
                ? CryptCATAdminCalcHashFromFileHandle(handle, ref size, null, 0)
                : CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, null, 0);
            if (size == 0 || size > 256) return (false, "");
            var hash = new byte[size];
            bool hashed = hashAlg is null
                ? CryptCATAdminCalcHashFromFileHandle(handle, ref size, hash, 0)
                : CryptCATAdminCalcHashFromFileHandle2(admin, handle, ref size, hash, 0);
            if (!hashed) return (false, "");

            catInfo = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
            if (catInfo == IntPtr.Zero) return (false, "");

            var ci = new CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<CATALOG_INFO>() };
            if (!CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) return (false, "");

            string memberTag = Convert.ToHexString(hash);
            var catalog = new WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = ci.wszCatalogFile,
                pcwszMemberTag = memberTag,
                pcwszMemberFilePath = path,
                hMemberFile = handle,
                pbCalculatedFileHash = Marshal.AllocHGlobal((int)size),
                cbCalculatedFileHash = size,
                hCatAdmin = admin,
            };
            Marshal.Copy(hash, 0, catalog.pbCalculatedFileHash, (int)size);
            IntPtr pCat = Marshal.AllocHGlobal(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            try
            {
                Marshal.StructureToPtr(catalog, pCat, false);
                var data = NewTrustData(2 /* WTD_CHOICE_CATALOG */, pCat);
                var action = GenericVerifyV2;
                int result = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                Close(ref data);
                return (result == 0, ci.wszCatalogFile ?? "");
            }
            finally
            {
                Marshal.FreeHGlobal(catalog.pbCalculatedFileHash);
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(pCat);
                Marshal.FreeHGlobal(pCat);
            }
        }
        catch { return (false, ""); }
        finally
        {
            if (catInfo != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
            if (admin != IntPtr.Zero) CryptCATAdminReleaseContext(admin, 0);
        }
    }

    static WINTRUST_DATA NewTrustData(uint choice, IntPtr info) => new()
    {
        cbStruct = (uint)Marshal.SizeOf<WINTRUST_DATA>(),
        dwUIChoice = 2,              // WTD_UI_NONE
        fdwRevocationChecks = 0,     // WTD_REVOKE_NONE: no network lookups during a scan
        dwUnionChoice = choice,
        pInfo = info,
        dwStateAction = 1,           // WTD_STATEACTION_VERIFY (closed in Close)
        dwProvFlags = 0x1000,        // WTD_CACHE_ONLY_URL_RETRIEVAL: never go online
    };

    static void Close(ref WINTRUST_DATA data)
    {
        data.dwStateAction = 2; // WTD_STATEACTION_CLOSE
        var action = GenericVerifyV2;
        try { WinVerifyTrust(new IntPtr(-1), ref action, ref data); } catch { }
    }

    static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
    static readonly Guid DriverActionVerify = new("F750E6C3-38EE-11d1-85E5-00C04FC295EE");

    const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    const int CERT_E_CHAINING = unchecked((int)0x800B010A);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] public string? pcwszCatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] public string pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode)]
    static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminAcquireContext(out IntPtr hCatAdmin, ref Guid subsystem, uint flags);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATAdminAcquireContext2(out IntPtr hCatAdmin, ref Guid subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle(IntPtr hFile, ref uint cbHash, byte[]? pbHash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr hCatAdmin, IntPtr hFile, ref uint cbHash, byte[]? pbHash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr hCatAdmin, byte[] pbHash, uint cbHash, uint flags, IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CryptCATCatalogInfoFromContext(IntPtr hCatInfo, ref CATALOG_INFO psCatInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint flags);
}
