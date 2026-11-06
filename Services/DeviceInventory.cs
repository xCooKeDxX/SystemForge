using System.Runtime.InteropServices;

namespace SystemForge;

/// <summary>A device Windows knows about, connected or not, with the driver it uses.</summary>
public sealed record DeviceInfo(
    string InstanceId,
    string Name,
    string Class,
    string Manufacturer,
    string Provider,
    string Version,
    DateTime? Date,
    string InfName,
    string MatchingId,
    bool Present,
    string[] HardwareIds,
    string[] CompatibleIds)
{
    public string Enumerator => InstanceId.Split('\\')[0].ToUpperInvariant();
    public bool HasDriver => InfName.Length > 0;
    public bool IsMicrosoftDriver => Provider.StartsWith("Microsoft", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Where an ID sits in Windows' match ranking for this device: 0 is the most specific hardware ID.
    /// Compatible IDs rank after every hardware ID. -1 = this device doesn't list it at all.
    /// </summary>
    public int Rank(string id)
    {
        for (int i = 0; i < HardwareIds.Length; i++)
            if (HardwareIds[i].Equals(id, StringComparison.OrdinalIgnoreCase)) return i;
        for (int i = 0; i < CompatibleIds.Length; i++)
            if (CompatibleIds[i].Equals(id, StringComparison.OrdinalIgnoreCase)) return 1000 + i;
        return -1;
    }

    /// <summary>Rank of the ID the current driver was matched on (no driver = worst possible).</summary>
    public int CurrentRank => MatchingId.Length == 0 ? int.MaxValue : (Rank(MatchingId) is var r && r >= 0 ? r : int.MaxValue - 1);
}

/// <summary>
/// Lists every device Windows has ever set up, including ones that are unplugged right now
/// (the same set Device Manager shows with "Show hidden devices").
/// </summary>
public static class DeviceInventory
{
    public static List<DeviceInfo> Scan()
    {
        var list = new List<DeviceInfo>();
        IntPtr set = SetupDiGetClassDevsW(IntPtr.Zero, null, IntPtr.Zero, DIGCF_ALLCLASSES);
        if (set == INVALID_HANDLE_VALUE) return list;
        try
        {
            var data = new Native.SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<Native.SP_DEVINFO_DATA>() };
            for (uint i = 0; SetupDiEnumDeviceInfo(set, i, ref data); i++)
            {
                try
                {
                    string id = Str(set, ref data, Keys.InstanceId);
                    if (id.Length == 0) continue;
                    string name = Str(set, ref data, Keys.FriendlyName);
                    if (name.Length == 0) name = Str(set, ref data, Keys.DeviceDesc);
                    if (name.Length == 0) name = Str(set, ref data, Keys.DriverDesc);
                    if (name.Length == 0) name = id;

                    list.Add(new DeviceInfo(
                        id,
                        name,
                        Str(set, ref data, Keys.Class),
                        Str(set, ref data, Keys.Manufacturer),
                        Str(set, ref data, Keys.DriverProvider),
                        Str(set, ref data, Keys.DriverVersion),
                        Date(set, ref data, Keys.DriverDate),
                        Path.GetFileName(Str(set, ref data, Keys.DriverInfPath)),
                        Str(set, ref data, Keys.MatchingDeviceId),
                        Bool(set, ref data, Keys.IsPresent) ?? true,
                        StrList(set, ref data, Keys.HardwareIds),
                        StrList(set, ref data, Keys.CompatibleIds)));
                }
                catch { /* skip a device we can't read */ }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
        return list;
    }

    // ---- property reading ----

    static byte[]? Raw(IntPtr set, ref Native.SP_DEVINFO_DATA data, DEVPROPKEY key, out uint type)
    {
        SetupDiGetDevicePropertyW(set, ref data, ref key, out type, null, 0, out uint needed, 0);
        if (needed == 0) return null;
        var buffer = new byte[needed];
        return SetupDiGetDevicePropertyW(set, ref data, ref key, out type, buffer, needed, out _, 0) ? buffer : null;
    }

    static string Str(IntPtr set, ref Native.SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var b = Raw(set, ref data, key, out uint type);
        if (b is null || type != DEVPROP_TYPE_STRING) return "";
        return System.Text.Encoding.Unicode.GetString(b).TrimEnd('\0').Trim();
    }

    static string[] StrList(IntPtr set, ref Native.SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var b = Raw(set, ref data, key, out uint type);
        if (b is null || type != DEVPROP_TYPE_STRING_LIST) return Array.Empty<string>();
        return System.Text.Encoding.Unicode.GetString(b).Split('\0', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    static DateTime? Date(IntPtr set, ref Native.SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var b = Raw(set, ref data, key, out uint type);
        if (b is null || type != DEVPROP_TYPE_FILETIME || b.Length < 8) return null;
        // Driver dates are calendar dates stored as UTC midnight; drop the UTC tag so they don't shift a day in other time zones.
        try { return DateTime.SpecifyKind(DateTime.FromFileTimeUtc(BitConverter.ToInt64(b, 0)).Date, DateTimeKind.Unspecified); } catch { return null; }
    }

    static bool? Bool(IntPtr set, ref Native.SP_DEVINFO_DATA data, DEVPROPKEY key)
    {
        var b = Raw(set, ref data, key, out uint type);
        if (b is null || type != DEVPROP_TYPE_BOOLEAN || b.Length < 1) return null;
        return b[0] != 0;
    }

    // ---- Windows API ----

    const uint DIGCF_ALLCLASSES = 0x4; // no DIGCF_PRESENT: include unplugged devices
    static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);
    const uint DEVPROP_TYPE_STRING = 0x12, DEVPROP_TYPE_STRING_LIST = 0x2012, DEVPROP_TYPE_FILETIME = 0x10, DEVPROP_TYPE_BOOLEAN = 0x11;

    [StructLayout(LayoutKind.Sequential)]
    struct DEVPROPKEY
    {
        public Guid fmtid;
        public uint pid;
        public DEVPROPKEY(string guid, uint pid) { fmtid = new Guid(guid); this.pid = pid; }
    }

    static class Keys
    {
        const string Device = "a45c254e-df1c-4efd-8020-67d146a850e0";
        const string Driver = "a8b865dd-2e3d-4094-ad97-e593a70c75d6";
        public static readonly DEVPROPKEY DeviceDesc = new(Device, 2);
        public static readonly DEVPROPKEY HardwareIds = new(Device, 3);
        public static readonly DEVPROPKEY CompatibleIds = new(Device, 4);
        public static readonly DEVPROPKEY Class = new(Device, 9);
        public static readonly DEVPROPKEY Manufacturer = new(Device, 13);
        public static readonly DEVPROPKEY FriendlyName = new(Device, 14);
        public static readonly DEVPROPKEY DriverDate = new(Driver, 2);
        public static readonly DEVPROPKEY DriverVersion = new(Driver, 3);
        public static readonly DEVPROPKEY DriverDesc = new(Driver, 4);
        public static readonly DEVPROPKEY DriverInfPath = new(Driver, 5);
        public static readonly DEVPROPKEY MatchingDeviceId = new(Driver, 8);
        public static readonly DEVPROPKEY DriverProvider = new(Driver, 9);
        public static readonly DEVPROPKEY InstanceId = new("78c34fc8-104a-4aca-9ea4-524d52996e57", 256);
        public static readonly DEVPROPKEY IsPresent = new("540b947e-8b40-45bc-a8a2-6a0b894cbda2", 5);
    }

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr SetupDiGetClassDevsW(IntPtr classGuid, string? enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref Native.SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiGetDevicePropertyW(IntPtr deviceInfoSet, ref Native.SP_DEVINFO_DATA deviceInfoData,
        ref DEVPROPKEY propertyKey, out uint propertyType, byte[]? propertyBuffer, uint propertyBufferSize, out uint requiredSize, uint flags);

    [DllImport("setupapi.dll", SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);
}
