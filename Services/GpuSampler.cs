using System.Runtime.InteropServices;

namespace SystemForge;

/// <summary>
/// Total GPU use, measured the same way Task Manager does: Windows' "GPU Engine" performance counters
/// (works for NVIDIA, AMD and Intel on Windows 10 1709 and later). Each engine's load is the sum of every
/// process using it; the GPU's load is its busiest engine; with two GPUs (laptop iGPU + dGPU) we report the busier one.
/// Each consumer keeps its own sampler, because a reading is the change since that consumer's last call.
/// </summary>
public sealed class GpuSampler : IDisposable
{
    readonly object gate = new();
    IntPtr query, counter;
    bool ready, failed, primed;

    public double Sample()
    {
        lock (gate)
        {
            if (failed) return 0;
            try
            {
                if (!ready && !Open()) { failed = true; return 0; }
                if (Pdh.PdhCollectQueryData(query) != 0) return 0;
                if (!primed) { primed = true; return 0; } // rates need two collections
                return Read();
            }
            catch { return 0; }
        }
    }

    bool Open()
    {
        if (Pdh.PdhOpenQuery(null, IntPtr.Zero, out query) != 0) return false;
        // Wildcard instances are re-expanded on every collection, so newly started games are picked up.
        if (Pdh.PdhAddEnglishCounter(query, @"\GPU Engine(*)\Utilization Percentage", IntPtr.Zero, out counter) != 0)
        {
            Pdh.PdhCloseQuery(query);
            query = IntPtr.Zero;
            return false;
        }
        ready = true;
        return true;
    }

    double Read()
    {
        uint size = 0, count = 0;
        int status = Pdh.PdhGetFormattedCounterArray(counter, Pdh.PDH_FMT_DOUBLE | Pdh.PDH_FMT_NOCAP100, ref size, ref count, IntPtr.Zero);
        if (status != Pdh.PDH_MORE_DATA || size == 0) return 0;

        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            status = Pdh.PdhGetFormattedCounterArray(counter, Pdh.PDH_FMT_DOUBLE | Pdh.PDH_FMT_NOCAP100, ref size, ref count, buffer);
            if (status != 0) return 0;

            // Instance names look like "pid_1234_luid_0x0000_0x0000ABCD_phys_0_eng_3_engtype_3D".
            var perEngine = new Dictionary<string, double>(StringComparer.OrdinalIgnoreCase);
            int itemSize = Marshal.SizeOf<Pdh.PDH_FMT_COUNTERVALUE_ITEM_DOUBLE>();
            for (int i = 0; i < count; i++)
            {
                var item = Marshal.PtrToStructure<Pdh.PDH_FMT_COUNTERVALUE_ITEM_DOUBLE>(buffer + i * itemSize);
                if (item.CStatus != 0 && item.CStatus != Pdh.PDH_CSTATUS_NEW_DATA) continue;
                string name = Marshal.PtrToStringUni(item.szName) ?? "";
                int luid = name.IndexOf("luid_", StringComparison.OrdinalIgnoreCase);
                if (luid < 0) continue;
                string engineKey = name[luid..]; // drop the pid part: luid + phys + eng + type identifies one engine
                perEngine[engineKey] = perEngine.GetValueOrDefault(engineKey) + item.Value;
            }
            if (perEngine.Count == 0) return 0;
            return Math.Round(Math.Clamp(perEngine.Values.Max(), 0, 100), 1);
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (query != IntPtr.Zero) Pdh.PdhCloseQuery(query);
            query = IntPtr.Zero;
            ready = false;
        }
    }

    static class Pdh
    {
        public const uint PDH_FMT_DOUBLE = 0x00000200, PDH_FMT_NOCAP100 = 0x00008000;
        public const int PDH_MORE_DATA = unchecked((int)0x800007D2);
        public const uint PDH_CSTATUS_NEW_DATA = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct PDH_FMT_COUNTERVALUE_ITEM_DOUBLE
        {
            public IntPtr szName;
            public uint CStatus;   // PDH_FMT_COUNTERVALUE starts here (4-byte status, then 8-aligned union)
            public double Value;
        }

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern int PdhOpenQuery(string? dataSource, IntPtr userData, out IntPtr query);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern int PdhAddEnglishCounter(IntPtr query, string path, IntPtr userData, out IntPtr counter);

        [DllImport("pdh.dll")]
        public static extern int PdhCollectQueryData(IntPtr query);

        [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
        public static extern int PdhGetFormattedCounterArray(IntPtr counter, uint format, ref uint bufferSize, ref uint itemCount, IntPtr itemBuffer);

        [DllImport("pdh.dll")]
        public static extern int PdhCloseQuery(IntPtr query);
    }
}
