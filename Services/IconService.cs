using System.Collections.Concurrent;
using System.Drawing.Imaging;

namespace SystemForge;

/// <summary>Pulls app icons out of .exe files, cached by path.</summary>
public static class IconService
{
    static readonly ConcurrentDictionary<string, Bitmap?> bitmaps = new(StringComparer.OrdinalIgnoreCase);
    static readonly ConcurrentDictionary<string, string?> dataUrls = new(StringComparer.OrdinalIgnoreCase);

    public static Bitmap? GetBitmap(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        return bitmaps.GetOrAdd(path, p =>
        {
            try
            {
                if (!File.Exists(p)) return null;
                using var icon = Icon.ExtractAssociatedIcon(p);
                return icon?.ToBitmap();
            }
            catch { return null; }
        });
    }

    /// <summary>Icon as a PNG data URL for the dashboard.</summary>
    public static string? GetDataUrl(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        return dataUrls.GetOrAdd(path, p =>
        {
            var bmp = GetBitmap(p);
            if (bmp is null) return null;
            try
            {
                lock (bmp)
                {
                    using var ms = new MemoryStream();
                    bmp.Save(ms, ImageFormat.Png);
                    return "data:image/png;base64," + Convert.ToBase64String(ms.ToArray());
                }
            }
            catch { return null; }
        });
    }
}
