namespace UapkiNet.Polyfil;

/// <summary>
/// Hex converter.
/// </summary>
public static class Hex
{
    /// <summary>
    /// Converts byte array to hex string.
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string ToHexString(byte[] data)
    {
        
        var chars = new char[data.Length * 2];
        const string a = "0123456789ABCDEF";
        var j = 0;
        
        foreach (var t in data)
        {
            chars[j++] = a[t >> 4];
            chars[j++] = a[t & 0xF];
        }
        
        return new string(chars);
    }

    /// <summary>
    /// Converts hex string to byte array.
    /// Accepts optional "0x" prefix and ignores leading/trailing spaces.
    /// </summary>
    /// <param name="s"></param>
    /// <returns></returns>
    /// <exception cref="FormatException"></exception>
    public static byte[] FromHexString(string s)
    {
        s = s.Trim();
        
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) 
            s = s.Substring(2);
        
        if ((s.Length & 1) != 0) 
            throw new FormatException("Invalid hex length.");
        
        var r = new byte[s.Length / 2];
        for (int i = 0, j = 0; i < s.Length; i += 2, j++)
        {
            var hi = N(s[i]); int lo = N(s[i + 1]);
            if (hi < 0 || lo < 0) throw new FormatException("Invalid hex char.");
            r[j] = (byte)((hi << 4) | lo);
        }
        return r;
    }

    /// <summary>
    /// Hex char to number
    /// </summary>
    /// <param name="c"></param>
    /// <returns></returns>
    private static int N(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }
}
