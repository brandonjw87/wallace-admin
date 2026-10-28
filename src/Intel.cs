using System.Collections.Concurrent;
using System.IO;
using System.IO.Compression;
using System.Net;
using MaxMind.Db;

namespace WNH;

/// <summary>Host intelligence: names learned from DNS/TLS in the capture, reverse DNS, offline ASN/country
/// (GeoLite2 databases shipped with Sniffnet), IANA port names (Sniffnet's services list) and service tagging.</summary>
public static class Intel
{
    public static readonly ConcurrentDictionary<string, string> Names = new(); // ip -> host name
    static readonly ConcurrentDictionary<string, (string asn, string country)> asnCache = new();
    static readonly ConcurrentDictionary<string, byte> ptrPending = new();
    static readonly SemaphoreSlim ptrSem = new(8);
    static Reader asnDb, countryDb; static bool dbTried; static readonly object dbGate = new();
    static Dictionary<string, string> ports;

    public static bool GeoAvailable { get { EnsureDb(); return asnDb != null; } }

    static void EnsureDb()
    {
        if (dbTried) return;
        lock (dbGate)
        {
            if (dbTried) return;
            try { using var s = Core.Res("asn.mmdb"); if (s != null) asnDb = new Reader(s); } catch (Exception ex) { Core.Log("asn db: " + ex.Message); }
            try { using var s = Core.Res("country.mmdb"); if (s != null) countryDb = new Reader(s); } catch (Exception ex) { Core.Log("country db: " + ex.Message); }
            dbTried = true;
        }
    }

    public static (string asn, string country) Owner(string ip)
    {
        if (string.IsNullOrEmpty(ip) || IsPrivate(ip)) return ("", "");
        return asnCache.GetOrAdd(ip, k =>
        {
            EnsureDb(); string a = "", c = "";
            try
            {
                var addr = IPAddress.Parse(k);
                var r = asnDb?.Find<Dictionary<string, object>>(addr);
                if (r != null && r.TryGetValue("autonomous_system_organization", out var o)) a = o?.ToString() ?? "";
                var cr = countryDb?.Find<Dictionary<string, object>>(addr);
                if (cr != null && cr.TryGetValue("country", out var co) && co is Dictionary<string, object> cd && cd.TryGetValue("iso_code", out var iso)) c = iso?.ToString() ?? "";
            }
            catch { }
            return (a, c);
        });
    }

    public static bool IsPrivate(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return false;
        if (IPAddress.IsLoopback(a)) return true;
        var b = a.GetAddressBytes();
        if (b.Length == 4) return b[0] == 10 || b[0] == 192 && b[1] == 168 || b[0] == 172 && b[1] >= 16 && b[1] <= 31 || b[0] == 169 && b[1] == 254 || b[0] >= 224;
        return a.IsIPv6LinkLocal || a.IsIPv6Multicast || a.IsIPv6SiteLocal || (b[0] & 0xFE) == 0xFC;
    }

    public static void Learn(string ip, string name) { if (!string.IsNullOrEmpty(ip) && !string.IsNullOrEmpty(name)) Names[ip] = name.TrimEnd('.').ToLowerInvariant(); }

    public static string NameOf(string ip)
    {
        if (Names.TryGetValue(ip, out var n)) return n;
        if (ip == "192.0.2.11") return "this PC (AdGuard DNS / gateway)";
        if (ip.StartsWith("224.") || ip.StartsWith("239.") || ip == "255.255.255.255" || ip.StartsWith("ff0", StringComparison.OrdinalIgnoreCase) || ip.EndsWith(".255")) return "local broadcast/multicast";
        if (!IsPrivate(ip) && ptrPending.TryAdd(ip, 0)) _ = Ptr(ip);
        return null;
    }

    static async Task Ptr(string ip)
    {
        await ptrSem.WaitAsync();
        try
        {
            var t = Dns.GetHostEntryAsync(ip); _ = t.ContinueWith(x => _ = x.Exception, TaskContinuationOptions.OnlyOnFaulted);
            if (await Task.WhenAny(t, Task.Delay(2500)) == t && t.Status == TaskStatus.RanToCompletion && t.Result.HostName != ip) Names.TryAdd(ip, t.Result.HostName.ToLowerInvariant());
        }
        catch { }
        finally { ptrSem.Release(); }
    }

    public static string PortName(int port, string proto)
    {
        if (ports == null)
        {
            var m = new Dictionary<string, string>();
            try
            {
                using var s = Core.Res("services.txt.gz"); using var gz = new GZipStream(s, CompressionMode.Decompress); using var r = new StreamReader(gz);
                string l; while ((l = r.ReadLine()) != null) { if (l.StartsWith("#")) continue; var p = l.Split('\t'); if (p.Length == 2) m.TryAdd(p[1].Trim(), p[0].Trim()); }
            }
            catch (Exception ex) { Core.Log("services: " + ex.Message); }
            ports = m;
        }
        return ports.TryGetValue($"{port}/{proto.ToLowerInvariant()}", out var n) ? n : "";
    }

    static readonly (string match, string tag)[] Rules =
    {
        ("nflxvideo", "Netflix"), ("netflix", "Netflix"), ("nflxso", "Netflix"), ("nflxext", "Netflix"),
        ("googlevideo", "YouTube video"), ("youtube", "YouTube"), ("ytimg", "YouTube"), ("ggpht", "YouTube"),
        ("sponsor.ajay", "SponsorBlock"),
        ("logs.roku", "Roku telemetry"), ("scribe.logs.roku", "Roku telemetry"), ("cooper.logs.roku", "Roku telemetry"), ("ravm.tv", "Roku ads"), ("ads.roku", "Roku ads"), ("roku", "Roku"),
        ("lgtvsdp", "LG TV services"), ("lgsmartad", "LG ads"), ("lgad", "LG ads"), ("lge.com", "LG TV services"), ("alphonso", "TV tracking (Alphonso)"), ("samba.tv", "TV tracking (Samba)"),
        ("doubleclick", "Google ads"), ("googlesyndication", "Google ads"), ("googleadservices", "Google ads"), ("app-measurement", "Google analytics"),
        ("hulu", "Hulu"), ("disney", "Disney+"), ("dssott", "Disney+"), ("bamgrid", "Disney+"), ("hbo", "Max"), ("max.com", "Max"), ("aiv-cdn", "Prime Video"), ("primevideo", "Prime Video"), ("amazonvideo", "Prime Video"),
        ("pluto", "Pluto TV"), ("tubi", "Tubi"), ("peacock", "Peacock"), ("paramount", "Paramount+"), ("spotify", "Spotify"), ("pandora", "Pandora"), ("twitch", "Twitch"), ("ttvnw", "Twitch"),
        ("apple.com", "Apple"), ("icloud", "Apple iCloud"), ("microsoft", "Microsoft"), ("windowsupdate", "Windows Update"), ("xbox", "Xbox"), ("facebook", "Facebook"), ("fbcdn", "Facebook"), ("instagram", "Instagram"),
        ("tiktok", "TikTok"), ("x.com", "X"), ("twimg", "X"), ("akamai", "Akamai CDN"), ("cloudfront", "Amazon CDN"), ("amazonaws", "AWS"), ("fastly", "Fastly CDN"), ("cloudflare", "Cloudflare"), ("1e100.net", "Google"), ("google", "Google"),
    };

    public static string Tag(string host, string owner, int port, string proto)
    {
        var h = (host ?? "").ToLowerInvariant();
        foreach (var (m, t) in Rules) if (h.Contains(m)) return t;
        var o = (owner ?? "").ToLowerInvariant();
        if (o.Contains("netflix")) return "Netflix";
        if (o.Contains("roku")) return "Roku";
        if (o.Contains("google")) return "Google / YouTube";
        if (o.Contains("amazon")) return "Amazon";
        if (o.Contains("akamai")) return "Akamai CDN";
        if (o.Contains("microsoft")) return "Microsoft";
        if (o.Contains("facebook") || o.Contains("meta platforms")) return "Meta";
        if (o.Contains("cloudflare")) return "Cloudflare";
        if (o.Contains("apple")) return "Apple";
        return port switch { 53 => "DNS", 853 => "DNS-over-TLS", 123 => "Time (NTP)", 1900 => "SSDP discovery", 5353 => "mDNS", 67 or 68 => "DHCP", 8060 => "Roku ECP", 3000 or 3001 => "Local dashboard", _ => "" };
    }

    // ---- Blacklist ----
    static List<string> blCache; static int blHash;
    public static string Blacklisted(string ip, string host)
    {
        var list = AppSettings.Current.Blacklist; int h = string.Join("\n", list).GetHashCode();
        if (blCache == null || h != blHash) { blCache = list.Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("#")).ToList(); blHash = h; }
        foreach (var e in blCache)
        {
            if (e.Contains('/') && InCidr(ip, e)) return e;
            if (string.Equals(e, ip, StringComparison.OrdinalIgnoreCase)) return e;
            if (!string.IsNullOrEmpty(host) && !char.IsDigit(e[0]) && host.Contains(e, StringComparison.OrdinalIgnoreCase)) return e;
        }
        return null;
    }
    public static bool InCidr(string ip, string cidr)
    {
        try
        {
            var p = cidr.Split('/'); var net = IPAddress.Parse(p[0]).GetAddressBytes(); var a = IPAddress.Parse(ip).GetAddressBytes(); int bits = int.Parse(p[1]);
            if (net.Length != a.Length) return false;
            for (int i = 0; i < net.Length && bits > 0; i++, bits -= 8) { int mask = bits >= 8 ? 0xFF : 0xFF << (8 - bits) & 0xFF; if ((net[i] & mask) != (a[i] & mask)) return false; }
            return true;
        }
        catch { return false; }
    }
}
