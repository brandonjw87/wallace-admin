using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace WNH;

/// <summary>Active discovery helpers: TCP/UDP wake probes (so sleeping phones/cameras land in ARP), port profile,
/// NetBIOS + mDNS name lookups, SSDP/UPnP descriptions, HTTP Server banner, and device-type classification.</summary>
public static class Discovery
{
    // 62078 = iPhone/iPad lockdownd, 554/8554 = RTSP cameras, 80/8000/8080 = ONVIF/web cams, 8060 = Roku ECP, 8008/8009 = Chromecast,
    // 34567 = XMEye DVR/cam, 37777 = Dahua, 7000 = AirPlay, 1400 = Sonos, 9100/631 = printers, 445/139 = Windows/SMB, 22 = SSH, 8001/8002 = Samsung TV
    public static readonly int[] ProfilePorts = { 21, 22, 23, 53, 80, 139, 443, 445, 554, 631, 1400, 5000, 7000, 8000, 8001, 8002, 8008, 8009, 8060, 8080, 8443, 8554, 9000, 9100, 34567, 37777, 49152, 62078 };
    static readonly int[] WakePorts = { 62078, 554, 80, 443, 8000 };
    static readonly HttpClient http = new(new SocketsHttpHandler { ConnectTimeout = TimeSpan.FromSeconds(2) }) { Timeout = TimeSpan.FromSeconds(3) };
    static readonly ConcurrentDictionary<string, string> ssdp = new(); static DateTime ssdpAt;

    /// <returns>1 open, 0 refused (host is alive), -1 no answer.</returns>
    public static async Task<int> Tcp(string ip, int port, int ms)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        using var cts = new CancellationTokenSource(ms);
        try { await s.ConnectAsync(IPAddress.Parse(ip), port, cts.Token); return 1; }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionRefused) { return 0; }
        catch { return -1; }
    }

    /// <summary>Touch every silent address so Windows ARPs it; refused/open TCP also proves the host is alive.</summary>
    public static async Task WakeAsync(IEnumerable<string> ips, ConcurrentDictionary<string, bool> alive, CancellationToken ct)
    {
        using var sem = new SemaphoreSlim(512);
        using var udp = new UdpClient(); var nb = NbQuery();
        await Task.WhenAll(ips.Select(async ip =>
        {
            await sem.WaitAsync(ct);
            try
            {
                try { var ep = new IPEndPoint(IPAddress.Parse(ip), 137); udp.Send(nb, nb.Length, ep); var m = MdnsQuery(ip); udp.Send(m, m.Length, new IPEndPoint(ep.Address, 5353)); } catch { }
                var pingT = Task.Run(async () => { try { using var pg = new System.Net.NetworkInformation.Ping(); return (await pg.SendPingAsync(ip, 700)).Status == System.Net.NetworkInformation.IPStatus.Success; } catch { return false; } });
                var res = await Task.WhenAll(WakePorts.Select(p => Tcp(ip, p, 350)));
                if (res.Any(r => r >= 0) || await pingT) alive[ip] = true;
            }
            finally { sem.Release(); }
        }));
    }

    public static async Task ProfileAsync(Device d)
    {
        var nbT = NetBiosName(d.Ip); var mdT = MdnsName(d.Ip); // name lookups run in parallel with the port sweep
        var res = await Task.WhenAll(ProfilePorts.Select(async p => (p, r: await Tcp(d.Ip, p, 400))));
        d.Ports = res.Where(x => x.r == 1).Select(x => x.p).OrderBy(x => x).ToList();
        d.ProbedAt = DateTime.Now;
        var nbn = await nbT; if (!string.IsNullOrEmpty(nbn)) d.NbName = nbn;
        var md = await mdT; if (!string.IsNullOrEmpty(md)) d.MdnsName = md;
        foreach (var p in new[] { 80, 8000, 8080 }.Where(d.Ports.Contains).Take(1))
        {
            try
            {
                using var r = await http.GetAsync($"http://{d.Ip}:{p}/", HttpCompletionOption.ResponseContentRead);
                var server = r.Headers.Server?.ToString() ?? ""; var body = await r.Content.ReadAsStringAsync();
                if (body.Length > 20000) body = body[..20000];
                var title = Regex.Match(body, @"<title[^>]*>([^<]{1,80})</title>", RegexOptions.IgnoreCase).Groups[1].Value.Trim();
                var hint = string.Join(" ", new[] { server, title }.Where(x => x != "")); if (hint != "") d.WebInfo = hint;
            }
            catch { }
        }
    }

    // ---------- NetBIOS (UDP 137 NBSTAT) ----------
    static byte[] NbQuery()
    {
        var q = new List<byte> { 0x13, 0x37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, (byte)'C', (byte)'K' };
        for (int i = 0; i < 30; i++) q.Add((byte)'A');
        q.AddRange(new byte[] { 0, 0, 0x21, 0, 1 }); return q.ToArray();
    }
    public static async Task<string> NetBiosName(string ip)
    {
        try
        {
            using var u = new UdpClient(); u.Connect(IPAddress.Parse(ip), 137); var q = NbQuery(); await u.SendAsync(q, q.Length);
            var t = u.ReceiveAsync(); _ = t.ContinueWith(x => _ = x.Exception, TaskContinuationOptions.OnlyOnFaulted); /* 3.1.0: socket disposed on timeout -> observe, no log spam */ if (await Task.WhenAny(t, Task.Delay(900)) != t) return null;
            var b = t.Result.Buffer; if (b.Length < 57) return null; int n = b[56];
            for (int i = 0; i < n && 57 + i * 18 + 18 <= b.Length; i++)
            {
                int o = 57 + i * 18; int flags = (b[o + 16] << 8) | b[o + 17];
                if (b[o + 15] == 0 && (flags & 0x8000) == 0) return Encoding.ASCII.GetString(b, o, 15).Trim();
            }
        }
        catch { }
        return null;
    }

    // ---------- mDNS unicast reverse lookup (iPhones / Macs / many IoT answer with name.local) ----------
    static byte[] MdnsQuery(string ip)
    {
        var q = new List<byte> { 0x42, 0x42, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
        foreach (var lbl in ip.Split('.').Reverse().Concat(new[] { "in-addr", "arpa" })) { q.Add((byte)lbl.Length); q.AddRange(Encoding.ASCII.GetBytes(lbl)); }
        q.AddRange(new byte[] { 0, 0, 12, 0, 1 }); return q.ToArray();
    }
    public static async Task<string> MdnsName(string ip)
    {
        try
        {
            using var u = new UdpClient(); u.Connect(IPAddress.Parse(ip), 5353); var q = MdnsQuery(ip); await u.SendAsync(q, q.Length);
            var t = u.ReceiveAsync(); _ = t.ContinueWith(x => _ = x.Exception, TaskContinuationOptions.OnlyOnFaulted); /* 3.1.0: socket disposed on timeout -> observe, no log spam */ if (await Task.WhenAny(t, Task.Delay(1200)) != t) return null;
            var b = t.Result.Buffer; if (b.Length < 12) return null;
            int qd = (b[4] << 8) | b[5], an = (b[6] << 8) | b[7], o = 12;
            for (int i = 0; i < qd; i++) { ReadName(b, ref o); o += 4; }
            for (int i = 0; i < an && o + 10 <= b.Length; i++)
            {
                ReadName(b, ref o); int type = (b[o] << 8) | b[o + 1]; int len = (b[o + 8] << 8) | b[o + 9]; o += 10;
                if (type == 12) { int p = o; var name = ReadName(b, ref p); return name.Replace(".local", "").TrimEnd('.'); }
                o += len;
            }
        }
        catch { }
        return null;
    }
    static string ReadName(byte[] b, ref int o)
    {
        var parts = new List<string>(); int p = o; bool jumped = false; int guard = 0;
        while (p < b.Length && guard++ < 64)
        {
            int len = b[p];
            if (len == 0) { p++; break; }
            if ((len & 0xC0) == 0xC0) { int ptr = ((len & 0x3F) << 8) | b[p + 1]; if (!jumped) o = p + 2; jumped = true; p = ptr; continue; }
            parts.Add(Encoding.UTF8.GetString(b, p + 1, len)); p += len + 1;
        }
        if (!jumped) o = p;
        return string.Join(".", parts);
    }

    // ---------- SSDP / UPnP ----------
    public static async Task<IReadOnlyDictionary<string, string>> SsdpAsync(IEnumerable<string> localIps)
    {
        if (DateTime.Now - ssdpAt < TimeSpan.FromMinutes(10) && ssdp.Count > 0) return ssdp;
        ssdpAt = DateTime.Now;
        var loc = new ConcurrentDictionary<string, (string server, string location)>();
        var msg = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
        await Task.WhenAll(localIps.Where(i => i.StartsWith("192.168.1.") || i.StartsWith("192.168.137.")).Select(async lip =>
        {
            try
            {
                using var u = new UdpClient(new IPEndPoint(IPAddress.Parse(lip), 0));
                var ep = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 1900);
                await u.SendAsync(msg, msg.Length, ep); await Task.Delay(100); await u.SendAsync(msg, msg.Length, ep);
                var end = DateTime.Now.AddSeconds(3.5);
                while (DateTime.Now < end)
                {
                    var t = u.ReceiveAsync(); _ = t.ContinueWith(x => _ = x.Exception, TaskContinuationOptions.OnlyOnFaulted); /* 3.1.0: socket disposed on timeout -> observe, no log spam */ if (await Task.WhenAny(t, Task.Delay(end - DateTime.Now)) != t) break;
                    var s = Encoding.ASCII.GetString(t.Result.Buffer); var ip = t.Result.RemoteEndPoint.Address.ToString();
                    var server = Regex.Match(s, @"^SERVER:\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline).Groups[1].Value.Trim();
                    var location = Regex.Match(s, @"^LOCATION:\s*(.+)$", RegexOptions.IgnoreCase | RegexOptions.Multiline).Groups[1].Value.Trim();
                    loc.AddOrUpdate(ip, (server, location), (k, old) => (old.server == "" ? server : old.server, old.location == "" || old.location.Contains("dial", StringComparison.OrdinalIgnoreCase) ? location : old.location));
                }
            }
            catch { }
        }));
        await Task.WhenAll(loc.Select(async kv =>
        {
            string info = "";
            try
            {
                if (kv.Value.location.StartsWith("http"))
                {
                    var xml = await http.GetStringAsync(kv.Value.location);
                    string X(string tag) => Regex.Match(xml, $"<{tag}>([^<]{{1,80}})</{tag}>", RegexOptions.IgnoreCase).Groups[1].Value.Trim();
                    info = string.Join(" | ", new[] { X("friendlyName"), X("manufacturer"), X("modelName") }.Where(x => x != "").Distinct());
                }
            }
            catch { }
            if (info == "") info = kv.Value.server;
            if (info != "") ssdp[kv.Key] = WebUtility.HtmlDecode(info);
        }));
        return ssdp;
    }

    // ---------- classification ----------
    static bool Has(string s, params string[] keys) => keys.Any(k => s.Contains(k, StringComparison.OrdinalIgnoreCase));
    public static void Classify(Device d)
    {
        var ports = d.Ports ?? new List<int>(); bool P(params int[] p) => p.Any(ports.Contains);
        var v = d.Vendor ?? ""; var text = $"{d.Name} {d.HostName} {d.NbName} {d.MdnsName} {d.Upnp} {d.WebInfo}";
        bool priv = v.StartsWith("Private");
        string t;
        if (d.Ip == "192.0.2.15" || d.Ip == "192.0.2.11") t = "Router";
        else if (Devices.KnownNames().ContainsKey(d.Mac ?? "")) t = Has(d.Name ?? "", "TV") ? "TV (Roku)" : "Roku";
        else if (Has(text + " " + v, "camera", "ipcam", "ip cam", "hikvision", "dahua", "reolink", "amcrest", "wyze", "arlo", "blink", "eufy", "tapo c", "imou", "foscam", "ezviz", "lorex", "annke", "xmeye", "uc-httpd", "swann", "netcam", "nvr", "dvr", "onvif", "vstarcam", "hangzhou", "ring llc", "ubiquiti protect", "zmodo", "yi technology", "geovision", "axis comm", "hanwha", "vivotek", "uniview")
                 || P(554, 8554, 34567, 37777)) t = "Camera";
        else if (P(62078) || Has(text, "iphone", "ipad")) t = priv ? "Phone (private address)" : "iPhone/iPad";
        else if (Has(text, "android", "galaxy", "pixel", "phone", "moto ", "oneplus", "redmi")) t = priv ? "Phone (private address)" : "Phone";
        else if (P(8060) || Has(v + text, "roku")) t = "Roku";
        else if (P(8001, 8002) || Has(text, " tv", "tv ", "television", "bravia", "webos", "vizio", "smartcast", "tizen") || Has(v, "LG Electronics", "TCL", "Hisense", "Vizio", "Sony", "Funai", "TP Vision", "Shenzhen TCL")) t = "TV";
        else if (P(8008, 8009) || Has(text + v, "chromecast", "google home", "nest")) t = "Google/Chromecast";
        else if (Has(text + v, "echo", "alexa", "amazon", "kindle", "fire tv")) t = "Amazon Echo/Fire";
        else if (P(1400) || Has(text + v, "sonos")) t = "Speaker (Sonos)";
        else if (P(9100, 631) || Has(text + v, "printer", "epson", "brother", "canon", "hewlett", "hp ", "laserjet", "officejet", "deskjet")) t = "Printer";
        else if (Has(text + v, "xbox", "playstation", "nintendo", "sony interactive")) t = "Game console";
        else if (Has(v + text, "Espressif", "Tuya", "Leedarson", "Gaoshengda", "Ezurio", "Ecobee", "Wemo", "Belkin", "Kasa", "TP-Link", "Lutron", "Philips Lighting", "Signify", "Chamberlain", "MyQ", "Govee", "iRobot", "Texas Instruments", "Silicon Labs", "Murata", "Universal Global Scientific", "Seeed", "Wisol", "Shenzhen", "SmartThings", "Hubitat"))
            t = "Smart-home / IoT";
        else if (P(445, 139) || Has(text + v, "windows", "desktop-", "laptop-", "macbook", "imac", "Micro-Star", "Intel Corporate", "Dell", "Lenovo", "ASUSTek", "Liteon", "AzureWave", "Hon Hai", "Raspberry")) t = "Computer";
        else if (Has(v, "Apple")) t = P(7000) ? "Apple TV / Mac" : "Apple device (phone/tablet?)";
        else if (Has(v, "Samsung", "Motorola", "OnePlus", "Xiaomi", "Huawei", "OPPO", "vivo", "Google", "Nothing Technology", "HMD", "ZTE", "TCT mobile")) t = "Phone";
        else if (priv && !P(80, 443, 8000, 8080, 8443, 445, 22, 9000, 5000)) t = "Phone (private address)";
        else t = priv ? "Unknown (private MAC)" : "Unknown";
        d.Type = t;
    }
}
