using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace WNH;

public class Conn
{
    public string DeviceMac, Adapter, Remote, Proto; public int Port;
    public long Up, Down, Packets; public DateTime First, Last;
    public string Host, Owner, Country, Service, PortName;
}

public class DevTraffic { public string Mac, Adapter; public long Up, Down, PrevUp, PrevDown; public double RateUp, RateDown; public DateTime Last; }

/// <summary>Live packet capture on Npcap (idea and parsing approach ported from Sniffnet's capture/parse_packets).
/// Everything here is isolated so that a missing Npcap can never crash the app.</summary>
public static class Capture
{
    public static string Status { get; private set; } = "not started";
    public static bool Running { get; private set; }
    public static volatile bool Paused;
    public static long Packets, Bytes;
    public static readonly object Gate = new();
    public static readonly Dictionary<string, Conn> Conns = new();
    public static readonly Dictionary<string, DevTraffic> Devs = new();
    static Timer rateTimer;
    static DateTime lastNewHostToast = DateTime.MinValue;

    public static void Start()
    {
        if (Running) return;
        if (!NpcapInfo.Installed) { Status = "Npcap is not installed"; return; }
        try { Status = CaptureImpl.Start(); Running = Status.StartsWith("Capturing"); }
        catch (Exception ex) { Status = "capture failed: " + ex.Message; Core.Log("capture start: " + ex); }
        rateTimer ??= new Timer(_ => Rates(), null, 1000, 1000);
    }
    public static void Stop() { try { CaptureImpl.Stop(); } catch { } Running = false; Status = "stopped"; }

    static void Rates()
    {
        lock (Gate)
            foreach (var d in Devs.Values) { d.RateUp = d.Up - d.PrevUp; d.RateDown = d.Down - d.PrevDown; d.PrevUp = d.Up; d.PrevDown = d.Down; }
    }

    public static bool SeenRecently(string mac, TimeSpan within) { lock (Gate) return Devs.TryGetValue(mac, out var d) && DateTime.Now - d.Last < within; }

    public static void Clear() { lock (Gate) { Conns.Clear(); Devs.Clear(); Packets = Bytes = 0; } }

    // Called on capture threads.
    internal static void OnFrame(ReadOnlySpan<byte> f, int wireLen, bool ethernet, string adapter, byte[] myMac, bool hotspot)
    {
        if (Paused) return;
        try
        {
            int off = 0; byte[] srcMac = null, dstMac = null; int etype;
            if (ethernet)
            {
                if (f.Length < 14) return;
                dstMac = f[..6].ToArray(); srcMac = f.Slice(6, 6).ToArray(); etype = f[12] << 8 | f[13]; off = 14;
                if (etype == 0x8100 && f.Length >= 18) { etype = f[16] << 8 | f[17]; off = 18; }
            }
            else etype = f.Length > 0 && f[0] >> 4 == 6 ? 0x86DD : 0x0800;

            string src, dst; int proto, l4;
            if (etype == 0x0800)
            {
                if (f.Length < off + 20) return; int ihl = (f[off] & 0x0F) * 4; proto = f[off + 9];
                src = new IPAddress(f.Slice(off + 12, 4)).ToString(); dst = new IPAddress(f.Slice(off + 16, 4)).ToString(); l4 = off + ihl;
            }
            else if (etype == 0x86DD)
            {
                if (f.Length < off + 40) return; proto = f[off + 6];
                src = new IPAddress(f.Slice(off + 8, 16)).ToString(); dst = new IPAddress(f.Slice(off + 24, 16)).ToString(); l4 = off + 40;
            }
            else return;
            int sp = 0, dp = 0; string p = proto switch { 6 => "TCP", 17 => "UDP", 1 => "ICMP", 58 => "ICMPv6", 2 => "IGMP", _ => "IP" + proto };
            if ((proto == 6 || proto == 17) && f.Length >= l4 + 4) { sp = f[l4] << 8 | f[l4 + 1]; dp = f[l4 + 2] << 8 | f[l4 + 3]; }

            // Direction: which side is "the device"?
            bool up; string devKey, remote; int rport;
            if (hotspot && srcMac != null && myMac != null)
            {
                bool fromMe = srcMac.AsSpan().SequenceEqual(myMac);
                if (fromMe && (dstMac[0] & 1) == 1) return; // PC's own broadcasts
                up = !fromMe; devKey = Mac(fromMe ? dstMac : srcMac); remote = fromMe ? src : dst; rport = fromMe ? sp : dp;
                if ((dstMac[0] & 1) == 1 && !fromMe) remote = dst; // broadcast/multicast from device
            }
            else
            {
                bool fromMe = srcMac != null && myMac != null ? srcMac.AsSpan().SequenceEqual(myMac) : Devices.LocalIps().Contains(src);
                up = fromMe; devKey = "THIS-PC"; remote = fromMe ? dst : src; rport = fromMe ? dp : sp;
            }

            // Learn names: DNS answers (UDP 53) and TLS SNI (TCP 443 ClientHello)
            if (proto == 17 && sp == 53 && f.Length > l4 + 8) Dns(f[(l4 + 8)..]);
            string sni = null;
            if (proto == 6 && dp == 443 && f.Length > l4 + 20) { int doff = (f[l4 + 12] >> 4) * 4; if (f.Length > l4 + doff + 5) sni = Sni(f[(l4 + doff)..]); if (sni != null) Intel.Learn(dst, sni); }

            Interlocked.Increment(ref Packets); Interlocked.Add(ref Bytes, wireLen);
            string key = $"{devKey}|{remote}|{rport}|{p}";
            bool isNew = false; Conn c;
            lock (Gate)
            {
                if (!Devs.TryGetValue(devKey, out var dt)) Devs[devKey] = dt = new DevTraffic { Mac = devKey, Adapter = adapter };
                if (up) dt.Up += wireLen; else dt.Down += wireLen;
                if (up) dt.Last = DateTime.Now;
                if (!Conns.TryGetValue(key, out c))
                {
                    if (Conns.Count >= 6000) Prune();
                    Conns[key] = c = new Conn { DeviceMac = devKey, Adapter = adapter, Remote = remote, Port = rport, Proto = p, First = DateTime.Now };
                    isNew = true;
                }
                if (up) c.Up += wireLen; else c.Down += wireLen;
                c.Packets++; c.Last = DateTime.Now;
            }
            if (isNew) OnNewConn(c);
        }
        catch (Exception ex) { Core.Log("frame: " + ex.Message); }
    }

    static void Prune()
    {
        foreach (var k in Conns.OrderBy(kv => kv.Value.Last).Take(1000).Select(kv => kv.Key).ToList()) Conns.Remove(k);
    }

    static string Mac(byte[] b) => b == null ? "?" : string.Join(":", b.Select(x => x.ToString("X2")));

    static void OnNewConn(Conn c)
    {
        Task.Run(() =>
        {
            try
            {
                Enrich(c);
                var bl = Intel.Blacklisted(c.Remote, c.Host);
                if (bl != null && AppSettings.Current.AlertBlacklist)
                    Alerts.Raise($"bl-{c.DeviceMac}-{c.Remote}", "red", "Blacklisted host contacted", $"{DeviceName(c.DeviceMac)} → {c.Host ?? c.Remote}:{c.Port} (rule: {bl})", 60);
                if (AppSettings.Current.AlertNewHost && !Intel.IsPrivate(c.Remote) && DateTime.Now - lastNewHostToast > TimeSpan.FromSeconds(30))
                {
                    lastNewHostToast = DateTime.Now;
                    Alerts.Raise($"nh-{c.DeviceMac}-{c.Host ?? c.Remote}", "blue", "New host contacted", $"{DeviceName(c.DeviceMac)} → {c.Host ?? c.Remote} ({c.Service})", 1440);
                }
            }
            catch (Exception ex) { Core.Log("newconn: " + ex.Message); }
        });
    }

    public static void Enrich(Conn c)
    {
        c.Host ??= Intel.NameOf(c.Remote);
        if (c.Owner == null) { var (a, co) = Intel.Owner(c.Remote); c.Owner = a; c.Country = co; }
        c.PortName = c.Port > 0 ? Intel.PortName(c.Port, c.Proto) : "";
        c.Service = Intel.Tag(c.Host, c.Owner, c.Port, c.Proto);
    }

    public static string DeviceName(string mac)
    {
        if (mac == "THIS-PC") return "This PC (MSI)";
        if (Devices.All.TryGetValue(mac, out var d)) return d.Display + " (" + d.Ip + ")";
        return Devices.NameFor(mac, null) ?? Oui.Lookup(mac) + " " + mac;
    }

    // ---------- tiny DNS response parser ----------
    static void Dns(ReadOnlySpan<byte> m)
    {
        if (m.Length < 12 || (m[2] & 0x80) == 0) return;
        int qd = m[4] << 8 | m[5], an = m[6] << 8 | m[7]; int i = 12; string qname = null;
        for (int q = 0; q < qd; q++) { var n = ReadName(m, ref i); qname ??= n; i += 4; if (i > m.Length) return; }
        for (int a = 0; a < an && i + 10 <= m.Length; a++)
        {
            ReadName(m, ref i); if (i + 10 > m.Length) return;
            int type = m[i] << 8 | m[i + 1]; int len = m[i + 8] << 8 | m[i + 9]; i += 10; if (i + len > m.Length) return;
            if (qname != null && (type == 1 && len == 4 || type == 28 && len == 16)) Intel.Learn(new IPAddress(m.Slice(i, len)).ToString(), qname);
            i += len;
        }
    }
    static string ReadName(ReadOnlySpan<byte> m, ref int i)
    {
        var sb = new StringBuilder(); int pos = i; bool jumped = false; int guard = 0;
        while (pos < m.Length && guard++ < 64)
        {
            int l = m[pos];
            if (l == 0) { pos++; break; }
            if ((l & 0xC0) == 0xC0) { if (pos + 1 >= m.Length) break; if (!jumped) i = pos + 2; jumped = true; pos = (l & 0x3F) << 8 | m[pos + 1]; continue; }
            if (pos + 1 + l > m.Length) break;
            if (sb.Length > 0) sb.Append('.'); sb.Append(Encoding.ASCII.GetString(m.Slice(pos + 1, l))); pos += l + 1;
        }
        if (!jumped) i = pos;
        return sb.ToString();
    }

    // ---------- TLS ClientHello SNI ----------
    static string Sni(ReadOnlySpan<byte> t)
    {
        if (t.Length < 43 || t[0] != 0x16 || t[5] != 0x01) return null;
        int i = 43; if (i >= t.Length) return null;
        i += 1 + t[i]; // session id
        if (i + 2 > t.Length) return null; i += 2 + (t[i] << 8 | t[i + 1]); // cipher suites
        if (i + 1 > t.Length) return null; i += 1 + t[i];                   // compression
        if (i + 2 > t.Length) return null; int end = Math.Min(t.Length, i + 2 + (t[i] << 8 | t[i + 1])); i += 2;
        while (i + 4 <= end)
        {
            int type = t[i] << 8 | t[i + 1], len = t[i + 2] << 8 | t[i + 3]; i += 4;
            if (type == 0 && i + 5 <= end) { int nl = t[i + 3] << 8 | t[i + 4]; if (i + 5 + nl <= t.Length) return Encoding.ASCII.GetString(t.Slice(i + 5, nl)).ToLowerInvariant(); return null; }
            i += len;
        }
        return null;
    }
}

/// <summary>All SharpPcap usage lives here; never JIT-ed unless Npcap's wpcap.dll exists.</summary>
static class CaptureImpl
{
    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetDllDirectory(string path);
    static readonly List<SharpPcap.LibPcap.LibPcapLiveDevice> open = new();

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static string Start()
    {
        SetDllDirectory(NpcapInfo.Dir);
        var list = SharpPcap.LibPcap.LibPcapLiveDeviceList.Instance;
        var names = new List<string>();
        var nics = NetworkInterface.GetAllNetworkInterfaces();
        foreach (var dev in list)
        {
            var ips = dev.Addresses.Where(a => a.Addr?.ipAddress != null).Select(a => a.Addr.ipAddress.ToString()).ToList();
            var nic = nics.FirstOrDefault(n => dev.Name.Contains(n.Id, StringComparison.OrdinalIgnoreCase));
            if (nic != null) ips.AddRange(nic.GetIPProperties().UnicastAddresses.Select(u => u.Address.ToString()));
            bool hotspot = ips.Contains("192.0.2.11");
            bool eth = AppSettings.Current.CaptureEthernetToo && !hotspot && nic != null && nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet && ips.Any(x => x.StartsWith("192.168.1."));
            if (!hotspot && !eth) continue;
            string label = hotspot ? "Hotspot" : "Ethernet";
            byte[] mac = dev.MacAddress?.GetAddressBytes();
            if ((mac == null || mac.Length != 6) && nic != null) mac = nic.GetPhysicalAddress().GetAddressBytes();
            dev.Open(new SharpPcap.DeviceConfiguration { Mode = SharpPcap.DeviceModes.None, ReadTimeout = 500, Snaplen = 1600 });
            bool ethernet = dev.LinkType == PacketDotNet.LinkLayers.Ethernet;
            dev.OnPacketArrival += (s, e) => { var raw = e.GetPacket(); Capture.OnFrame(raw.Data, raw.PacketLength, ethernet, label, mac, hotspot); };
            dev.StartCapture(); open.Add(dev); names.Add($"{label} ({dev.Description})");
        }
        if (names.Count == 0) return "No hotspot adapter (192.0.2.11) found by Npcap — is the hotspot on?";
        return "Capturing on " + string.Join(", ", names);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void Stop()
    {
        foreach (var d in open) { try { d.StopCapture(); d.Close(); } catch { } }
        open.Clear();
    }
}
