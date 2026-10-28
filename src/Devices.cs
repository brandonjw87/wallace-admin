using System.Collections.Concurrent;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace WNH;

public class StateChange { public DateTime T { get; set; } public bool Up { get; set; } }

public class Device
{
    public string Mac { get; set; }
    public string Ip { get; set; }
    public string Network { get; set; }   // "Hotspot" or "Home LAN"
    public string Name { get; set; }
    public string Vendor { get; set; }
    public string HostName { get; set; }
    public bool Online { get; set; }
    public double LatencyMs { get; set; } = -1;
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public List<StateChange> History { get; set; } = new();
    public long BytesUp { get; set; }
    public long BytesDown { get; set; }
    public string Type { get; set; }
    public List<int> Ports { get; set; }
    public DateTime ProbedAt { get; set; }
    public string NbName { get; set; }
    public string MdnsName { get; set; }
    public string Upnp { get; set; }
    public string WebInfo { get; set; }
    public string PortsText => Ports == null ? "" : string.Join(",", Ports);
    public string VendorType => string.IsNullOrEmpty(Type) ? Vendor : $"{Vendor} · {Type}";
    public string Display => !string.IsNullOrEmpty(Name) ? Name : !string.IsNullOrEmpty(HostName) ? HostName : !string.IsNullOrEmpty(MdnsName) ? MdnsName : !string.IsNullOrEmpty(NbName) ? NbName : !string.IsNullOrEmpty(Upnp) ? Upnp.Split('|')[0].Trim() : !string.IsNullOrEmpty(Type) && !Type.StartsWith("Unknown") ? $"{Type} ({Vendor})" : $"{Vendor} device";
    public string Status => Online ? "Online" : "Offline";
    public string LastSeenText => LastSeen == default ? "" : LastSeen.ToString("MMM d h:mm tt");
    public string LatencyText => Online && LatencyMs >= 0 ? $"{LatencyMs:0} ms" : "";
    public string UsageText => BytesUp + BytesDown == 0 ? "" : $"↑ {Core.Bytes(BytesUp)}  ↓ {Core.Bytes(BytesDown)}";
    public double UptimePct(TimeSpan span)
    {
        var from = DateTime.Now - span; if (History.Count == 0) return Online ? 100 : 0;
        double up = 0; bool state = false; DateTime cur = from;
        foreach (var h in History) { if (h.T <= from) { state = h.Up; continue; } if (state) up += (h.T - cur).TotalSeconds; cur = h.T; state = h.Up; }
        if (state) up += (DateTime.Now - cur).TotalSeconds;
        return Math.Clamp(up / span.TotalSeconds * 100, 0, 100);
    }
}

public static class Oui
{
    static Dictionary<string, string> map; static readonly object gate = new();
    public static int Count { get { Ensure(); return map.Count; } }
    static void Ensure()
    {
        if (map != null) return;
        lock (gate)
        {
            if (map != null) return;
            var m = new Dictionary<string, string>(45000, StringComparer.OrdinalIgnoreCase);
            try
            {
                using var s = Core.Res("oui.tsv.gz"); using var gz = new GZipStream(s, CompressionMode.Decompress); using var r = new StreamReader(gz);
                string line; while ((line = r.ReadLine()) != null) { int t = line.IndexOf('\t'); if (t == 6) m.TryAdd(line[..6], line[7..].Trim()); }
            }
            catch (Exception ex) { Core.Log("oui load: " + ex.Message); }
            map = m;
        }
    }
    public static string Lookup(string mac)
    {
        if (string.IsNullOrEmpty(mac)) return "Unknown";
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant(); if (hex.Length < 6) return "Unknown";
        Ensure();
        if (map.TryGetValue(hex[..6], out var v)) return Shorten(v);
        if ((Convert.ToInt32(hex.Substring(0, 2), 16) & 0x02) != 0) return "Private (randomized) MAC";
        return "Unknown vendor";
    }
    static string Shorten(string v)
    {
        foreach (var suf in new[] { ", Inc.", " Inc.", " Co., Ltd.", " Co.,Ltd.", " Corporation", " Corp.", " Limited", " LLC", " Ltd." }) if (v.EndsWith(suf, StringComparison.OrdinalIgnoreCase)) return v[..^suf.Length];
        return v;
    }
}

/// <summary>Device discovery: ping sweep + ARP table for the hotspot (192.0.2.19/24) and the home LAN (192.0.2.20/24).</summary>
public static class Devices
{
    public static readonly ConcurrentDictionary<string, Device> All = new(StringComparer.OrdinalIgnoreCase); // by MAC
    public static event Action Updated;
    public static DateTime LastScan; public static TimeSpan LastScanTook; public static string LastError;
    static int scanning; static CancellationTokenSource loop;
    public static DateTime LastFullScan, NextScan; public static string LastScanKind = ""; public static bool IsScanning => Volatile.Read(ref scanning) == 1; static Dictionary<string, string> knownNames;

    public static void Start()
    {
        foreach (var d in JsonStore.Load<List<Device>>("devices.json")) { d.Online = false; if (d.Mac != null) All[d.Mac] = d; }
        Dedupe(true);
        if (loop != null) return; loop = new CancellationTokenSource();
        _ = Task.Run(async () =>
        {
            await Task.Delay(1500);
            while (!loop.IsCancellationRequested)
            {
                var s = AppSettings.Current;
                bool full = LastFullScan == default || DateTime.Now - LastFullScan >= TimeSpan.FromMinutes(Math.Max(1, s.FullScanMinutes));
                if (s.AutoRefresh || LastScan == default) { try { await ScanAsync(default, full); } catch { } }
                NextScan = DateTime.Now.AddSeconds(Math.Max(10, s.QuickRefreshSeconds));
                try { await Task.Delay(TimeSpan.FromSeconds(Math.Max(10, s.QuickRefreshSeconds)), loop.Token); } catch { }
            }
        });
    }

    public static Dictionary<string, string> KnownNames()
    {
        if (knownNames != null) return knownNames;
        var k = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var f = Path.Combine(Core.Tools, @"roku-dhcp\roku-macs.txt");
            if (File.Exists(f)) foreach (var l in File.ReadAllLines(f))
            {
                if (l.TrimStart().StartsWith("#") || !l.Contains(',')) continue;
                var p = l.Split(','); if (p.Length >= 3 && p[0].Trim().Length >= 12) k[NormMac(p[0])] = p[2].Trim();
            }
        }
        catch (Exception ex) { Core.Log("roku-macs: " + ex.Message); }
        return knownNames = k;
    }
    /// <summary>Resolve "mac:AA:BB:CC:DD:EE:FF[:port]" to the current IP (scan cache, then ARP). Plain targets pass through. Null = not seen.</summary>
    public static string ResolveTarget(string t)
    {
        if (string.IsNullOrWhiteSpace(t) || !t.StartsWith("mac:", StringComparison.OrdinalIgnoreCase)) return t;
        var body = t[4..]; string port = null;
        var parts = body.Split(new[] { ':', '-' }); if (parts.Length == 7) { port = parts[6]; body = string.Join(":", parts.Take(6)); }
        var mac = NormMac(body); string ip = null;
        if (All.TryGetValue(mac, out var d) && !string.IsNullOrEmpty(d.Ip)) ip = d.Ip;
        if (ip == null) try { ip = ReadArp().Where(a => NormMac(a.mac) == mac).Select(a => a.ip).FirstOrDefault(); } catch { }
        return ip == null ? null : (port == null ? ip : ip + ":" + port);
    }
    public static string NormMac(string m) => string.Join(":", Enumerable.Range(0, 6).Select(i => new string(m.Where(Uri.IsHexDigit).ToArray()).ToUpperInvariant().PadRight(12, '0').Substring(i * 2, 2)));

    public static string NameFor(string mac, string ip)
    {
        if (AppSettings.Current.DeviceNames.TryGetValue(mac, out var n) && !string.IsNullOrWhiteSpace(n)) return n;
        if (KnownNames().TryGetValue(mac, out n)) return n;
        if (mac == "00:00:5E:00:53:03") return "LG TV";
        if (ip == "192.0.2.15") return "Spectrum router";
        return null;
    }

    public static async Task<int> ScanAsync(CancellationToken ct = default, bool full = true)
    {
        if (Interlocked.Exchange(ref scanning, 1) == 1) return -1;
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var mine = LocalIps();
            var targets = new List<string>();
            foreach (var prefix in new[] { "192.168.137.", "192.168.1." })
                if (mine.Any(m => m.StartsWith(prefix))) for (int i = 1; i < 255; i++) { var ip = prefix + i; if (!mine.Contains(ip)) targets.Add(ip); }
            // FAST PATH: read the ARP table first; quick refresh only pings known/ARP addresses, full rescan sweeps
            // everything with ping + wake probes + SSDP all running in parallel (high concurrency, short timeouts).
            var arpFirst = ReadArp(); var arpDyn = arpFirst.Where(a => a.dynamic).Select(a => a.ip).ToHashSet();
            var knownIps = All.Values.Where(x => x.Ip != null).Select(x => x.Ip).ToHashSet();
            var pingSet = full ? targets : targets.Where(ip => knownIps.Contains(ip) || arpDyn.Contains(ip)).ToList();
            var lat = new ConcurrentDictionary<string, double>();
            var alive = new ConcurrentDictionary<string, bool>();
            var ssdpTask = full ? Task.Run(async () => { try { return await Discovery.SsdpAsync(mine); } catch (Exception ex) { Core.Log("ssdp: " + ex.Message); return null; } }) : Task.FromResult<IReadOnlyDictionary<string, string>>(null);
            using var sem = new SemaphoreSlim(256);
            var pingTask = Task.WhenAll(pingSet.Select(async ip =>
            {
                await sem.WaitAsync(ct);
                try { using var p = new Ping(); var r = await p.SendPingAsync(ip, 600); if (r.Status == IPStatus.Success) lat[ip] = r.RoundtripTime; }
                catch { }
                finally { sem.Release(); }
            }));
            var wakeTask = full ? Discovery.WakeAsync(targets.Where(ip => !arpDyn.Contains(ip)), alive, ct) : Task.CompletedTask;
            await Task.WhenAll(pingTask, wakeTask);
            // Wake pass: silent addresses get TCP (62078 iPhone, 554 RTSP, 80/443/8000 web/ONVIF) + NetBIOS/mDNS UDP so they
            // ARP-resolve even when they ignore ping (sleeping phones, cameras with ICMP off).
            await Task.Delay(full ? 500 : 150, ct);
            var arp = ReadArp();
            var now = DateTime.Now; var seenMacs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var (ip, mac, dynamic) in arp)
            {
                if (!(ip.StartsWith("192.168.137.") || ip.StartsWith("192.168.1.")) || mine.Contains(ip)) continue;
                if (ip.EndsWith(".255")) continue;
                bool isNew = !All.TryGetValue(mac, out var d);
                // Windows ICS keeps STATIC ARP entries for old hotspot leases, so a static entry alone does not mean "online".
                bool isAlive = lat.ContainsKey(ip) || alive.ContainsKey(ip) || dynamic || Capture.SeenRecently(mac, TimeSpan.FromMinutes(Math.Max(1, AppSettings.Current.OfflineMinutes)));
                // 3.1.0 duplicate fix: never create a device from a dead ARP entry. ICS leaves STATIC entries for every old lease, and phones
                // with randomized MACs leave a new one per reconnect, which used to appear as offline duplicates of the same phone/IP.
                if (!isAlive) continue;
                seenMacs.Add(mac);
                if (isNew) d = new Device { Mac = mac, FirstSeen = now };
                d.Ip = ip; d.Network = ip.StartsWith("192.168.137.") ? "Hotspot" : "Home LAN";
                d.Vendor = Oui.Lookup(mac); d.Name = NameFor(mac, ip) ?? d.Name;
                d.LatencyMs = lat.TryGetValue(ip, out var ms) ? ms : -1;
                d.LastSeen = now;
                if (!d.Online) { d.Online = true; d.History.Add(new StateChange { T = now, Up = true }); if (!isNew && LastScan != default) Alerts.Raise("up-" + mac, "green", $"{d.Display} is back online", $"{ip} on {d.Network}", 30); }
                if (isNew)
                {
                    All[mac] = d;
                    if (AppSettings.Current.AlertNewDevice && LastScan != default) Alerts.Raise("new-" + mac, "blue", "New device joined " + d.Network, $"{d.Display} — {ip} [{mac}] {d.Vendor}", 1440);
                }
                if (d.HostName == null) _ = ResolveName(d);
            }
            Updated?.Invoke(); // incremental UI: show online devices before slow profiling
            // Profile (ports, NetBIOS, mDNS, web banner) new/stale devices, merge SSDP, then classify everything.
            var toProfile = All.Values.Where(x => seenMacs.Contains(x.Mac) && (x.Ports == null || (full && now - x.ProbedAt > TimeSpan.FromHours(6)))).ToList();
            using (var psem = new SemaphoreSlim(48))
                await Task.WhenAll(toProfile.Select(async x => { await psem.WaitAsync(ct); try { await Discovery.ProfileAsync(x); Discovery.Classify(x); Updated?.Invoke(); } catch { } finally { psem.Release(); } }));
            try
            {
                var up = await ssdpTask;
                if (up != null) foreach (var x in All.Values) if (x.Ip != null && seenMacs.Contains(x.Mac) && up.TryGetValue(x.Ip, out var info)) x.Upnp = info;
            }
            catch (Exception ex) { Core.Log("ssdp: " + ex.Message); }
            foreach (var x in All.Values) { x.Vendor = Oui.Lookup(x.Mac); Discovery.Classify(x); }
            foreach (var d in All.Values.Where(x => x.Online && !seenMacs.Contains(x.Mac)))
                if (now - d.LastSeen > TimeSpan.FromMinutes(Math.Max(1, AppSettings.Current.OfflineMinutes)))
                {
                    d.Online = false; d.History.Add(new StateChange { T = now, Up = false });
                    if (AppSettings.Current.AlertDeviceOffline) Alerts.Raise("down-" + d.Mac, "red", $"{d.Display} went offline", $"last seen {d.LastSeen:t} at {d.Ip}", 30);
                }
            foreach (var d in All.Values) if (d.History.Count > 400) d.History.RemoveRange(0, d.History.Count - 400);
            LastScan = now; LastScanTook = sw.Elapsed; LastScanKind = full ? "full" : "quick"; if (full) LastFullScan = now; LastError = null;
            Dedupe(false);
            JsonStore.Save("devices.json", All.Values.ToList());
            Updated?.Invoke();
            return seenMacs.Count;
        }
        catch (Exception ex) { LastError = ex.Message; Core.Log("scan: " + ex); return -1; }
        finally { Volatile.Write(ref scanning, 0); }
    }

    public static bool Randomized(string mac) { var h = new string((mac ?? "").Where(Uri.IsHexDigit).ToArray()); return h.Length >= 2 && (Convert.ToInt32(h[..2], 16) & 0x02) != 0; }
    static string Key(Device d) => (d.HostName ?? "").Trim().ToLowerInvariant() is { Length: > 0 } h ? h : (d.Name ?? "").Trim().ToLowerInvariant();

    /// <summary>Merge duplicates in the device cache. Rules: (1) MAC is the identity; (2) an offline entry sharing an IP with a newer entry is merged
    /// when it was never seen alive, has a randomized MAC, or has the same name; (3) randomized-MAC entries with the same host name collapse into
    /// the most recent; (4) optional prune of offline > PruneDays (named/Roku devices kept). devices.json is backed up once a day before changes.</summary>
    public static int Dedupe(bool saveNow)
    {
        var list = All.Values.ToList(); var drop = new HashSet<string>(StringComparer.OrdinalIgnoreCase); var named = AppSettings.Current.DeviceNames; var roku = KnownNames();
        foreach (var d in list) if (string.IsNullOrEmpty(d.Mac) || d.Mac.Length != 17) drop.Add(d.Mac ?? "");
        foreach (var g in list.Where(d => !string.IsNullOrEmpty(d.Ip)).GroupBy(d => d.Ip))
        {
            var keep = g.OrderByDescending(d => d.Online).ThenByDescending(d => d.LastSeen).First();
            foreach (var o in g.Where(o => o != keep && !o.Online))
                if (o.LastSeen == default || Randomized(o.Mac) || (Key(o) != "" && Key(o) == Key(keep))) { drop.Add(o.Mac); keep.Name ??= o.Name; if (keep.FirstSeen > o.FirstSeen && o.FirstSeen != default) keep.FirstSeen = o.FirstSeen; }
        }
        foreach (var g in list.Where(d => Randomized(d.Mac) && Key(d) != "" && !drop.Contains(d.Mac)).GroupBy(Key))
            foreach (var o in g.OrderByDescending(d => d.Online).ThenByDescending(d => d.LastSeen).Skip(1)) if (!o.Online) drop.Add(o.Mac);
        if (AppSettings.Current.PruneStale)
            foreach (var d in list) if (!d.Online && d.LastSeen != default && DateTime.Now - d.LastSeen > TimeSpan.FromDays(Math.Max(1, AppSettings.Current.PruneDays)) && !named.ContainsKey(d.Mac ?? "") && !roku.ContainsKey(d.Mac ?? "")) drop.Add(d.Mac);
        drop.Remove("");
        if (drop.Count == 0) return 0;
        try { var p = Path.Combine(Core.DataDir, "devices.json"); var bak = Path.Combine(Core.DataDir, $"devices.json.bak-{DateTime.Now:yyyyMMdd}"); if (File.Exists(p) && !File.Exists(bak)) File.Copy(p, bak); } catch { }
        foreach (var m in drop) All.TryRemove(m, out _);
        Core.Log($"devices: merged/pruned {drop.Count} duplicate or stale entries");
        if (saveNow) { JsonStore.Save("devices.json", All.Values.ToList()); Updated?.Invoke(); }
        return drop.Count;
    }

    /// <summary>One row per real device for the Safe Guard / Admin pages: scanner devices plus AdGuard persistent clients, matched by any MAC in the
    /// client's ids first, then by IP (the old IP-only match showed a Roku twice when its hotspot lease changed).</summary>
    public static List<Device> Merged(System.Text.Json.Nodes.JsonArray clients)
    {
        var devs = All.Values.Where(d => !string.IsNullOrEmpty(d.Ip)).ToList();
        foreach (var c in clients ?? new System.Text.Json.Nodes.JsonArray())
        {
            var ids = c["ids"].AsArray().Select(i => (string)i).ToList();
            var macs = ids.Where(i => i.Count(ch => ch == ':') == 5).Select(NormMac).ToList(); var ip = ids.FirstOrDefault(i => i.Count(ch => ch == '.') == 3);
            if (devs.Any(d => macs.Contains(d.Mac ?? "", StringComparer.OrdinalIgnoreCase)) || (macs.Count == 0 && ip != null && devs.Any(d => d.Ip == ip))) continue;
            if (ip == null && macs.Count == 0) continue;
            devs.Add(new Device { Ip = ip, Mac = macs.FirstOrDefault(), Name = ((string)c["name"]).Replace("SG ", "").Replace("Roku - ", "").Replace("Phone - ", ""), Vendor = macs.Count > 0 ? Oui.Lookup(macs[0]) : "", Network = ip?.StartsWith("192.168.1.") == true ? "Home LAN" : "Hotspot" });
        }
        return devs.OrderBy(d => d.Network).ThenBy(d => System.Version.TryParse(d.Ip ?? "", out var v) ? v : new System.Version()).ToList();
    }

    static async Task ResolveName(Device d)
    {
        d.HostName = "";
        try
        {
            var t = Dns.GetHostEntryAsync(d.Ip); _ = t.ContinueWith(x => _ = x.Exception, TaskContinuationOptions.OnlyOnFaulted);
            if (await Task.WhenAny(t, Task.Delay(2000)) == t && t.Status == TaskStatus.RanToCompletion && t.Result.HostName != d.Ip) d.HostName = t.Result.HostName.Replace(".mshome.net", "").Replace(".lan", "");
        }
        catch { }
    }

    public static HashSet<string> LocalIps() =>
        NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up)
        .SelectMany(n => n.GetIPProperties().UnicastAddresses).Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        .Select(a => a.Address.ToString()).ToHashSet();

    [DllImport("iphlpapi.dll", ExactSpelling = true)] static extern int GetIpNetTable(IntPtr table, ref int size, bool order);

    public static List<(string ip, string mac, bool dynamic)> ReadArp()
    {
        var list = new List<(string, string, bool)>(); int size = 0;
        GetIpNetTable(IntPtr.Zero, ref size, false);
        if (size <= 0) return list;
        var buf = Marshal.AllocHGlobal(size);
        try
        {
            if (GetIpNetTable(buf, ref size, true) != 0) return list;
            int n = Marshal.ReadInt32(buf);
            for (int i = 0; i < n; i++)
            {
                var row = buf + 4 + i * 24;
                int len = Marshal.ReadInt32(row, 4); int type = Marshal.ReadInt32(row, 20);
                if (len != 6 || type == 2) continue; // invalid
                var mac = new byte[6]; Marshal.Copy(row + 8, mac, 0, 6);
                if (mac.All(b => b == 0xFF) || mac.All(b => b == 0) || (mac[0] & 1) == 1) continue; // broadcast/multicast
                var ip = new IPAddress(BitConverter.GetBytes(Marshal.ReadInt32(row, 16))).ToString();
                list.Add((ip, string.Join(":", mac.Select(b => b.ToString("X2"))), type == 3)); // 3 = dynamic (live neighbour), 4 = static (ICS lease leftovers)
            }
        }
        finally { Marshal.FreeHGlobal(buf); }
        return list;
    }
}
