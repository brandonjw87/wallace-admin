using System.Net.NetworkInformation;

namespace WNH;

public class AdapterSeries
{
    public string Key, Label, Description, Ip;
    public readonly double[] In = new double[Bandwidth.Window], Out = new double[Bandwidth.Window]; // bytes/sec ring
    public int Head; // index of next write
    public long LastRx = -1, LastTx = -1; public DateTime LastAt;
    public double CurIn, CurOut, PeakIn, PeakOut; public long TotalIn, TotalOut;
    public int OverSeconds;
    public bool Present;
    public IEnumerable<double> Ordered(double[] a) { for (int i = 0; i < Bandwidth.Window; i++) yield return a[(Head + i) % Bandwidth.Window]; }
}

/// <summary>1-second per-adapter throughput from Windows interface counters (no Npcap needed). 5-minute window.</summary>
public static class Bandwidth
{
    public const int Window = 300;
    public static readonly Dictionary<string, AdapterSeries> Series = new()
    {
        ["hotspot"] = new AdapterSeries { Key = "hotspot", Label = "WALLACE hotspot" },
        ["ethernet"] = new AdapterSeries { Key = "ethernet", Label = "Ethernet (main)" },
        ["wifi"] = new AdapterSeries { Key = "wifi", Label = "Wi-Fi (backup)" },
    };
    public static readonly object Gate = new();
    public static event Action Sampled;
    static Timer timer; static int busy;

    public static void Start() { timer ??= new Timer(_ => Tick(), null, 0, 1000); }

    public static string Classify(NetworkInterface n, out string ip)
    {
        ip = n.GetIPProperties().UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)?.Address.ToString() ?? "";
        if (ip.StartsWith("192.168.137.") || n.Description.Contains("Wi-Fi Direct", StringComparison.OrdinalIgnoreCase) && ip != "" && !ip.StartsWith("169.254")) return "hotspot";
        if (n.NetworkInterfaceType == NetworkInterfaceType.Ethernet && !n.Description.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase) && !n.Description.Contains("Virtual", StringComparison.OrdinalIgnoreCase)) return "ethernet";
        if (n.NetworkInterfaceType == NetworkInterfaceType.Wireless80211 && !n.Description.Contains("Direct", StringComparison.OrdinalIgnoreCase)) return "wifi";
        return null;
    }

    static void Tick()
    {
        if (Interlocked.Exchange(ref busy, 1) == 1) return;
        try
        {
            var now = DateTime.UtcNow; var seen = new HashSet<string>();
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (n.OperationalStatus != OperationalStatus.Up) continue;
                string key, ip; long rx, tx;
                try { key = Classify(n, out ip); if (key == null || seen.Contains(key)) continue; var st = n.GetIPStatistics(); rx = st.BytesReceived; tx = st.BytesSent; }
                catch { continue; }
                seen.Add(key);
                lock (Gate)
                {
                    var s = Series[key]; s.Present = true; s.Description = n.Description; s.Ip = ip;
                    double din = 0, dout = 0;
                    if (s.LastRx >= 0 && rx >= s.LastRx && tx >= s.LastTx)
                    {
                        var dt = Math.Max(0.2, (now - s.LastAt).TotalSeconds);
                        din = (rx - s.LastRx) / dt; dout = (tx - s.LastTx) / dt;
                        s.TotalIn += rx - s.LastRx; s.TotalOut += tx - s.LastTx;
                    }
                    s.LastRx = rx; s.LastTx = tx; s.LastAt = now;
                    s.In[s.Head] = din; s.Out[s.Head] = dout; s.Head = (s.Head + 1) % Window;
                    s.CurIn = din; s.CurOut = dout; s.PeakIn = Math.Max(s.PeakIn, din); s.PeakOut = Math.Max(s.PeakOut, dout);
                    CheckThreshold(s);
                }
            }
            lock (Gate) foreach (var s in Series.Values) if (!seen.Contains(s.Key)) { s.Present = false; s.CurIn = s.CurOut = 0; s.In[s.Head] = 0; s.Out[s.Head] = 0; s.Head = (s.Head + 1) % Window; }
            Sampled?.Invoke();
        }
        catch (Exception ex) { Core.Log("bandwidth tick: " + ex.Message); }
        finally { Volatile.Write(ref busy, 0); }
    }

    static void CheckThreshold(AdapterSeries s)
    {
        var cfg = AppSettings.Current; if (!cfg.AlertBandwidth) { s.OverSeconds = 0; return; }
        double mbps = (s.CurIn + s.CurOut) * 8 / 1e6;
        s.OverSeconds = mbps > cfg.BandwidthMbps ? s.OverSeconds + 1 : 0;
        if (s.OverSeconds == Math.Max(1, cfg.BandwidthSeconds))
            Alerts.Raise("bw-" + s.Key, "yellow", $"High bandwidth on {s.Label}", $"{mbps:0.0} Mbps for {cfg.BandwidthSeconds}s (limit {cfg.BandwidthMbps} Mbps).", 15);
    }
}
