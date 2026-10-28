using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace WNH;

public class Probe { public DateTime T; public bool Up; public double Ms; public string Note; }

public class MonitorState
{
    public MonitorDef Def;
    public readonly List<Probe> History = new(); // newest last, capped
    public bool? Up; public double Ms = -1; public string Note = ""; public int Fails;
    public double UptimePct => History.Count == 0 ? 0 : History.Count(p => p.Up) * 100.0 / History.Count;
}

/// <summary>homelable-style live status checks (ping / TCP / HTTP) with a history timeline.</summary>
public static class Monitors
{
    public const int Keep = 120;
    public static readonly List<MonitorState> States = new();
    public static readonly object Gate = new();
    public static event Action Updated;
    static Timer timer; static int running;
    static readonly HttpClient http = new(new SocketsHttpHandler { AllowAutoRedirect = true, ConnectTimeout = TimeSpan.FromSeconds(4) }) { Timeout = TimeSpan.FromSeconds(6) };

    public static void Start() { Sync(); timer ??= new Timer(async _ => await RunAllAsync(), null, 500, Math.Max(10, AppSettings.Current.MonitorSeconds) * 1000); }

    public static void Sync()
    {
        lock (Gate)
        {
            var defs = AppSettings.Current.Monitors;
            States.RemoveAll(s => !defs.Contains(s.Def));
            foreach (var d in defs) if (!States.Any(s => s.Def == d)) States.Add(new MonitorState { Def = d });
            States.Sort((a, b) => defs.IndexOf(a.Def).CompareTo(defs.IndexOf(b.Def)));
        }
    }

    public static MonitorState Find(string target) { lock (Gate) return States.FirstOrDefault(s => s.Def.Target.Contains(target)); }

    public static async Task RunAllAsync()
    {
        if (Interlocked.Exchange(ref running, 1) == 1) return;
        try
        {
            List<MonitorState> list; lock (Gate) list = States.ToList();
            await Task.WhenAll(list.Select(async s =>
            {
                var p = await ProbeOnce(s.Def);
                lock (Gate)
                {
                    s.History.Add(p); if (s.History.Count > Keep) s.History.RemoveAt(0);
                    s.Ms = p.Ms; s.Note = p.Note; s.Fails = p.Up ? 0 : s.Fails + 1;
                    bool? before = s.Up;
                    if (p.Up) s.Up = true; else if (s.Fails >= 2 || before == null) s.Up = false;
                    if (before == true && s.Up == false && AppSettings.Current.AlertMonitorDown)
                        Alerts.Raise("mon-" + s.Def.Name, "red", $"{s.Def.Name} is DOWN", $"{s.Def.Type} {s.Def.Target}: {p.Note}", 15);
                    if (before == false && s.Up == true) Alerts.Raise("monup-" + s.Def.Name, "green", $"{s.Def.Name} recovered", $"{s.Def.Type} {s.Def.Target} {p.Ms:0} ms", 5);
                }
            }));
            Updated?.Invoke();
        }
        catch (Exception ex) { Core.Log("monitors: " + ex); }
        finally { Volatile.Write(ref running, 0); }
    }

    public static async Task<Probe> ProbeOnce(MonitorDef d)
    {
        var p = new Probe { T = DateTime.Now }; var sw = System.Diagnostics.Stopwatch.StartNew();
        // MAC-based targets ("mac:AA:BB:..") follow a device to whatever DHCP lease it currently has on WALLACE
        var target = Devices.ResolveTarget(d.Target);
        if (target == null) { p.Up = false; p.Ms = -1; p.Note = "device not seen on network (MAC " + d.Target[4..] + ")"; return p; }
        try
        {
            switch ((d.Type ?? "ping").ToLowerInvariant())
            {
                case "tcp":
                    {
                        var i = target.LastIndexOf(':'); var host = target[..i]; var port = int.Parse(target[(i + 1)..]);
                        using var c = new TcpClient(); using var cts = new CancellationTokenSource(2500);
                        await c.ConnectAsync(host, port, cts.Token); p.Up = true; p.Ms = sw.Elapsed.TotalMilliseconds; p.Note = "port open"; break;
                    }
                case "http":
                    {
                        using var r = await http.GetAsync(target, HttpCompletionOption.ResponseHeadersRead);
                        p.Ms = sw.Elapsed.TotalMilliseconds; p.Up = (int)r.StatusCode < 500; p.Note = "HTTP " + (int)r.StatusCode; break;
                    }
                default:
                    {
                        using var ping = new Ping(); var r = await ping.SendPingAsync(target, 1500);
                        p.Up = r.Status == IPStatus.Success; p.Ms = p.Up ? r.RoundtripTime : -1; p.Note = r.Status.ToString(); break;
                    }
            }
        }
        catch (Exception ex) { p.Up = false; p.Ms = -1; p.Note = (ex.InnerException ?? ex).Message; }
        return p;
    }
}
