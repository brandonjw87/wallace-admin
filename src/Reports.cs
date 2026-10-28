using System.IO;
using System.Text;

namespace WNH;

/// <summary>CSV / HTML exports of devices, connections, usage and health.</summary>
public static class Reports
{
    static string Stamp => DateTime.Now.ToString("yyyyMMdd-HHmmss");
    static void W(string path, string text) => File.WriteAllText(path, text, new UTF8Encoding(true));

    public static string DevicesCsv(string dir)
    {
        var sb = new StringBuilder("Name,IP,MAC,Vendor,Network,Status,Ping ms,Uptime 24h %,First seen,Last seen,Uploaded bytes,Downloaded bytes\r\n");
        foreach (var d in Devices.All.Values.OrderBy(d => d.Network).ThenBy(d => d.Ip))
            sb.AppendLine(string.Join(",", new[] { d.Display, d.Ip, d.Mac, d.Vendor, d.Network, d.Status, d.LatencyMs.ToString("0"), d.UptimePct(TimeSpan.FromHours(24)).ToString("0"), d.FirstSeen.ToString("s"), d.LastSeen.ToString("s"), d.BytesUp.ToString(), d.BytesDown.ToString() }.Select(Core.Csv)));
        var p = Path.Combine(dir, $"devices-{Stamp}.csv"); W(p, sb.ToString()); return p;
    }

    static List<Conn> Snapshot() { lock (Capture.Gate) return Capture.Conns.Values.ToList(); }

    public static string Connections(string dir)
    {
        var sb = new StringBuilder("Device,Service,Remote host,Remote IP,Owner (ASN),Country,Port,Port name,Protocol,Uploaded bytes,Downloaded bytes,Packets,First seen,Last seen\r\n");
        foreach (var c in Snapshot().OrderByDescending(c => c.Up + c.Down))
        {
            Capture.Enrich(c);
            sb.AppendLine(string.Join(",", new[] { Capture.DeviceName(c.DeviceMac), c.Service, c.Host, c.Remote, c.Owner, c.Country, c.Port.ToString(), c.PortName, c.Proto, c.Up.ToString(), c.Down.ToString(), c.Packets.ToString(), c.First.ToString("s"), c.Last.ToString("s") }.Select(Core.Csv)));
        }
        var p = Path.Combine(dir, $"connections-{Stamp}.csv"); W(p, sb.ToString()); return p;
    }

    public static string UsageCsv(string dir)
    {
        var sb = new StringBuilder("Device,Service,Uploaded bytes,Downloaded bytes,Connections\r\n");
        foreach (var g in Snapshot().Select(c => { Capture.Enrich(c); return c; }).GroupBy(c => (c.DeviceMac, Svc: string.IsNullOrEmpty(c.Service) ? "Other" : c.Service)).OrderByDescending(g => g.Sum(c => c.Up + c.Down)))
            sb.AppendLine(string.Join(",", new[] { Capture.DeviceName(g.Key.DeviceMac), g.Key.Svc, g.Sum(c => c.Up).ToString(), g.Sum(c => c.Down).ToString(), g.Count().ToString() }.Select(Core.Csv)));
        var p = Path.Combine(dir, $"usage-{Stamp}.csv"); W(p, sb.ToString()); return p;
    }

    public static string Html(string dir)
    {
        var sb = new StringBuilder();
        sb.Append("<!doctype html><meta charset=utf-8><title>WALLACE Admin report</title><style>body{background:#1e1e1e;color:#f5f5f7;font-family:'Segoe UI Variable','Segoe UI',system-ui;margin:32px}h1{font-weight:700}h2{color:#a1a1a6;margin-top:32px}table{border-collapse:collapse;width:100%;background:#2c2c2e;border-radius:12px;overflow:hidden}td,th{padding:7px 10px;text-align:left;font-size:13px}th{color:#a1a1a6;border-bottom:1px solid #3a3a3c}tr:nth-child(even){background:#262628}.Green{color:#30d158}.Yellow{color:#ffd60a}.Red{color:#ff453a}.card{display:inline-block;background:#2c2c2e;border-radius:12px;padding:14px 18px;margin:0 10px 10px 0}</style>");
        sb.Append($"<h1>WALLACE Admin</h1><p>Report generated {DateTime.Now:dddd MMM d yyyy, h:mm tt} · app v{Core.Version}</p>");
        sb.Append($"<div class=card><b class={Health.Overall}>●</b> {Core.Esc(Health.Summary)}</div><div class=card>{Devices.All.Values.Count(d => d.Online)} devices online</div><div class=card>Capture: {Core.Esc(Capture.Status)}</div>");
        lock (Bandwidth.Gate) foreach (var s in Bandwidth.Series.Values.Where(s => s.Present)) sb.Append($"<div class=card>{Core.Esc(s.Label)}: ↓ {Core.Bytes(s.TotalIn)} ↑ {Core.Bytes(s.TotalOut)} (peak ↓ {Core.Rate(s.PeakIn)})</div>");
        sb.Append("<h2>Health checks</h2><table><tr><th>Layer<th>Check<th>Status<th>Detail<th>Meaning");
        foreach (var c in Health.Checks) sb.Append($"<tr><td>{Core.Esc(c.Layer)}<td>{Core.Esc(c.Name)}<td class={c.Status}>{c.Status}<td>{Core.Esc(c.Detail)}<td>{Core.Esc(c.Explain)}");
        sb.Append("</table><h2>Live status checks</h2><table><tr><th>Check<th>Target<th>Status<th>Latency<th>Uptime (recent)");
        lock (Monitors.Gate) foreach (var m in Monitors.States) sb.Append($"<tr><td>{Core.Esc(m.Def.Name)}<td>{Core.Esc(m.Def.Type + " " + m.Def.Target)}<td class={(m.Up == true ? "Green" : "Red")}>{(m.Up == true ? "UP" : "DOWN")}<td>{(m.Ms >= 0 ? m.Ms.ToString("0") + " ms" : "")}<td>{m.UptimePct:0.#}%");
        sb.Append("</table><h2>Devices</h2><table><tr><th>Name<th>IP<th>Network<th>Vendor<th>Status<th>Up 24h<th>Last seen<th>Traffic");
        foreach (var d in Devices.All.Values.OrderBy(d => d.Network).ThenByDescending(d => d.Online)) sb.Append($"<tr><td>{Core.Esc(d.Display)}<td>{d.Ip}<td>{d.Network}<td>{Core.Esc(d.Vendor)}<td class={(d.Online ? "Green" : "Red")}>{d.Status}<td>{d.UptimePct(TimeSpan.FromHours(24)):0}%<td>{d.LastSeenText}<td>{d.UsageText}");
        sb.Append("</table><h2>Top connections</h2><table><tr><th>Device<th>Service<th>Host<th>Owner<th>Port<th>↑<th>↓");
        foreach (var c in Snapshot().OrderByDescending(c => c.Up + c.Down).Take(200)) { Capture.Enrich(c); sb.Append($"<tr><td>{Core.Esc(Capture.DeviceName(c.DeviceMac))}<td>{Core.Esc(c.Service)}<td>{Core.Esc(c.Host ?? c.Remote)}<td>{Core.Esc(c.Owner)} {c.Country}<td>{c.Port}/{c.Proto}<td>{Core.Bytes(c.Up)}<td>{Core.Bytes(c.Down)}"); }
        sb.Append("</table><h2>Recent alerts</h2><table><tr><th>Time<th>Alert<th>Detail");
        foreach (var a in Alerts.Feed.ToList().Take(100)) sb.Append($"<tr><td>{a.TimeText}<td>{Core.Esc(a.Title)}<td>{Core.Esc(a.Body)}");
        sb.Append("</table><p style='color:#8e8e93;margin-top:30px'>Contains IP owner data from GeoLite2 by MaxMind (CC BY-SA 4.0). Secrets are never included.</p>");
        var p = Path.Combine(dir, $"report-{Stamp}.html"); W(p, Core.Redact(sb.ToString())); return p;
    }

    public static string WriteAll(string dir)
    {
        Directory.CreateDirectory(dir);
        var files = new[] { DevicesCsv(dir), Connections(dir), UsageCsv(dir), Html(dir) };
        return string.Join("; ", files.Select(Path.GetFileName));
    }
}
