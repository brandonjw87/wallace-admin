using System.Diagnostics;
using System.IO;
using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;

namespace WNH;

/// <summary>GL.iNet Flint-style router features, mapped honestly onto a Windows Mobile Hotspot (ICS) host.</summary>
public static class Router
{
    public record Feature(string Name, string Status, string How);
    public static readonly Feature[] Features =
    {
        new("Client list (online/offline, IP, MAC, vendor, last seen)", "Implemented", "Devices + Admin pages; ARP/ping/SSDP/mDNS scan, duplicates merged by MAC."),
        new("Per-device block / pause", "Implemented (hotspot)", "Windows Filtering Platform block on the IP-forward layer + AdGuard access list. Spectrum devices: not possible from this PC (their traffic never passes it)."),
        new("Parental control profiles (adult/social/SafeSearch)", "Implemented", "Safe Guard + category toggles in AdGuard Home. Per-device profiles only work for devices AdGuard sees directly (see ICS note)."),
        new("Schedules / bedtime per device or whole hotspot", "Implemented", "Bedtime rules below create Windows scheduled tasks that pause/resume a device (by MAC) or stop/start the hotspot."),
        new("Per-client traffic stats", "Partial", "Live Traffic / Bandwidth pages count bytes per device via Npcap capture while the app runs; no long-term per-client counters like the router's."),
        new("Per-device bandwidth limit / QoS", "Not possible", "Windows QoS policies (pacing) apply to traffic this PC sends from its own apps, not to forwarded ICS traffic, and there is no per-client shaper without a driver."),
        new("AdGuard per-client settings", "Partial", "Persistent clients exist (SG Phone/SG Roku), but the hotspot DNS proxy hides real client IPs for UDP DNS, so per-client rules are unreliable on WALLACE."),
        new("Encrypted upstream DNS (DoH/DoT)", "Implemented", "Button below switches AdGuard Home upstreams to Cloudflare/Quad9 DoH (with plain bootstrap). Shows current upstreams."),
        new("Guest network", "Not possible", "Windows can host only one hotspot SSID; WALLACE already is the separate network from Spectrum."),
        new("VPN client / server (WireGuard, Tailscale)", "Not implemented (ask first)", "Possible on Windows but needs installing software and/or exposing a port; not done without your OK."),
        new("Network kill switch", "Partial", "'Pause whole hotspot' via a schedule rule with device '*' (stops the hotspot). No VPN kill switch since no VPN is used."),
        new("MAC filter / allowlist-only mode", "Not possible", "Windows hotspot has no MAC filter. Workaround: pause unknown devices individually; the password is the real gate."),
        new("Max clients", "Read-only", "Windows fixes the hotspot client limit (shown on the WALLACE page); it cannot be changed without a driver."),
        new("Port forwarding / DDNS", "Not applicable", "WALLACE sits behind the Spectrum router (double NAT); forwarding belongs on the Spectrum router. Not exposed."),
        new("Firmware / plugin manager", "Implemented (app level)", "Updates page checks AdGuard Home, iSponsorBlockTV, Uptime Kuma, Sniffnet, blocklists. Nothing auto-installs."),
        new("Scheduled reboot", "Implemented (off by default)", "Weekly reboot task below (2-minute warning)."),
        new("Scheduled Wi-Fi on/off", "Implemented", "Bedtime rule with device '*' stops the hotspot at From and restarts it at To."),
        new("LED control", "Not applicable", "No router LEDs."),
        new("Connection alerts", "Implemented", "Alerts page: new device, device offline, monitor down, bandwidth, blacklist hits."),
        new("Speed test", "Implemented", "Cloudflare speed test below (download/upload/latency) from this PC."),
        new("Ping / traceroute / DNS lookup diagnostics", "Implemented", "Tools below."),
        new("Logs", "Implemented", "Logs page + Admin > view/clear logs; AdGuard query log in Reports PDF."),
        new("Multi-WAN failover / load balancing", "Partial (status only)", "Windows picks the uplink by metric (Ethernet first, Wi-Fi backup). Status shown below; no load balancing."),
        new("IPv6", "Status only", "ICS hands out IPv4 only; IPv6 status of the uplink is shown below."),
        new("Wi-Fi channel / band / tx power", "Partial", "Band (5 GHz) is set and shown; channel is chosen by the Intel driver. Changing tx power/channel would need driver settings (off-limits)."),
    };

    public static async Task<string> SpeedTest()
    {
        using var h = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(60) };
        var sw = Stopwatch.StartNew(); await h.GetAsync("https://speed.cloudflare.com/__down?bytes=0"); var lat = sw.ElapsedMilliseconds;
        sw.Restart(); var data = await h.GetByteArrayAsync("https://speed.cloudflare.com/__down?bytes=25000000"); double down = data.Length * 8 / sw.Elapsed.TotalSeconds / 1e6;
        var up = new byte[10_000_000]; new Random().NextBytes(up); sw.Restart(); await h.PostAsync("https://speed.cloudflare.com/__up", new System.Net.Http.ByteArrayContent(up)); double upm = up.Length * 8 / sw.Elapsed.TotalSeconds / 1e6;
        var r = $"Download {down:0.0} Mbps \u00B7 Upload {upm:0.0} Mbps \u00B7 HTTPS latency {lat} ms (from this PC over {Wallace.Current.Uplink})"; Core.Log("speedtest: " + r); return r;
    }

    public static async Task<string> PingTrace(string host, bool trace)
    {
        host = (host ?? "").Trim(); if (!System.Text.RegularExpressions.Regex.IsMatch(host, @"^[A-Za-z0-9.:-]+$")) return "Enter a host name or IP.";
        if (!trace)
        {
            var res = new List<string>(); using var p = new Ping();
            for (int i = 0; i < 4; i++) { try { var r = await p.SendPingAsync(host, 2000); res.Add(r.Status == IPStatus.Success ? $"{r.RoundtripTime} ms" : r.Status.ToString()); } catch (Exception ex) { res.Add(ex.InnerException?.Message ?? ex.Message); } }
            return $"ping {host}: " + string.Join(", ", res);
        }
        return await Task.Run(() => { var (c, o) = Core.RunPs($"tracert -d -h 20 -w 800 {host}", 90000); return o.Trim(); });
    }

    public static async Task<string> DnsLookup(string host) => await Task.Run(() => Core.RunPs($"Resolve-DnsName '{host.Replace("'", "")}' -Server 127.0.0.1 -DnsOnly -ErrorAction Stop | ?{{ $_.IPAddress }} | %{{ $_.Type.ToString()+' '+$_.IPAddress }}", 15000).output.Trim());

    public static readonly string[] EncryptedUpstreams = { "https://dns.cloudflare.com/dns-query", "https://dns.quad9.net/dns-query" };
    public static async Task<string> Upstreams() { var d = await SafeGuard.Get("dns/info"); return string.Join(", ", (d["upstream_dns"]?.AsArray() ?? new JsonArray()).Select(x => (string)x)); }
    public static async Task SetEncryptedUpstreams()
    {
        var d = await SafeGuard.Get("dns/info");
        await SafeGuard.Send("POST", "dns/config", new JsonObject { ["upstream_dns"] = new JsonArray(EncryptedUpstreams.Select(x => (JsonNode)x).ToArray()), ["bootstrap_dns"] = new JsonArray("1.1.1.1", "9.9.9.9"), ["upstream_mode"] = (string)d["upstream_mode"] is { Length: > 0 } um ? um : "load_balance" });
        Core.Log("AdGuard upstreams -> encrypted DoH");
    }

    public static string NetStatus()
    {
        var ups = NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up && n.GetIPProperties().GatewayAddresses.Any(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && g.Address.ToString() != "0.0.0.0")).ToList();
        var lines = ups.Select(n => { var p = n.GetIPProperties(); bool v6 = p.UnicastAddresses.Any(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 && !a.Address.IsIPv6LinkLocal); return $"{n.Name} ({n.NetworkInterfaceType}): gateway {p.GatewayAddresses.First(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).Address}, IPv6 {(v6 ? "yes" : "no")}"; }).ToList();
        var (_, wl) = Core.RunPs("(netsh wlan show interfaces) -match '^\\s+(Name|SSID|Channel|Band|Radio type|Receive rate|Signal)\\s' | %{ $_.Trim() }", 15000);
        return $"Active uplink(s): {(lines.Count == 0 ? "none" : string.Join(" | ", lines))}\nFailover: {(ups.Count > 1 ? "a backup uplink is up; Windows switches automatically by route metric" : "only one uplink up right now; if Ethernet drops Windows will use Wi-Fi if it is connected")}\nWi-Fi client radio: {wl.Trim().Replace("\r\n", "; ")}\nWALLACE hotspot: {Wallace.Current.State}, {Wallace.Current.BandText}, clients {Wallace.Current.Clients}/{Wallace.Current.MaxClients}";
    }
}

public class RouterPage : PageBase
{
    public override string Title => "Router (Flint features)";
    public override string Subtitle => "What a GL.iNet Flint router offers, and what WALLACE Admin can do on a Windows hotspot";
    readonly TextBox outBox = P.Viewer(); readonly StackPanel schedList = new();
    protected override UIElement Build()
    {
        outBox.Height = 150;
        var feat = new StackPanel();
        foreach (var f in Router.Features)
        {
            var g = new Grid { Margin = new Thickness(0, 2, 0, 2) }; g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(290) }); g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(170) }); g.ColumnDefinitions.Add(new ColumnDefinition());
            var col = f.Status.StartsWith("Implemented") ? UI.Green : f.Status.StartsWith("Partial") || f.Status.Contains("only") ? UI.Yellow : UI.Sub;
            var a = UI.T(f.Name, 12.5); var b = UI.T(f.Status, 12, FontWeights.SemiBold, col); var c = UI.T(f.How, 11.5, null, UI.Sub, true); Grid.SetColumn(b, 1); Grid.SetColumn(c, 2); g.Children.Add(a); g.Children.Add(b); g.Children.Add(c); feat.Children.Add(g);
        }
        var host = UI.Box("1.1.1.1", 200);
        async void Out(Func<Task<string>> f) { outBox.Text = "Running\u2026"; try { outBox.Text = await f(); } catch (Exception ex) { outBox.Text = "Failed: " + Core.Redact(ex.Message); } }
        var tools = UI.Card(UI.Col(UI.H("Diagnostics"),
            UI.Row(UI.Btn("Speed test", () => Out(Router.SpeedTest), true, "\uEC4A"), new Border { Width = 6 }, host, new Border { Width = 6 },
                   UI.Btn("Ping", () => Out(() => Router.PingTrace(host.Text, false)), false, "\uE968"), new Border { Width = 6 }, UI.Btn("Traceroute", () => Out(() => Router.PingTrace(host.Text, true)), false, "\uE8AD"), new Border { Width = 6 },
                   UI.Btn("DNS lookup (AdGuard)", () => Out(() => Router.DnsLookup(host.Text)), false, "\uE774")),
            UI.Row(UI.Btn("Uplink / failover / Wi-Fi status", () => Out(() => Task.Run(Router.NetStatus)), false, "\uE701"), new Border { Width = 6 },
                   UI.Btn("Show DNS upstreams", () => Out(async () => "AdGuard upstreams: " + await Router.Upstreams()), false, "\uE946"), new Border { Width = 6 },
                   UI.Btn("Use encrypted upstreams (DoH)", () => { if (Admin.Confirm("Switch AdGuard Home upstream DNS to Cloudflare + Quad9 DNS-over-HTTPS? (Back up settings first on the Admin page if unsure.)")) Out(async () => { await Router.SetEncryptedUpstreams(); return "Now: " + await Router.Upstreams(); }); }, false, "\uE72E")),
            outBox));
        // bedtime schedules
        var sName = UI.Box("Bedtime", 120); var sDev = new ComboBox { Width = 230, IsEditable = true, Text = "*" }; sDev.DropDownOpened += (s, e) => sDev.ItemsSource = new[] { "* (whole hotspot)" }.Concat(Devices.All.Values.Where(d => d.Network == "Hotspot").Select(d => $"{d.Display} | {d.Mac}")).ToList();
        var sFrom = UI.Box("22:00", 60); var sTo = UI.Box("06:00", 60); var sDays = UI.Box("0123456", 80); sDays.ToolTip = "0=Sun \u2026 6=Sat";
        var rb = UI.Box("off", 140); rb.ToolTip = "e.g. 'Sunday 04:00' or 'off'";
        var sched = UI.Card(UI.Col(UI.H("Schedules / bedtime"), UI.T("Pause a hotspot device (by MAC) or stop the whole hotspot between From and To. Saved as Windows scheduled tasks under \\WALLACE\\ (one UAC click to install). Overnight ranges (22:00\u219206:00) work.", 11.5, null, UI.Sub, true),
            UI.Row(sName, new Border { Width = 6 }, sDev, new Border { Width = 6 }, UI.T("from ", 12), sFrom, UI.T("  to ", 12), sTo, UI.T("  days ", 12), sDays, new Border { Width = 6 },
                UI.Btn("Add", () => { var mac = sDev.Text.StartsWith("*") ? "*" : sDev.Text.Split('|').Last().Trim(); if (mac != "*" && mac.Length != 17) { outBox.Text = "Pick a device from the list."; return; } if (!TimeSpan.TryParse(sFrom.Text, out _) || !TimeSpan.TryParse(sTo.Text, out _)) { outBox.Text = "Times must be HH:mm"; return; }
                    AppSettings.Current.Schedules.Add(new ScheduleRule { Name = sName.Text.Trim(), Mac = mac, From = sFrom.Text.Trim(), To = sTo.Text.Trim(), Days = new string(sDays.Text.Where(char.IsDigit).Distinct().ToArray()) }); AppSettings.Save(); RenderSched(); }, false, "\uE710")),
            schedList,
            UI.Row(UI.Btn("Install schedules (UAC)", () => { if (Admin.Confirm($"Install {AppSettings.Current.Schedules.Count(x => x.Enabled)} schedule rule(s) as Windows tasks (replaces earlier WALLACE bedtime tasks)?")) Out(InstallSched); }, true, "\uE823"), new Border { Width = 16 },
                   UI.T("Weekly reboot: ", 12), rb, new Border { Width = 6 }, UI.Btn("Set (UAC)", () => { if (Admin.Confirm("Set scheduled reboot to: " + rb.Text + "?")) Out(async () => { var (ok, l) = await Admin.Elevate("reboot-schedule", rb.Text.Trim()); return l; }); }, false, "\uE777"))));
        RenderSched();
        return UI.Scroll(UI.Col(tools, sched, UI.Card(UI.Col(UI.H("Flint / GL.iNet feature map"), UI.T("Green = implemented, yellow = partial, grey = not possible or not applicable on a Windows hotspot.", 11.5, null, UI.Sub, true), new Border { Height = 6 }, feat))));
    }
    async Task<string> InstallSched()
    {
        // 3.2.0: phones are never paused by a schedule (messaging protected); whole-hotspot rules are fine (phones fall back to mobile data)
        var safe = AppSettings.Current.Schedules.Where(s => s.Mac == "*" || !Messaging.IsPhone(null, s.Mac, s.Name)).ToList(); int skipped = AppSettings.Current.Schedules.Count - safe.Count;
        var f = Path.Combine(Core.DataDir, "schedules.json"); File.WriteAllText(f, JsonSerializer.Serialize(safe));
        if (skipped > 0) Core.Log($"schedules: skipped {skipped} phone rule(s) - messaging protected");
        var (ok, l) = await Admin.Elevate("install-schedules", f); return (ok ? "OK: " : "FAILED: ") + l + (skipped > 0 ? $" ({skipped} phone schedule(s) skipped: messaging protected)" : "");
    }
    void RenderSched()
    {
        schedList.Children.Clear();
        foreach (var r in AppSettings.Current.Schedules.ToList())
        {
            var rr = r; var cb = new CheckBox { IsChecked = r.Enabled, VerticalAlignment = VerticalAlignment.Center }; cb.Click += (s, e) => { rr.Enabled = cb.IsChecked == true; AppSettings.Save(); };
            var who = r.Mac == "*" ? "whole hotspot" : (Devices.All.TryGetValue(r.Mac, out var d) ? d.Display : r.Mac);
            schedList.Children.Add(UI.Row(cb, UI.T($"  {r.Name}: {who}  {r.From}\u2192{r.To}  days {r.Days}", 12.5), new Border { Width = 10 }, UI.Btn("Delete", () => { if (Admin.Confirm("Delete schedule " + rr.Name + "? (Click Install afterwards to update Windows tasks.)")) { AppSettings.Current.Schedules.Remove(rr); AppSettings.Save(); RenderSched(); } }, false, "\uE74D")));
        }
        if (AppSettings.Current.Schedules.Count == 0) schedList.Children.Add(UI.T("No schedules yet.", 12, null, UI.Sub));
    }
}
