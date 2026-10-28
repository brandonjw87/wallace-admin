using System.IO;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace WNH;

public record BlockEvent(DateTime Time, string ClientIp, string Device, string Mac, string Attribution, string Domain, string Category, string App, string Source);

/// <summary>Blocked-request reports from the AdGuard Home query log: who (best-effort device), what (domain/app), why (category/list), when.</summary>
public static class BlockReport
{
    public static readonly string[] AllCategories = { "Porn / adult", "Gambling", "Instagram", "Social", "Ads", "Trackers", "Malware / scam", "Crypto-mining", "Telemetry", "SafeSearch", "Bypass / VPN / DoH", "Custom rules", "Other" };
    static readonly (string suffix, string app)[] Apps =
    {
        ("instagram.com","Instagram"),("cdninstagram.com","Instagram"),("facebook.com","Facebook"),("fbcdn.net","Facebook"),("facebook.net","Facebook"),("tiktok","TikTok"),("snapchat.com","Snapchat"),("sc-cdn.net","Snapchat"),
        ("twitter.com","X/Twitter"),("twimg.com","X/Twitter"),("reddit.com","Reddit"),("redd.it","Reddit"),("discord","Discord"),("tinder.com","Tinder"),("onlyfans.com","OnlyFans"),
        ("pornhub.com","Pornhub"),("xvideos","XVideos"),("xnxx","XNXX"),("doubleclick.net","Google Ads"),("googlesyndication.com","Google Ads"),("googleadservices.com","Google Ads"),("google-analytics.com","Google Analytics"),
        ("app-measurement.com","Firebase Analytics"),("roku.com","Roku"),("ravm.tv","Roku ads"),("amazon-adsystem.com","Amazon Ads"),("scorecardresearch.com","comScore"),("adnxs.com","Xandr Ads"),
        ("microsoft.com","Microsoft"),("msn.com","Microsoft"),("bing.com","Bing"),("google.com","Google"),("youtube.com","YouTube"),("netflix","Netflix"),("hulu","Hulu"),("samsung","Samsung"),("lgtv","LG TV"),("apple.com","Apple"),("icloud.com","Apple iCloud"),
        ("draftkings","DraftKings"),("fanduel","FanDuel"),("bet365","bet365"),("coinhive","Coinhive miner"),
    };
    public static string AppFor(string domain)
    {
        var d = (domain ?? "").ToLowerInvariant().TrimEnd('.');
        foreach (var (s, a) in Apps) if (d == s || d.EndsWith("." + s) || (!s.Contains('.') && d.Contains(s))) return a;
        var parts = d.Split('.'); return parts.Length >= 2 ? parts[^2] : d;
    }
    static readonly HashSet<string> PcIds = new() { "127.0.0.1", "::1", "192.0.2.11", "192.0.2.13" };

    public static async Task<List<BlockEvent>> Load(DateTime from, DateTime to, int max = 20000)
    {
        var filters = (await SafeGuard.Get("filtering/status"))["filters"]?.AsArray() ?? new JsonArray(); var cat = new Dictionary<long, (string c, string n)>();
        foreach (var f in filters)
        {
            string n = (string)f["name"] ?? "", u = (string)f["url"] ?? "";
            string c = n.Contains("[ads]") ? "Ads" : n.Contains("[strict]") ? "Trackers" : n.Contains("[malware]") ? "Malware / scam" : n.Contains("[crypto]") ? "Crypto-mining" : n.Contains("[telemetry]") ? "Telemetry" : n.Contains("[gambling]") ? "Gambling"
                : n.StartsWith("Safe Guard:") ? "Porn / adult" : SafeGuard.BypassListUrls.Contains(u) ? "Bypass / VPN / DoH" : "Ads";
            cat[(long)f["id"]] = (c, n);
        }
        var clients = SafeGuard.LastClients ?? (await SafeGuard.Get("clients"))["clients"]?.AsArray() ?? new JsonArray();
        var res = new List<BlockEvent>(); var seen = new HashSet<string>();
        foreach (var status in new[] { "blocked", "blocked_services", "blocked_parental", "blocked_safebrowsing", "safe_search" })
        {
            string older = null;
            for (int page = 0; page < 200 && res.Count < max; page++)
            {
                var q = await SafeGuard.Get($"querylog?limit=500&response_status={status}" + (older == null ? "" : "&older_than=" + Uri.EscapeDataString(older)));
                var data = q["data"]?.AsArray() ?? new JsonArray(); if (data.Count == 0) break; bool past = false;
                foreach (var e in data)
                {
                    if (!DateTime.TryParse((string)e["time"], out var t)) continue; t = t.ToLocalTime(); if (t < from) { past = true; break; } if (t > to) continue;
                    string reason = (string)e["reason"] ?? "", dom = (string)e["question"]?["name"] ?? "?", ip = (string)e["client"] ?? "";
                    if (!reason.StartsWith("Filtered") && reason != "Rewrite") continue;
                    var key = (string)e["time"] + dom + ip; if (!seen.Add(key)) continue;
                    string category = "Other", source = reason;
                    if (reason == "FilteredBlockedService") { var sv = (string)e["service_name"] ?? ""; category = sv == "instagram" ? "Instagram" : "Social"; source = "Blocked service: " + sv; }
                    else if (reason == "FilteredParental") { category = "Porn / adult"; source = "AdGuard parental control"; }
                    else if (reason == "FilteredSafeBrowsing") { category = "Malware / scam"; source = "AdGuard browsing security"; }
                    else if (reason is "FilteredSafeSearch" or "Rewrite") { category = "SafeSearch"; source = "SafeSearch forced"; }
                    else foreach (var r in e["rules"]?.AsArray() ?? new JsonArray())
                    {
                        long id = (long?)r?["filter_list_id"] ?? 0;
                        if (id == 0) { category = "Custom rules"; source = "Custom rule " + (string)r?["text"]; } else if (cat.TryGetValue(id, out var cn)) { category = cn.c; source = cn.n; }
                        break;
                    }
                    var (dev, mac, att) = Attribute(ip, (string)e["client_info"]?["name"], t, clients);
                    res.Add(new BlockEvent(t, ip, dev, mac, att, dom, category, AppFor(dom), source));
                }
                older = (string)q["oldest"]; if (past || string.IsNullOrEmpty(older)) break;
            }
        }
        return res.OrderByDescending(x => x.Time).ToList();
    }

    /// <summary>Best-effort device attribution. Exact when AdGuard saw the device's own IP; for queries relayed by the Windows hotspot DNS proxy
    /// (seen as this PC) we only say "probably X" when exactly one hotspot device was online at that time.</summary>
    static (string dev, string mac, string att) Attribute(string ip, string clientName, DateTime t, JsonArray clients)
    {
        if (PcIds.Contains(ip))
        {
            var online = Devices.All.Values.Where(d => d.Network == "Hotspot" && WasOnline(d, t)).ToList();
            if (online.Count == 1) return ($"WALLACE hotspot \u2013 probably {online[0].Display}", online[0].Mac, "inferred (only hotspot device online)");
            return ("WALLACE hotspot / this PC (device unknown)", "", online.Count == 0 ? "relayed by Windows hotspot DNS" : $"relayed by Windows hotspot DNS ({online.Count} devices online)");
        }
        var dv = Devices.All.Values.FirstOrDefault(d => d.Ip == ip); var c = SafeGuard.FindClient(clients, ip, dv?.Mac);
        var name = dv?.Display ?? (c != null ? ((string)c["name"]).Replace("SG ", "") : !string.IsNullOrEmpty(clientName) ? clientName : ip);
        return (name, dv?.Mac ?? "", "exact (device's own IP)");
    }
    static bool WasOnline(Device d, DateTime t)
    {
        if (d.FirstSeen > t) return false; var before = d.History.LastOrDefault(h => h.T <= t);
        return before?.Up ?? (d.Online && d.FirstSeen <= t);
    }

    public static string Pdf(List<BlockEvent> ev, DateTime from, DateTime to, string title, string dir = null)
    {
        QuestPDF.Settings.License = LicenseType.Community;
        dir ??= Path.Combine(Core.ReportDir, "Blocked"); Directory.CreateDirectory(dir);
        var file = Path.Combine(dir, $"WALLACE-blocked-{from:yyyyMMdd-HHmm}-to-{to:yyyyMMdd-HHmm}.pdf");
        var cats = ev.GroupBy(e => e.Category).OrderByDescending(g => g.Count()).Select(g => (g.Key, g.Count())).ToList();
        var devs = ev.GroupBy(e => e.Device).OrderByDescending(g => g.Count()).ToList();
        var sites = ev.GroupBy(e => e.Domain).OrderByDescending(g => g.Count()).Take(15).Select(g => (g.Key + "  (" + g.First().App + ")", g.Count())).ToList();
        var apps = ev.GroupBy(e => e.App).OrderByDescending(g => g.Count()).Take(10).Select(g => (g.Key, g.Count())).ToList();
        bool hourly = (to - from).TotalHours <= 48; var buckets = new List<(string, int)>();
        for (var b = hourly ? new DateTime(from.Year, from.Month, from.Day, from.Hour, 0, 0) : from.Date; b < to; b = hourly ? b.AddHours(1) : b.AddDays(1))
        { var e2 = hourly ? b.AddHours(1) : b.AddDays(1); var bb = b; buckets.Add((hourly ? b.ToString("HH") : b.ToString("M/d"), ev.Count(x => x.Time >= bb && x.Time < e2))); }
        const string accent = "#0A84FF"; var colors = new[] { "#FF375F", "#FF9F0A", "#BF5AF2", "#0A84FF", "#30D158", "#64D2FF", "#FFD60A", "#8E8E93", "#5E5CE6", "#FF453A", "#32D74B", "#AC8E68", "#636366" };
        string Col(string c) => colors[Math.Max(0, Array.IndexOf(AllCategories, c)) % colors.Length];
        int exact = ev.Count(e => e.Attribution.StartsWith("exact")), inferred = ev.Count(e => e.Attribution.StartsWith("inferred"));

        void Bars(IContainer c, List<(string label, int n)> rows, Func<string, string> color = null)
        {
            int max = Math.Max(1, rows.Select(r => r.n).DefaultIfEmpty(0).Max());
            c.Column(col =>
            {
                if (rows.Count == 0) col.Item().Text("Nothing in this range.").FontColor(Colors.Grey.Medium);
                foreach (var (l, n) in rows) col.Item().PaddingVertical(1.5f).Row(r =>
                {
                    r.ConstantItem(190).Text(l).FontSize(8.5f).ClampLines(1);
                    r.RelativeItem().Height(10).Row(br => { float w = Math.Max(0.01f, n / (float)max); br.RelativeItem(w).Background(color?.Invoke(l) ?? accent); br.RelativeItem(Math.Max(0.001f, 1 - w)); });
                    r.ConstantItem(48).AlignRight().Text(n.ToString("N0")).FontSize(8.5f);
                });
            });
        }
        void Timeline(IContainer c)
        {
            int max = Math.Max(1, buckets.Select(b => b.Item2).DefaultIfEmpty(0).Max());
            c.Height(110).Row(r =>
            {
                foreach (var (l, n) in buckets) r.RelativeItem().PaddingHorizontal(0.5f).Column(col =>
                {
                    col.Item().Height(92).AlignBottom().Height(Math.Max(0.5f, 92f * n / max)).Background(accent);
                    col.Item().AlignCenter().Text(buckets.Count > 40 ? "" : l).FontSize(6);
                });
            });
        }

        Document.Create(doc =>
        {
            doc.Page(p =>
            {
                p.Size(PageSizes.Letter); p.Margin(32); p.DefaultTextStyle(x => x.FontSize(9.5f).FontFamily("Segoe UI"));
                p.Header().Row(r => { r.RelativeItem().Column(c => { c.Item().Text(title).FontSize(18).Bold().FontColor(accent); c.Item().Text($"{from:ddd MMM d yyyy h:mm tt} \u2013 {to:ddd MMM d yyyy h:mm tt} (Eastern)  \u00B7  generated {DateTime.Now:MMM d h:mm tt}").FontSize(8.5f).FontColor(Colors.Grey.Darken1); }); });
                p.Footer().AlignCenter().Text(t => { t.Span("WALLACE Admin " + Core.Version + " \u00B7 page ").FontSize(8); t.CurrentPageNumber().FontSize(8); t.Span(" / ").FontSize(8); t.TotalPages().FontSize(8); });
                p.Content().Column(col =>
                {
                    col.Spacing(10);
                    col.Item().Row(r =>
                    {
                        void Kpi(string k, string v) => r.RelativeItem().Border(0.5f).BorderColor(Colors.Grey.Lighten2).Padding(8).Column(c => { c.Item().Text(v).FontSize(16).Bold(); c.Item().Text(k).FontSize(8).FontColor(Colors.Grey.Darken1); });
                        Kpi("blocked requests", ev.Count.ToString("N0")); Kpi("devices / sources", devs.Count.ToString()); Kpi("categories hit", cats.Count.ToString()); Kpi("porn / adult blocks", ev.Count(e => e.Category == "Porn / adult").ToString("N0")); Kpi("gambling blocks", ev.Count(e => e.Category == "Gambling").ToString("N0"));
                    });
                    col.Item().Background(Colors.Yellow.Lighten4).Padding(8).Text(
                        $"How devices are identified: {exact:N0} blocks came from a device AdGuard saw directly (exact). On the WALLACE hotspot, Windows' own DNS proxy relays every hotspot device's lookups, so AdGuard sees them as this PC; " +
                        $"those are shown as 'WALLACE hotspot / this PC (device unknown)', or 'probably <device>' ({inferred:N0} blocks) when only one hotspot device was online at that minute. Spectrum Wi-Fi devices do not use AdGuard and never appear here.").FontSize(8.5f);
                    col.Item().Text("Blocks by category").Bold().FontSize(12); col.Item().Element(c => Bars(c, cats, Col));
                    col.Item().Text(hourly ? "Blocks per hour" : "Blocks per day").Bold().FontSize(12); col.Item().Element(Timeline);
                    col.Item().Row(r =>
                    {
                        r.RelativeItem().Column(c => { c.Item().Text("Top devices").Bold().FontSize(12); c.Item().Element(x => Bars(x, devs.Take(10).Select(g => (g.Key, g.Count())).ToList())); });
                        r.ConstantItem(14);
                        r.RelativeItem().Column(c => { c.Item().Text("Top apps / services").Bold().FontSize(12); c.Item().Element(x => Bars(x, apps)); });
                    });
                    col.Item().Text("Top blocked sites").Bold().FontSize(12); col.Item().Element(c => Bars(c, sites));
                });
            });
            foreach (var g in devs.Take(25))
                doc.Page(p =>
                {
                    p.Size(PageSizes.Letter); p.Margin(32); p.DefaultTextStyle(x => x.FontSize(9).FontFamily("Segoe UI"));
                    var first = g.First();
                    p.Header().Column(c => { c.Item().Text("Device: " + g.Key).FontSize(15).Bold().FontColor(accent); c.Item().Text($"IP {first.ClientIp}  \u00B7  MAC {(string.IsNullOrEmpty(first.Mac) ? "unknown" : first.Mac)}  \u00B7  {first.Attribution}  \u00B7  {g.Count():N0} blocks").FontSize(8.5f).FontColor(Colors.Grey.Darken1); });
                    p.Footer().AlignCenter().Text(t => { t.CurrentPageNumber().FontSize(8); });
                    p.Content().Column(col =>
                    {
                        col.Spacing(8);
                        col.Item().Element(c => Bars(c, g.GroupBy(e => e.Category).OrderByDescending(x => x.Count()).Select(x => (x.Key, x.Count())).ToList(), Col));
                        col.Item().Text("Most recent blocks").Bold().FontSize(11);
                        col.Item().Table(t =>
                        {
                            t.ColumnsDefinition(cd => { cd.ConstantColumn(78); cd.RelativeColumn(3); cd.RelativeColumn(1.4f); cd.RelativeColumn(1.2f); cd.RelativeColumn(2.2f); });
                            t.Header(h => { foreach (var s in new[] { "Time", "Domain", "Category", "App", "Blocked by" }) h.Cell().BorderBottom(0.5f).PaddingBottom(2).Text(s).Bold().FontSize(8); });
                            foreach (var e in g.Take(120))
                            {
                                t.Cell().Text(e.Time.ToString("M/d h:mm:ss tt")).FontSize(7.5f); t.Cell().Text(e.Domain).FontSize(7.5f).ClampLines(1); t.Cell().Text(e.Category).FontSize(7.5f).FontColor(Col(e.Category));
                                t.Cell().Text(e.App).FontSize(7.5f).ClampLines(1); t.Cell().Text(e.Source).FontSize(7.5f).ClampLines(1);
                            }
                        });
                    });
                });
        }).GeneratePdf(file);
        Core.Log($"block report: {ev.Count} events -> {file}");
        return file;
    }

    public static async Task<string> Make(DateTime from, DateTime to, string category = null, string device = null)
    {
        var ev = await Load(from, to);
        if (!string.IsNullOrEmpty(category) && category != "All categories") ev = ev.Where(e => e.Category == category).ToList();
        if (!string.IsNullOrEmpty(device) && device != "All devices") ev = ev.Where(e => e.Device == device).ToList();
        return Pdf(ev, from, to, "WALLACE blocked-content report" + (category is null or "All categories" ? "" : " \u2013 " + category) + (device is null or "All devices" ? "" : " \u2013 " + device));
    }

    /// <summary>Called hourly by the app: daily report after 7 AM, weekly on Mondays.</summary>
    public static async Task AutoTick()
    {
        var s = AppSettings.Current; if (s.AutoReport is not ("daily" or "weekly") || DateTime.Now.Hour < 7) return;
        if (s.LastAutoReport.Date == DateTime.Today || (s.AutoReport == "weekly" && DateTime.Today.DayOfWeek != DayOfWeek.Monday)) return;
        try { var f = await Make(DateTime.Today.AddDays(s.AutoReport == "weekly" ? -7 : -1), DateTime.Today); s.LastAutoReport = DateTime.Now; AppSettings.Save(); UI.Toast("Blocked-content report ready", f); }
        catch (Exception ex) { Core.Log("auto report: " + ex.Message); }
    }

    public static UIElement Card()
    {
        var range = new ComboBox { Width = 130, ItemsSource = new[] { "Last 24 hours", "Last 7 days", "Last 14 days", "Custom" }, SelectedIndex = 0 };
        var fromP = new DatePicker { SelectedDate = DateTime.Today.AddDays(-1), Width = 120, Visibility = Visibility.Collapsed }; var toP = new DatePicker { SelectedDate = DateTime.Today, Width = 120, Visibility = Visibility.Collapsed };
        range.SelectionChanged += (s, e) => { var v = range.SelectedIndex == 3 ? Visibility.Visible : Visibility.Collapsed; fromP.Visibility = v; toP.Visibility = v; };
        var cat = new ComboBox { Width = 150, ItemsSource = new[] { "All categories" }.Concat(AllCategories).ToList(), SelectedIndex = 0, Margin = new Thickness(8, 0, 0, 0) };
        var dev = new ComboBox { Width = 230, IsEditable = true, Text = "All devices", Margin = new Thickness(8, 0, 0, 0), ToolTip = "Type a device name exactly as shown in a report, or leave 'All devices'" };
        dev.DropDownOpened += (s, e) => dev.ItemsSource = new[] { "All devices", "WALLACE hotspot / this PC (device unknown)" }.Concat(Devices.All.Values.Select(d => d.Display)).Distinct().ToList();
        var auto = new ComboBox { Width = 110, ItemsSource = new[] { "off", "daily", "weekly" }, SelectedItem = AppSettings.Current.AutoReport, Margin = new Thickness(8, 0, 0, 0) };
        auto.SelectionChanged += (s, e) => { AppSettings.Current.AutoReport = (string)auto.SelectedItem; AppSettings.Save(); };
        var st = UI.T("PDF: who was blocked from porn, gambling, Instagram, ads, malware, trackers\u2026 with charts and per-device pages.", 12, null, UI.Sub, true);
        Button go = null;
        go = UI.Btn("Generate PDF", async () =>
        {
            go.IsEnabled = false; st.Text = "Reading AdGuard query log\u2026";
            try
            {
                DateTime to = DateTime.Now, from = range.SelectedIndex switch { 1 => to.AddDays(-7), 2 => to.AddDays(-14), 3 => fromP.SelectedDate ?? to.AddDays(-1), _ => to.AddHours(-24) };
                if (range.SelectedIndex == 3) to = (toP.SelectedDate ?? DateTime.Today).AddDays(1).AddSeconds(-1);
                var f = await Make(from, to, (string)cat.SelectedItem, dev.Text); st.Text = "Saved " + f; Core.Launch(f, "", false, true);
            }
            catch (Exception ex) { st.Text = "Failed: " + Core.Redact(ex.Message); Core.Log("block report: " + ex); }
            finally { go.IsEnabled = true; }
        }, true, "\uEA90");
        return UI.Card(UI.Col(UI.Row(UI.Icon("\uE83D", 18, UI.Accent), UI.T("  Blocked-content report (PDF)", 15, FontWeights.SemiBold)), st, new Border { Height = 8 },
            UI.Row(range, new Border { Width = 6 }, fromP, toP, cat, dev),
            UI.Row(go, new Border { Width = 8 }, UI.Btn("Open folder", () => { var d = Path.Combine(Core.ReportDir, "Blocked"); Directory.CreateDirectory(d); Core.Launch("explorer.exe", $"\"{d}\""); }, false, "\uE838"), UI.T("   Auto-report:", 12, null, UI.Sub), auto)));
    }
}
