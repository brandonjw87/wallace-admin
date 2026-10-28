using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WNH;

static class P
{
    public static UIElement Top(UIElement e) { DockPanel.SetDock(e, System.Windows.Controls.Dock.Top); return e; }
    public static DockPanel Dock(params UIElement[] topsThenFill) { var d = new DockPanel(); for (int i = 0; i < topsThenFill.Length; i++) d.Children.Add(i < topsThenFill.Length - 1 ? Top(topsThenFill[i]) : topsThenFill[i]); return d; }
    public static TextBox Viewer() { var t = UI.Box("", double.NaN, true, true); t.Background = UI.Inset; t.BorderThickness = new Thickness(0); return t; }
    public static void Center(StackPanel row) { foreach (UIElement e in row.Children) if (e is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center; }
}

// ============================== Alerts ==============================
public class AlertsPage : PageBase
{
    public override string Title => "Alerts";
    public override string Subtitle => "New devices, devices going offline, bandwidth spikes, red health tiles, monitor outages, blacklisted hosts";
    protected override UIElement Build()
    {
        var list = new ItemsControl { ItemsSource = Alerts.Feed };
        var f = new FrameworkElementFactory(typeof(Border));
        f.SetValue(Border.BackgroundProperty, UI.CardBg); f.SetValue(Border.CornerRadiusProperty, new CornerRadius(10)); f.SetValue(Border.PaddingProperty, new Thickness(14, 10, 14, 10)); f.SetValue(Border.MarginProperty, new Thickness(0, 0, 0, 8));
        var sp = new FrameworkElementFactory(typeof(DockPanel)); f.AppendChild(sp);
        var dot = new FrameworkElementFactory(typeof(System.Windows.Shapes.Ellipse)); dot.SetValue(FrameworkElement.WidthProperty, 10.0); dot.SetValue(FrameworkElement.HeightProperty, 10.0); dot.SetValue(FrameworkElement.MarginProperty, new Thickness(0, 4, 12, 0)); dot.SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Top);
        dot.SetBinding(System.Windows.Shapes.Shape.FillProperty, new System.Windows.Data.Binding("Color")); sp.AppendChild(dot);
        var time = new FrameworkElementFactory(typeof(TextBlock)); time.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("TimeText")); time.SetValue(TextBlock.ForegroundProperty, UI.Sub); time.SetValue(TextBlock.FontSizeProperty, 11.0); time.SetValue(DockPanel.DockProperty, System.Windows.Controls.Dock.Right); sp.AppendChild(time);
        var col = new FrameworkElementFactory(typeof(StackPanel)); sp.AppendChild(col);
        var t1 = new FrameworkElementFactory(typeof(TextBlock)); t1.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Title")); t1.SetValue(TextBlock.FontWeightProperty, FontWeights.SemiBold); col.AppendChild(t1);
        var t2 = new FrameworkElementFactory(typeof(TextBlock)); t2.SetBinding(TextBlock.TextProperty, new System.Windows.Data.Binding("Body")); t2.SetValue(TextBlock.ForegroundProperty, UI.Sub); t2.SetValue(TextBlock.TextWrappingProperty, TextWrapping.Wrap); col.AppendChild(t2);
        list.ItemTemplate = new DataTemplate { VisualTree = f };
        var empty = UI.T("No alerts yet. They'll appear here and as Windows notifications.", 13, null, UI.Sub);
        Alerts.Feed.CollectionChanged += (s, e) => empty.Visibility = Alerts.Feed.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        empty.Visibility = Alerts.Feed.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        var bar = UI.Row(UI.Btn("Send test notification", () => Alerts.Raise("test-" + DateTime.Now.Ticks, "blue", "Test notification", "Alerts from WALLACE Admin will look like this.", 0), true, "\uEA8F"),
            UI.Btn("Clear list", () => Alerts.Feed.Clear(), false, "\uE74D"), UI.Btn("Alert settings", () => ((MainWindow)Application.Current.MainWindow).Navigate("settings"), false, "\uE713"));
        return P.Dock(bar, empty, UI.Scroll(list));
    }
}

// ============================== Reports ==============================
public class ReportsPage : PageBase
{
    public override string Title => "Reports";
    public override string Subtitle => "Blocked-content PDF reports (by device, category, app), plus CSV / HTML exports";
    protected override UIElement Build()
    {
        UIElement Item(string glyph, string title, string text, Func<string> make) => UI.Card(UI.Col(UI.Row(UI.Icon(glyph, 18, UI.Accent), UI.T("  " + title, 15, FontWeights.SemiBold)), UI.T(text, 12, null, UI.Sub, true), new Border { Height = 10 },
            UI.Btn("Export", () => { var f = make(); UI.Toast("Report saved", f); Core.Launch("explorer.exe", $"/select,\"{f}\""); }, true, "\uEDE1")));
        var g = new System.Windows.Controls.Primitives.UniformGrid { Columns = 2 };
        g.Children.Add(Item("\uE9F9", "Full HTML report", "Health checks, live status, devices, top connections and recent alerts in one shareable page.", () => { var f = Reports.Html(Core.ReportDir); Core.Launch(f, "", false, true); return f; }));
        g.Children.Add(Item("\uE772", "Devices (CSV)", "Every device seen on the hotspot and LAN with vendor, uptime and traffic.", () => Reports.DevicesCsv(Core.ReportDir)));
        g.Children.Add(Item("\uE968", "Connections (CSV)", "Captured connections: device → remote host, owner, port, protocol, bytes. Needs Npcap.", () => Reports.Connections(Core.ReportDir)));
        g.Children.Add(Item("\uEC27", "Usage by service (CSV)", "Bytes per device per service (Netflix, YouTube, Roku telemetry…). Needs Npcap.", () => Reports.UsageCsv(Core.ReportDir)));
        return UI.Scroll(UI.Col(BlockReport.Card(), g, UI.Row(UI.Btn("Open reports folder", () => Core.Launch("explorer.exe", $"\"{Core.ReportDir}\""), false, "\uE838"), UI.T("  " + Core.ReportDir, 12, null, UI.Sub))));
    }
}

// ============================== Backups (+ CHANGES.md) ==============================
public class BackupsPage : PageBase
{
    public override string Title => "Backups";
    public override string Subtitle => "Read-only view of dev-config-backup and the CHANGES.md history (secrets redacted)";
    public record Row(string Name, string Date, string Files, string Size, string Path);
    DataGrid grid; TextBox changes;
    protected override UIElement Build()
    {
        grid = UI.Grid(UI.Col("Backup folder", "Name", 380), UI.Col("Date", "Date", 150), UI.Col("Files", "Files", 70), UI.Col("Size", "Size", 100)); grid.Height = 260;
        grid.MouseDoubleClick += (s, e) => Open();
        changes = P.Viewer();
        var bar = UI.Row(UI.Btn("Refresh", () => _ = Load(), true, "\uE72C"), UI.Btn("Open folder", Open, false, "\uE838"), UI.T("   Nothing here deletes or restores files.", 12, null, UI.Sub)); P.Center(bar);
        _ = Load();
        return P.Dock(bar, UI.Card(grid, 8), UI.T("CHANGES.md", 13, FontWeights.SemiBold, UI.Sub), UI.Card(changes, 4));
    }
    void Open() => Core.Launch("explorer.exe", "\"" + (grid.SelectedItem is Row r ? r.Path : Core.BackupRoot) + "\"");
    async Task Load()
    {
        var (rows, text) = await Task.Run(() =>
        {
            var list = new List<Row>();
            foreach (var dir in new[] { Core.BackupRoot, Path.Combine(Core.V2, "dev-config-backup") }.Where(Directory.Exists).SelectMany(r => new DirectoryInfo(r).GetDirectories()).OrderByDescending(d => d.LastWriteTime))
            {
                long size = 0; int n = 0; try { foreach (var f in dir.EnumerateFiles("*", SearchOption.AllDirectories)) { size += f.Length; n++; } } catch { }
                list.Add(new Row(dir.Name, dir.LastWriteTime.ToString("yyyy-MM-dd HH:mm"), n.ToString(), Core.Bytes(size), dir.FullName));
            }
            var cm = Path.Combine(Core.BackupRoot, "CHANGES.md");
            return (list, File.Exists(cm) ? Core.Redact(File.ReadAllText(cm)) : "CHANGES.md not found.");
        });
        grid.ItemsSource = rows; changes.Text = text;
    }
}

// ============================== Logs ==============================
public class LogsPage : PageBase
{
    public override string Title => "Logs";
    public override string Subtitle => "Watchdog, hotspot and iSponsorBlockTV logs in plain English";
    TextBox box;
    protected override UIElement Build()
    {
        box = P.Viewer();
        var bar = UI.Row(UI.Btn("Refresh logs", () => _ = Load(), true, "\uE72C"), UI.Btn("Open app logs folder", () => Core.Launch("explorer.exe", $"\"{Core.LogDir}\""), false, "\uE838"));
        _ = Load(); return P.Dock(bar, UI.Card(box, 4));
    }
    public override void OnShow() { if (box != null) _ = Load(); }
    async Task Load()
    {
        box.Text = await Task.Run(() =>
        {
            var sb = new StringBuilder();
            void Sum(string title, string path, int tail)
            {
                sb.AppendLine("■ " + title);
                if (!File.Exists(path)) { sb.AppendLine("  (not found: " + path + ")\r\n"); return; }
                string[] lines; try { using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); using var r = new StreamReader(fs); lines = r.ReadToEnd().Split('\n').Select(l => l.TrimEnd('\r')).Where(l => l.Length > 0).ToArray(); }
                catch (Exception ex) { sb.AppendLine("  could not read: " + ex.Message + "\r\n"); return; }
                var age = DateTime.Now - File.GetLastWriteTime(path);
                int warn = lines.Count(l => Regex.IsMatch(l, "WARN|UNHEALTHY|FAIL|ERROR", RegexOptions.IgnoreCase)), rep = lines.Count(l => l.Contains("REPAIR"));
                sb.AppendLine($"  In plain English: last written {(int)age.TotalMinutes} min ago; {lines.Length} lines; {warn} warning/problem lines and {rep} automatic repairs in this file.");
                var lastRepair = lines.LastOrDefault(l => l.Contains("REPAIR")); if (lastRepair != null) sb.AppendLine("  Last automatic repair: " + Core.Redact(lastRepair));
                sb.AppendLine("  Most recent lines:");
                foreach (var l in lines.Skip(Math.Max(0, lines.Length - tail))) sb.AppendLine("    " + Core.Redact(l));
                sb.AppendLine();
            }
            Sum("WALLACE watchdog (self-repair every 3 min)", Path.Combine(Core.V2, @"logs\watchdog.log"), 15);
            Sum("Hotspot starter", Path.Combine(Core.V2, @"logs\start-hotspot.log"), 8);
            Sum("iSponsorBlockTV errors", Path.Combine(Core.Tools, @"isponsorblocktv\err.log"), 5);
            Sum("This app (WALLACE Admin)", Path.Combine(Core.LogDir, $"app-{DateTime.Now:yyyyMMdd}.log"), 25);
            return sb.ToString();
        });
    }
}

// ============================== Updates ==============================
public class UpdatesPage : PageBase
{
    public override string Title => "Updates";
    public override string Subtitle => "Encrypted DNS status + GitHub update checks (apply only with backup + rollback)";
    protected override UIElement Build()
    {
        var grid = UI.Grid(UI.Col("Item", "Item", 180), UI.Col("Installed / local", "Installed", 260), UI.Col("Latest", "Latest", 330), UI.Col("Verdict", "Verdict", 300));
        var wu = new CheckBox { Content = "Include Windows Update (slow, read-only)", IsChecked = false, Margin = new Thickness(8, 0, 0, 0) };
        var info = UI.T("", 12, null, UI.Sub);
        Button b = null;
        b = UI.Btn("Check for updates", async () =>
        {
            b.IsEnabled = false; info.Text = "   checking GitHub…";
            try { grid.ItemsSource = await Core.CheckUpdates(wu.IsChecked == true); info.Text = $"   checked {DateTime.Now:t}"; }
            catch (Exception ex) { info.Text = "   failed: " + ex.Message; }
            finally { b.IsEnabled = true; }
        }, true, "\uE895");
        var bar = UI.Row(b, wu, info); P.Center(bar);
        // 3.4.0: refreshed blocklist sources by category with last-updated dates (live from AdGuard filtering/status)
        var src = UI.Grid(UI.Col("Category", "Category", 150), UI.Col("List", "Name", 300), UI.Col("Rules", "Rules", 90), UI.Col("Last updated", "Updated", 140), UI.Col("Source", "Url", 420));
        var srcInfo = UI.T("   loading blocklist sources…", 12, null, UI.Sub);
        async Task LoadSources() { try { var rows = await BlocklistSources.Load(); src.ItemsSource = rows; srcInfo.Text = $"   {rows.Count} enabled lists, {rows.Sum(r => r.RuleCount):N0} rules (read {DateTime.Now:t})"; } catch (Exception ex) { srcInfo.Text = "   sources unavailable: " + ex.Message; } }
        _ = LoadSources();
        var srcBar = UI.Row(UI.T("Blocklist sources", 15), UI.Btn("Reload", () => _ = LoadSources(), false, "\uE72C"), srcInfo); P.Center(srcBar);
        return P.Dock(EncryptionPanel.Build(), new Border { Height = 10 }, srcBar, UI.Card(src, 8), new Border { Height = 10 }, bar, UI.Card(grid, 8));
    }
}

// ============================== Research ==============================
public class ResearchPage : PageBase
{
    public override string Title => "Research";
    public override string Subtitle => "Find open-source projects for any layer, or hand the job to Grok Bot";
    public record Row(string Name, string Stars, string Updated, string About, string Url);
    protected override UIElement Build()
    {
        var topic = UI.Box("home network monitoring", 300);
        var grid = UI.Grid(UI.Col("Project", "Name", 260), UI.Col("★", "Stars", 80), UI.Col("Updated", "Updated", 100), UI.Col("What it is", "About", 640));
        grid.MouseDoubleClick += (s, e) => { if (grid.SelectedItem is Row r) Core.Launch(r.Url, "", false, true); };
        var info = UI.T("", 12, null, UI.Sub);
        async Task Search()
        {
            info.Text = "  searching…";
            try
            {
                var j = await Core.Http.GetStringAsync("https://api.github.com/search/repositories?sort=stars&order=desc&per_page=30&q=" + Uri.EscapeDataString(topic.Text + " pushed:>" + DateTime.UtcNow.AddMonths(-12).ToString("yyyy-MM-dd")));
                using var d = JsonDocument.Parse(j);
                grid.ItemsSource = d.RootElement.GetProperty("items").EnumerateArray().Select(r => new Row(r.GetProperty("full_name").GetString(), r.GetProperty("stargazers_count").GetInt32().ToString("N0"), r.GetProperty("pushed_at").GetDateTime().ToString("yyyy-MM-dd"), r.TryGetProperty("description", out var de) ? de.ToString() : "", r.GetProperty("html_url").GetString())).ToList();
                info.Text = "  double-click a row to open it";
            }
            catch (Exception ex) { info.Text = "  search failed: " + ex.Message; }
        }
        topic.KeyDown += (s, e) => { if (e.Key == System.Windows.Input.Key.Enter) _ = Search(); };
        var chips = new WrapPanel { Margin = new Thickness(0, 0, 0, 10) };
        foreach (var t in new[] { "dns adblock", "adguard home blocklist", "youtube sponsorblock tv", "roku", "home network monitoring", "network traffic monitor", "uptime monitor self-hosted", "windows hotspot" })
        {
            var c = new Border { CornerRadius = new CornerRadius(12), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 6, 6), Background = UI.CardHover, Child = UI.T(t, 12), Cursor = System.Windows.Input.Cursors.Hand };
            c.MouseLeftButtonUp += (s, e) => { topic.Text = t; _ = Search(); }; chips.Children.Add(c);
        }
        var bar = UI.Row(topic, new Border { Width = 8 }, UI.Btn("Search GitHub", () => _ = Search(), true, "\uE721"), UI.Btn("Ask Grok Bot to research + install…", () => AskGrokBot(topic.Text), false, "\uE8BD"), info); P.Center(bar);
        var how = UI.T("How this works: 'Search GitHub' lists popular, recently updated projects. This app never installs software by itself. 'Ask Grok Bot' copies a ready-made request to your clipboard and opens Grok Bot — paste it into the chat and Grok Bot researches, backs up, and installs only with your OK.", 12, null, UI.Sub, true);
        return P.Dock(bar, chips, how, UI.Card(grid, 8));
    }
    static void AskGrokBot(string topic)
    {
        string last;
        try { last = string.Join("; ", Health.Checks.Where(c => c.Status != "Green").Select(c => $"{c.Name}: {c.Detail}")); if (last == "") last = "(all green)"; } catch { last = "(no recent check)"; }
        var prompt = $"Research better tools for my home network layers (topic: {topic}). My setup: AdGuard Home DNS on 127.0.0.1 with HaGeZi lists, WALLACE Windows hotspot 192.0.2.11 for Roku/LG TVs, iSponsorBlockTV, Uptime Kuma, Open DHCP Server, Wallace-Roku v2 watchdog, WALLACE Admin (Windows monitor app). The hotspot runs on the Intel Wireless-AC 9462 (Wi-Fi 5, 5 GHz); the TP-Link Archer TX20U Plus (Wi-Fi 6) cannot host it with its current driver. Current non-green checks: {last}. Compare 3-5 options, tell me which one is worth it, then back up first and install only after I say yes. Never touch secrets or EverydayOfEvey.";
        try { Clipboard.SetText(prompt); } catch { }
        var exe = new[] { @"C:\Program Files\Grok Bot\Grok Bot.exe", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), @"Programs\Grok Bot\Grok Bot.exe") }.FirstOrDefault(File.Exists);
        if (exe != null) Core.Launch(exe, "", false, true);
        MessageBox.Show("A research request was copied to your clipboard.\n\nPaste it (Ctrl+V) into the Grok Bot chat.\n\nThis app can't send it for you and never installs software on its own.", "Ask Grok Bot");
    }
}

// ============================== Repairs ==============================
public class RepairsPage : PageBase
{
    public override string Title => "Repairs";
    public override string Subtitle => "One-click fixes. Each asks before doing anything.";
    protected override UIElement Build()
    {
        var g = new System.Windows.Controls.Primitives.UniformGrid { Columns = 2 };
        void Add(string glyph, string text, string help, Action a, bool confirm = true)
        {
            var btn = UI.Btn(text, () => { if (!confirm || MessageBox.Show(help + "\n\nContinue?", text, MessageBoxButton.YesNo) == MessageBoxResult.Yes) a(); }, true, glyph);
            btn.HorizontalAlignment = HorizontalAlignment.Left;
            g.Children.Add(UI.Card(UI.Col(btn, new Border { Height = 8 }, UI.T(help, 12, null, UI.Sub, true))));
        }
        Add("\uE701", "Restart hotspot", "Runs your tested start-hotspot.ps1. TVs drop off Wi-Fi for ~10 seconds and reconnect. No admin needed.", () => Core.Launch("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{Path.Combine(Core.V2, "start-hotspot.ps1")}\""));
        Add("\uE768", "Restart iSponsorBlockTV", "Stops and restarts the YouTube skipper using its normal hidden launcher.", () => Task.Run(() =>
        {
            foreach (var pr in Process.GetProcessesByName("iSponsorBlockTV")) try { pr.Kill(); pr.WaitForExit(5000); } catch { }
            Core.Launch("wscript.exe", $"\"{Path.Combine(Core.Tools, @"isponsorblocktv\run-hidden.vbs")}\"");
        }));
        Add("\uE7EF", "Restart AdGuard Home (admin)", "Windows will ask for admin permission (UAC) once. DNS pauses for a few seconds.", () =>
        { try { Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -WindowStyle Hidden -Command Restart-Service AdGuardHome -Force") { UseShellExecute = true, Verb = "runas" }); } catch (Exception ex) { UI.Toast("Not restarted", ex.Message); } });
        Add("\uE968", "Sniffnet (safe mode)", "Starts Sniffnet with software rendering (ICED_BACKEND=tiny-skia). Needs Npcap installed first.", () => Core.Launch(Path.Combine(Core.Tools, @"sniffnet-launch\Sniffnet-safe.cmd"), "", false, true), false);
        Add("\uE774", "Open AdGuard Home dashboard", "Opens http://127.0.0.1:3000 in your browser.", () => Core.Launch("http://127.0.0.1:3000", "", false, true), false);
        Add("\uE9D9", "Open Uptime Kuma", "Opens http://127.0.0.1:3001 in your browser.", () => Core.Launch("http://127.0.0.1:3001", "", false, true), false);
        Add("\uE838", "Open Tools folder", "Opens C:\\Users\\YOU\\Tools in Explorer.", () => Core.Launch("explorer.exe", "\"" + Core.Tools + "\""), false);
        return UI.Scroll(g);
    }
}

// ============================== Settings ==============================
public class SettingsPage : PageBase
{
    public override string Title => "Settings";
    public override string Subtitle => "Alert thresholds, blacklist, live checks and appearance";
    protected override UIElement Build()
    {
        var s = AppSettings.Current;
        CheckBox Tog(string text, bool v) => new() { Content = text, IsChecked = v };
        TextBox Num(double v) => UI.Box(v.ToString(), 70);
        var aNew = Tog("New device joins the hotspot or LAN", s.AlertNewDevice); var aOff = Tog("Device goes offline", s.AlertDeviceOffline); var aRed = Tog("Health tile turns red", s.AlertHealthRed);
        var aMon = Tog("Live status check goes down", s.AlertMonitorDown); var aBw = Tog("Bandwidth above threshold", s.AlertBandwidth); var aBl = Tog("Device contacts a blacklisted host", s.AlertBlacklist); var aNh = Tog("Device contacts a new remote host (chatty)", s.AlertNewHost);
        var bw = Num(s.BandwidthMbps); var bws = Num(s.BandwidthSeconds); var off = Num(s.OfflineMinutes); var scan = Num(s.ScanSeconds); var mon = Num(s.MonitorSeconds); var rc = Num(s.RecheckMinutes);
        var auto = Tog("Auto recheck health", s.AutoRecheck); var tr = Tog("Translucent window (Mica, Windows 11) — restart app to apply", s.Translucent); var eth = Tog("Also capture the Ethernet adapter (this PC's own traffic)", s.CaptureEthernetToo);
        var startup = Tog("Start WALLACE Admin when I sign in", File.Exists(StartupLnk));
        var bl = UI.Box(string.Join("\r\n", s.Blacklist), double.NaN, true); bl.Height = 150;
        var mons = UI.Box(string.Join("\r\n", s.Monitors.Select(m => $"{m.Name} | {m.Type} | {m.Target}")), double.NaN, true); mons.Height = 200;
        UIElement Line(string label, TextBox box, string unit) { var r = UI.Row(UI.T(label, 13), new Border { Width = 10 }, box, UI.T("  " + unit, 12, null, UI.Sub)); r.Margin = new Thickness(0, 4, 0, 4); P.Center(r); return r; }
        var status = UI.T("", 12, null, UI.Green);
        var save = UI.Btn("Save settings", () =>
        {
            double D(TextBox t, double min, double max, double dflt) => double.TryParse(t.Text, out var v) ? Math.Clamp(v, min, max) : dflt;
            s.AlertNewDevice = aNew.IsChecked == true; s.AlertDeviceOffline = aOff.IsChecked == true; s.AlertHealthRed = aRed.IsChecked == true; s.AlertMonitorDown = aMon.IsChecked == true;
            s.AlertBandwidth = aBw.IsChecked == true; s.AlertBlacklist = aBl.IsChecked == true; s.AlertNewHost = aNh.IsChecked == true;
            s.BandwidthMbps = D(bw, 1, 10000, 80); s.BandwidthSeconds = (int)D(bws, 1, 600, 10); s.OfflineMinutes = (int)D(off, 1, 120, 3);
            s.ScanSeconds = (int)D(scan, 20, 3600, 60); s.MonitorSeconds = (int)D(mon, 10, 3600, 30); s.RecheckMinutes = (int)D(rc, 1, 240, 5);
            s.AutoRecheck = auto.IsChecked == true; s.Translucent = tr.IsChecked == true; s.CaptureEthernetToo = eth.IsChecked == true;
            s.Blacklist = bl.Text.Replace("\r", "").Split('\n').Select(x => x.Trim()).Where(x => x.Length > 0).ToList();
            var newMons = new List<MonitorDef>(); var bad = new List<string>();
            foreach (var l in mons.Text.Replace("\r", "").Split('\n').Where(x => x.Trim().Length > 0))
            {
                var p = l.Split('|').Select(x => x.Trim()).ToArray();
                if (p.Length == 3 && p[1] is "ping" or "tcp" or "http" && (p[1] != "tcp" || p[2].Contains(':'))) { var old = s.Monitors.FirstOrDefault(m => m.Name == p[0] && m.Type == p[1] && m.Target == p[2]); newMons.Add(old ?? new MonitorDef { Name = p[0], Type = p[1], Target = p[2] }); }
                else bad.Add(l);
            }
            s.Monitors = newMons;
            try { SetStartup(startup.IsChecked == true); } catch (Exception ex) { bad.Add("startup: " + ex.Message); }
            AppSettings.RaiseChanged();
            status.Text = bad.Count == 0 ? $"  Saved {DateTime.Now:t}" : "  Saved, but skipped: " + string.Join("; ", bad); status.Foreground = bad.Count == 0 ? UI.Green : UI.Yellow;
        }, true, "\uE74E");
        var col = UI.Col(
            UI.Card(UI.Col(UI.H("Notifications"), aNew, aOff, aRed, aMon, aBw, Line("   Threshold", bw, "Mbps (in + out) for"), Line("   Sustained", bws, "seconds"), aBl, aNh, Line("Offline after", off, "minutes unseen"))),
            UI.Card(UI.Col(UI.H("Blacklist"), UI.T("One per line: an IP (1.2.3.4), a CIDR range (1.2.3.0/24) or part of a host name (ads.example.com). Lines starting with # are comments.", 12, null, UI.Sub, true), new Border { Height = 6 }, bl)),
            UI.Card(UI.Col(UI.H("Live status checks"), UI.T("One per line:  Name | ping|tcp|http | target   (tcp target is host:port, http target is a URL)", 12, null, UI.Sub, true), new Border { Height = 6 }, mons)),
            UI.Card(UI.Col(UI.H("Timing"), Line("Device scan every", scan, "seconds"), Line("Live checks every", mon, "seconds"), auto, Line("Health recheck every", rc, "minutes"))),
            UI.Card(UI.Col(UI.H("App"), tr, eth, startup)),
            UI.Row(save, status));
        P.Center((StackPanel)col.Children[^1]);
        return UI.Scroll(col);
    }
    static string StartupLnk => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Startup), "WALLACE Admin.lnk");
    static void SetStartup(bool on)
    {
        if (!on) { if (File.Exists(StartupLnk)) File.Delete(StartupLnk); return; }
        if (File.Exists(StartupLnk)) return;
        var t = Type.GetTypeFromProgID("WScript.Shell"); dynamic sh = Activator.CreateInstance(t);
        var lnk = sh.CreateShortcut(StartupLnk); lnk.TargetPath = Environment.ProcessPath; lnk.Save();
    }
}

// ============================== About ==============================
public class AboutPage : PageBase
{
    public override string Title => "About";
    public override string Subtitle => $"WALLACE Admin {Core.Version} · built for Brandon Wallace";
    protected override UIElement Build()
    {
        var v = P.Viewer(); v.Height = 260;
        v.Text = "==== Sniffnet (MIT / Apache-2.0) ====\r\n" + Core.ResText("lic-sniffnet") + "\r\n\r\n==== homelable (MIT) ====\r\n" + Core.ResText("lic-homelable");
        string credits =
@"Live Traffic, service/port naming and the packet parsing approach are ported from Sniffnet by Giuliano Bellini (github.com/GyulyVGC/sniffnet) — MIT/Apache-2.0. Port names use Sniffnet's services list.
Live Status timelines and the Network Map are inspired by homelable by Remy Jardinet (github.com/Pouzor/homelable) — MIT.
IP owner (ASN) and country data: GeoLite2 by MaxMind, distributed with Sniffnet — CC BY-SA 4.0 (maxmind.com).
MAC vendors: IEEE OUI registry (offline copy, " + Oui.Count.ToString("N0") + @" entries).
Libraries: SharpPcap (MIT), PacketDotNet, MaxMind.Db (Apache-2.0), Microsoft.Toolkit.Uwp.Notifications (MIT), .NET 8 / WPF (MIT).
Packet capture uses Npcap (npcap.com) — installed separately, free for personal use.";
        var info = UI.Col(UI.Row(UI.Icon("\uE946", 18, UI.Accent), UI.T($"  Npcap: {(NpcapInfo.Installed ? "installed " + NpcapInfo.Version : "not installed")} · Toasts: {(Alerts.ToastsWork ? "on" : "unavailable")} · Data: {Core.DataDir}", 12, null, UI.Sub)));
        return UI.Scroll(UI.Col(UI.Card(UI.Col(UI.H("Credits & licenses"), UI.T(credits, 12.5, null, UI.Text, true))), UI.Card(info), UI.Card(v, 4)));
    }
}

public static class BlocklistSources
{
    public record Row(string Category, string Name, string Rules, string Updated, string Url, long RuleCount);
    public static string Cat(string n)
    {
        n ??= ""; var m = Regex.Match(n, @"\[(\w+)\]");
        if (m.Success) return m.Groups[1].Value switch { "ads" => "Ads/trackers", "malware" => "Malware/phishing", "crypto" => "Crypto-mining", "gambling" => "Gambling", "strict" => "Ads/trackers (strict)", var x => x };
        if (n.StartsWith("Safe Guard:")) return "Adult/NSFW";
        if (n.Contains("DoH") || n.Contains("Bypass")) return "DNS bypass";
        return "Smart TV/device";
    }
    public static async Task<List<Row>> Load()
    {
        var f = (await SafeGuard.Get("filtering/status"))["filters"]?.AsArray() ?? new System.Text.Json.Nodes.JsonArray();
        return f.Where(x => (bool?)x?["enabled"] == true).Select(x =>
        {
            var n = (string)x["name"] ?? ""; long rc = (long?)x["rules_count"] ?? 0; var lu = (string)x["last_updated"];
            var d = DateTime.TryParse(lu, out var t) ? t.ToString("yyyy-MM-dd HH:mm") : "never";
            return new Row(Cat(n), n.Replace("Safe Guard+ ", "").Replace("Safe Guard: ", ""), rc.ToString("N0"), d, (string)x["url"] ?? "", rc);
        }).OrderBy(r => r.Category).ThenBy(r => r.Name).ToList();
    }
}