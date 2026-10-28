using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Shapes;

namespace WNH;

static class GridX
{
    public static DataGridTemplateColumn DotCol(string brushPath = "Dot")
    {
        var f = new FrameworkElementFactory(typeof(Ellipse));
        f.SetValue(FrameworkElement.WidthProperty, 9.0); f.SetValue(FrameworkElement.HeightProperty, 9.0);
        f.SetBinding(Shape.FillProperty, new System.Windows.Data.Binding(brushPath));
        return new DataGridTemplateColumn { Header = "", Width = new DataGridLength(26), CellTemplate = new DataTemplate { VisualTree = f } };
    }
    public static void Keep(DataGrid g, System.Collections.IEnumerable items, Func<object, string> key)
    {
        var sel = g.SelectedItem != null ? key(g.SelectedItem) : null;
        g.ItemsSource = items;
        if (sel != null) foreach (var i in items) if (key(i) == sel) { g.SelectedItem = i; break; }
    }
}

// ============================== Dashboard ==============================
public class DashboardPage : PageBase
{
    public override string Title => "Dashboard";
    public override string Subtitle => "Every layer of the Wallace network in plain English";
    readonly WrapPanel tiles = new(); readonly TextBlock sum = UI.T("", 20, FontWeights.SemiBold), when = UI.T("", 12, null, UI.Sub);
    readonly Ellipse bigDot = new() { Width = 22, Height = 22, Margin = new Thickness(0, 0, 14, 0) };
    readonly TextBlock sInternet = UI.T("—", 20, FontWeights.SemiBold), sDevices = UI.T("—", 20, FontWeights.SemiBold), sRate = UI.T("—", 20, FontWeights.SemiBold), sCapture = UI.T("—", 15, FontWeights.SemiBold);
    readonly TextBlock sInternetSub = UI.T("", 11, null, UI.Sub), sDevicesSub = UI.T("", 11, null, UI.Sub), sRateSub = UI.T("hotspot ↓ / ↑", 11, null, UI.Sub), sCaptureSub = UI.T("", 11, null, UI.Sub, true);
    Button recheck; Action renderHost;

    protected override UIElement Build()
    {
        var hostCard = Wallace.HostCard(out renderHost);
        Wallace.Changed += () => Application.Current?.Dispatcher.BeginInvoke(() => renderHost());
        recheck = UI.Btn("Recheck everything", () => _ = Health.Recheck(), true, "\uE72C");
        var auto = new CheckBox { Content = "Auto recheck", IsChecked = AppSettings.Current.AutoRecheck, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        auto.Click += (s, e) => { AppSettings.Current.AutoRecheck = auto.IsChecked == true; AppSettings.RaiseChanged(); };
        var hero = new DockPanel();
        var left = UI.Row(bigDot, UI.Col(sum, when)); left.Margin = new Thickness(0);
        var right = UI.Row(recheck, UI.Btn("Run status.ps1", () => Core.Launch("powershell.exe", $"-NoExit -NoProfile -ExecutionPolicy Bypass -File \"{System.IO.Path.Combine(Core.V2, "status.ps1")}\"", true), false, "\uE756"), auto);
        right.Margin = new Thickness(0); DockPanel.SetDock(right, Dock.Right); hero.Children.Add(right); hero.Children.Add(left);

        var stats = new UniformGrid { Columns = 4, Margin = new Thickness(0) };
        stats.Children.Add(Stat("\uE774", "#0A84FF", "Internet", sInternet, sInternetSub));
        stats.Children.Add(Stat("\uE772", "#FF9F0A", "Hotspot devices", sDevices, sDevicesSub));
        stats.Children.Add(Stat("\uEC27", "#64D2FF", "Live throughput", sRate, sRateSub));
        stats.Children.Add(Stat("\uE968", "#BF5AF2", "Packet capture", sCapture, sCaptureSub));
        Health.Changed += () => Application.Current.Dispatcher.BeginInvoke(Render);
        Render();
        return UI.Scroll(UI.Col(UI.Card(hero, 18), hostCard, stats, tiles));
    }

    static Border Stat(string glyph, string color, string label, TextBlock value, TextBlock sub)
    {
        var ic = new Border { Width = 28, Height = 28, CornerRadius = new CornerRadius(8), Background = UI.B(UI.C(color)), Child = UI.Icon(glyph, 14, Brushes.White), HorizontalAlignment = HorizontalAlignment.Left, Margin = new Thickness(0, 0, 0, 10) };
        ((TextBlock)ic.Child).HorizontalAlignment = HorizontalAlignment.Center;
        return UI.Card(UI.Col(ic, UI.T(label, 12, null, UI.Sub), value, sub));
    }

    void Render()
    {
        recheck.IsEnabled = !Health.Busy;
        bigDot.Fill = UI.StatusBrush(Health.Overall);
        sum.Text = Health.Busy && Health.Checks.Count == 0 ? "Checking every layer…" : Health.Summary;
        when.Text = Health.Busy ? "Checking now… (10–40 s)" : Health.Error != null ? "Last check failed: " + Health.Error : Health.LastRun == default ? "" : $"Last check {Health.LastRun:h:mm:ss tt}";
        tiles.Children.Clear();
        foreach (var g in Health.Checks.GroupBy(c => c.Layer))
        {
            var hdr = UI.T(g.Key, 15, FontWeights.SemiBold, UI.Sub); hdr.Margin = new Thickness(2, 8, 0, 8);
            tiles.Children.Add(new WrapBreak(hdr));
            foreach (var c in g) tiles.Children.Add(Tile(c));
        }
        UI.FadeIn(tiles, 6);
    }

    static UIElement Tile(Check c)
    {
        var word = c.Status switch { "Green" => "OK", "Yellow" => "CHECK", "Red" => "PROBLEM", _ => "N/A" };
        var pill = new Border { CornerRadius = new CornerRadius(9), Padding = new Thickness(8, 1, 8, 1), Background = UI.B(Color.FromArgb(50, UI.StatusBrush(c.Status).Color.R, UI.StatusBrush(c.Status).Color.G, UI.StatusBrush(c.Status).Color.B)), Child = UI.T(word, 10.5, FontWeights.SemiBold, UI.StatusBrush(c.Status)), HorizontalAlignment = HorizontalAlignment.Right };
        var top = new DockPanel(); DockPanel.SetDock(pill, Dock.Right); top.Children.Add(pill); top.Children.Add(UI.Row(UI.Dot(UI.StatusBrush(c.Status)), UI.T(c.Name, 13.5, FontWeights.SemiBold)));
        ((StackPanel)top.Children[1]).Margin = new Thickness(0);
        var d = UI.T(c.Detail, 12, null, UI.Text, true); d.MaxHeight = 34; d.Margin = new Thickness(0, 6, 0, 4);
        var x = UI.T(c.Explain, 11.5, null, UI.Sub, true); x.FontStyle = FontStyles.Italic; x.MaxHeight = 32;
        var card = UI.Card(UI.Col(top, d, x), 14); card.Width = 290; card.Height = 128;
        card.ToolTip = $"{c.Name}\n{c.Detail}\n\n{c.Explain}";
        return card;
    }

    public override void Tick()
    {
        var m = Monitors.Find("1.1.1.1");
        if (m != null) { sInternet.Text = m.Up == true ? "Online" : m.Up == false ? "OFFLINE" : "…"; sInternet.Foreground = m.Up == false ? UI.Red : UI.Text; sInternetSub.Text = m.Ms >= 0 ? $"{m.Ms:0} ms to Cloudflare · {m.UptimePct:0}% up" : m.Note; }
        var hs = Devices.All.Values.Where(d => d.Online && d.Network == "Hotspot").ToList();
        sDevices.Text = hs.Count.ToString(); sDevicesSub.Text = string.Join(", ", hs.Select(d => d.Display).Take(3)) + (hs.Count > 3 ? "…" : "");
        lock (Bandwidth.Gate) { var s = Bandwidth.Series["hotspot"]; sRate.Text = s.Present ? $"{Core.Rate(s.CurOut)} / {Core.Rate(s.CurIn)}" : "hotspot off"; }
        sCapture.Text = Capture.Running ? (Capture.Paused ? "Paused" : "Live") : NpcapInfo.Installed ? "Not running" : "Needs Npcap";
        sCapture.Foreground = Capture.Running ? UI.Green : UI.Yellow;
        sCaptureSub.Text = Capture.Running ? $"{Capture.Packets:N0} packets · {Capture.Conns.Count:N0} connections" : Capture.Status;
    }
}

/// <summary>Forces a line break in a WrapPanel (used for section headers).</summary>
public class WrapBreak : Border
{
    public WrapBreak(UIElement child) { Child = child; }
    protected override Size MeasureOverride(Size c) { base.MeasureOverride(c); return new Size(double.IsInfinity(c.Width) ? 1200 : c.Width, 34); }
}

// ============================== Live Status (homelable-style) ==============================
public class StatusPage : PageBase
{
    public override string Title => "Live Status";
    public override string Subtitle => "Ping / TCP / HTTP checks with an up-down history timeline (idea from homelable)";
    readonly StackPanel rows = new(); readonly TextBlock info = UI.T("", 12, null, UI.Sub);
    readonly Dictionary<MonitorState, (Ellipse dot, TextBlock ms, TextBlock up, TextBlock note, Timeline tl)> map = new();

    protected override UIElement Build()
    {
        var bar = UI.Row(UI.Btn("Check now", () => _ = Monitors.RunAllAsync(), true, "\uE72C"), UI.Btn("Edit checks", () => ((MainWindow)Application.Current.MainWindow).Navigate("settings"), false, "\uE70F"), info);
        info.VerticalAlignment = VerticalAlignment.Center;
        return new DockPanel { Children = { Dock(bar), UI.Scroll(rows) } };
    }
    static UIElement Dock(UIElement e) { DockPanel.SetDock(e, System.Windows.Controls.Dock.Top); return e; }

    public override void Tick()
    {
        List<MonitorState> list; lock (Monitors.Gate) list = Monitors.States.ToList();
        if (list.Count != map.Count || list.Any(s => !map.ContainsKey(s))) Rebuild(list);
        lock (Monitors.Gate)
            foreach (var s in list)
            {
                var (dot, ms, up, note, tl) = map[s];
                dot.Fill = s.Up == true ? UI.Green : s.Up == false ? UI.Red : UI.Gray;
                ms.Text = s.Ms >= 0 ? $"{s.Ms:0} ms" : "—"; up.Text = s.History.Count > 0 ? $"{s.UptimePct:0.#}% up" : ""; note.Text = s.Note;
                tl.Points = s.History.Select(p => (bool?)p.Up).ToList(); tl.InvalidateVisual();
            }
        info.Text = $"   every {AppSettings.Current.MonitorSeconds}s · {list.Count(s => s.Up == true)}/{list.Count} up";
    }

    void Rebuild(List<MonitorState> list)
    {
        rows.Children.Clear(); map.Clear();
        foreach (var s in list)
        {
            var g = new Grid(); foreach (var w in new[] { 24.0, 260, 90, 90, 160 }) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w) }); g.ColumnDefinitions.Add(new ColumnDefinition());
            var dot = UI.Dot(UI.Gray, 11); var name = UI.Col(UI.T(s.Def.Name, 13.5, FontWeights.SemiBold), UI.T($"{s.Def.Type.ToUpper()}  {s.Def.Target}", 11, null, UI.Sub));
            var ms = UI.T("", 13); var up = UI.T("", 12, null, UI.Sub); var note = UI.T("", 11, null, UI.Sub); var tl = new Timeline { Slots = Monitors.Keep, VerticalAlignment = VerticalAlignment.Center, Height = 20 };
            UIElement[] cells = { dot, name, ms, up, note, tl };
            for (int i = 0; i < cells.Length; i++) { Grid.SetColumn(cells[i], i); if (cells[i] is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center; g.Children.Add(cells[i]); }
            var card = UI.Card(g, 12); card.Margin = new Thickness(0, 0, 0, 8); rows.Children.Add(card);
            map[s] = (dot, ms, up, note, tl);
        }
    }
}

// ============================== Live Traffic (Sniffnet-style) ==============================
public class TrafficPage : PageBase
{
    public override string Title => "Live Traffic";
    public override string Subtitle => "Who is talking to what on the WALLACE hotspot (capture ideas from Sniffnet)";
    readonly ContentControl body = new();
    readonly TextBlock status = UI.T("", 12, null, UI.Sub, true);
    TextBox filter, port; string proto = "All"; Button pauseBtn; DataGrid devGrid, connGrid; int n;
    record DevRow(string Mac, string Device, string Adapter, string RateUp, string RateDown, string Up, string Down);
    public record ConnRow(string Key, string Device, string Service, string Host, string Owner, string Country, string Port, string Proto, string Up, string Down, string Last, long Total);

    protected override UIElement Build() { Rebuild(); return body; }

    void Rebuild() { body.Content = NpcapInfo.Installed ? Live() : InstallCard(); }

    UIElement InstallCard()
    {
        var inst = NpcapInfo.DesktopInstaller;
        var text = UI.Col(
            UI.Row(UI.Icon("\uE7BA", 22, UI.Yellow), UI.T("   Install Npcap to see live traffic", 18, FontWeights.SemiBold)),
            UI.T("Live Traffic (and Sniffnet) read packets through the free Npcap capture driver, which isn't installed yet. Everything else in this app works without it.", 13, null, UI.Sub, true),
            UI.T("\nWhen the Npcap installer opens:\n  • Leave “Restrict Npcap driver's access to Administrators only” UNCHECKED (so this app can capture without admin).\n  • Keep “Install Npcap in WinPcap API-compatible Mode” checked (Sniffnet needs it).\n  • Windows will ask for admin permission once — that's Npcap's own installer.", 13, null, UI.Text, true),
            new Border { Height = 14 },
            UI.Row(UI.Btn(inst != null ? "Install Npcap (from your Desktop)" : "Download Npcap", () => { if (inst != null) Core.Launch(inst, "", false, true); else Core.Launch("https://npcap.com/#download", "", false, true); }, true, "\uE896"),
                   UI.Btn("I've installed it — start capture", () => { Task.Run(Capture.Start).ContinueWith(_ => Application.Current.Dispatcher.BeginInvoke(Rebuild)); }, false, "\uE72C"),
                   UI.Btn("npcap.com", () => Core.Launch("https://npcap.com", "", false, true))));
        var c = UI.Card(text, 24); c.MaxWidth = 820; c.HorizontalAlignment = HorizontalAlignment.Left;
        return UI.Scroll(c);
    }

    UIElement Live()
    {
        filter = UI.Box("", 220); port = UI.Box("", 70);
        pauseBtn = UI.Btn(Capture.Paused ? "Resume" : "Pause", () => { Capture.Paused = !Capture.Paused; Rebuild(); }, false, Capture.Paused ? "\uE768" : "\uE769");
        var chips = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
        foreach (var p in new[] { "All", "TCP", "UDP", "Other" })
        {
            var b = new Border { CornerRadius = new CornerRadius(12), Padding = new Thickness(12, 4, 12, 4), Margin = new Thickness(0, 0, 6, 0), Cursor = System.Windows.Input.Cursors.Hand, Child = UI.T(p, 12), Background = p == proto ? UI.Accent : UI.CardHover };
            b.MouseLeftButtonUp += (s, e) => { proto = p; foreach (Border x in chips.Children) x.Background = ((TextBlock)x.Child).Text == proto ? UI.Accent : UI.CardHover; Refresh(); };
            chips.Children.Add(b);
        }
        filter.TextChanged += (s, e) => Refresh(); port.TextChanged += (s, e) => Refresh();
        var bar = UI.Row(pauseBtn, UI.Btn("Clear", () => { Capture.Clear(); Refresh(); }, false, "\uE74D"),
            UI.T("  Filter ", 12, null, UI.Sub), filter, UI.T("  Port ", 12, null, UI.Sub), port, new Border { Width = 12 }, chips,
            UI.Btn("Export CSV", () => { var f = Reports.Connections(Core.ReportDir); UI.Toast("Exported", f); Core.Launch("explorer.exe", $"/select,\"{f}\""); }, false, "\uEDE1"));
        foreach (UIElement e in bar.Children) if (e is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center;
        var restart = UI.Btn("Restart capture", () => { Capture.Stop(); Task.Run(Capture.Start); }, false, "\uE72C");
        var st = UI.Row(status, restart); status.VerticalAlignment = VerticalAlignment.Center; status.MaxWidth = 800;

        devGrid = UI.Grid(UI.Col("Device", "Device", 260), UI.Col("Adapter", "Adapter", 90), UI.Col("Upload now", "RateUp", 110), UI.Col("Download now", "RateDown", 120), UI.Col("Uploaded", "Up", 100), UI.Col("Downloaded", "Down", 110));
        devGrid.Height = 170; devGrid.SelectionChanged += (s, e) => { if (devGrid.SelectedItem is DevRow d && filter.Text != d.Device) filter.Text = d.Device.Split(" (")[0]; };
        connGrid = UI.Grid(UI.Col("Device", "Device", 190), UI.Col("Service", "Service", 120), UI.Col("Remote host", "Host", 250), UI.Col("Owner (ASN)", "Owner", 170), UI.Col("CC", "Country", 40),
            UI.Col("Port", "Port", 110), UI.Col("Proto", "Proto", 60), UI.Col("↑", "Up", 80), UI.Col("↓", "Down", 80), UI.Col("Last", "Last", 90));
        var top = UI.Card(UI.Col(UI.H("Devices"), devGrid), 12);
        var bottom = UI.Card(new DockPanel { Children = { Top(UI.H("Connections")), connGrid } }, 12);
        var dp = new DockPanel(); dp.Children.Add(Top(st)); dp.Children.Add(Top(bar)); dp.Children.Add(Top(top)); dp.Children.Add(bottom);
        Refresh(); return dp;
    }
    static UIElement Top(UIElement e) { DockPanel.SetDock(e, Dock.Top); return e; }

    public override void Tick() { if (++n % 2 == 0) Refresh(); }

    void Refresh()
    {
        if (!NpcapInfo.Installed) return;
        if (devGrid == null) { Rebuild(); return; }
        status.Text = (Capture.Paused ? "⏸ PAUSED · " : "") + Capture.Status + $" · {Capture.Packets:N0} packets · {Core.Bytes(Capture.Bytes)}" + (NpcapInfo.AdminOnly ? " · Npcap is set to admin-only: reinstall Npcap with that box unchecked" : "");
        List<DevTraffic> devs; List<Conn> conns;
        lock (Capture.Gate) { devs = Capture.Devs.Values.Select(d => new DevTraffic { Mac = d.Mac, Adapter = d.Adapter, Up = d.Up, Down = d.Down, RateUp = d.RateUp, RateDown = d.RateDown }).ToList(); conns = Capture.Conns.Values.ToList(); }
        foreach (var d in devs) if (Devices.All.TryGetValue(d.Mac, out var dev)) { dev.BytesUp = d.Up; dev.BytesDown = d.Down; }
        GridX.Keep(devGrid, devs.OrderByDescending(d => d.Up + d.Down).Select(d => new DevRow(d.Mac, Capture.DeviceName(d.Mac), d.Adapter, Core.Rate(d.RateUp), Core.Rate(d.RateDown), Core.Bytes(d.Up), Core.Bytes(d.Down))).ToList(), o => ((DevRow)o).Mac);
        string f = filter.Text.Trim(); int.TryParse(port.Text.Trim(), out int pf);
        var rows = new List<ConnRow>();
        foreach (var c in conns.OrderByDescending(c => c.Up + c.Down))
        {
            if (c.Host == null || c.Service == null) Capture.Enrich(c);
            if (proto == "TCP" && c.Proto != "TCP" || proto == "UDP" && c.Proto != "UDP" || proto == "Other" && (c.Proto == "TCP" || c.Proto == "UDP")) continue;
            if (pf > 0 && c.Port != pf) continue;
            var dn = Capture.DeviceName(c.DeviceMac);
            if (f.Length > 0 && !(dn.Contains(f, StringComparison.OrdinalIgnoreCase) || (c.Host ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) || (c.Service ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) || (c.Owner ?? "").Contains(f, StringComparison.OrdinalIgnoreCase) || c.Remote.Contains(f))) continue;
            rows.Add(new ConnRow($"{c.DeviceMac}|{c.Remote}|{c.Port}|{c.Proto}", dn, c.Service, c.Host ?? c.Remote, c.Owner, c.Country, c.Port == 0 ? "" : $"{c.Port} {c.PortName}", c.Proto, Core.Bytes(c.Up), Core.Bytes(c.Down), c.Last.ToString("h:mm:ss tt"), c.Up + c.Down));
            if (rows.Count >= 500) break;
        }
        GridX.Keep(connGrid, rows, o => ((ConnRow)o).Key);
    }
}

// ============================== Bandwidth ==============================
public class BandwidthPage : PageBase
{
    public override string Title => "Bandwidth";
    public override string Subtitle => "Real-time in / out per adapter · 1-second updates · last 5 minutes (no Npcap needed)";
    readonly Dictionary<string, (RateChart chart, TextBlock now, TextBlock meta)> cards = new();
    protected override UIElement Build()
    {
        var col = new StackPanel();
        foreach (var key in new[] { "hotspot", "ethernet", "wifi" })
        {
            var s = Bandwidth.Series[key];
            var chart = new RateChart { Height = 170 }; var now = UI.T("", 15, FontWeights.SemiBold); var meta = UI.T("", 11.5, null, UI.Sub);
            var legend = UI.Row(UI.Dot(UI.Accent, 8), UI.T("Download (in)   ", 11, null, UI.Sub), UI.Dot(UI.Green, 8), UI.T("Upload (out)", 11, null, UI.Sub)); legend.Margin = new Thickness(0, 4, 0, 8);
            var head = new DockPanel(); DockPanel.SetDock(now, Dock.Right); head.Children.Add(now); head.Children.Add(UI.H(s.Label));
            col.Children.Add(UI.Card(UI.Col(head, meta, legend, chart)));
            cards[key] = (chart, now, meta);
        }
        return UI.Scroll(col);
    }
    public override void Tick()
    {
        lock (Bandwidth.Gate)
            foreach (var (key, (chart, now, meta)) in cards)
            {
                var s = Bandwidth.Series[key];
                chart.In = s.Ordered(s.In).ToArray(); chart.Out = s.Ordered(s.Out).ToArray(); chart.InvalidateVisual();
                now.Text = s.Present ? $"↓ {Core.Rate(s.CurIn)}   ↑ {Core.Rate(s.CurOut)}" : "not connected";
                meta.Text = s.Present ? $"{s.Description} · {s.Ip} · peak ↓ {Core.Rate(s.PeakIn)} ↑ {Core.Rate(s.PeakOut)} · since app start ↓ {Core.Bytes(s.TotalIn)} ↑ {Core.Bytes(s.TotalOut)}" : "adapter is down or missing";
            }
    }
}

// ============================== Devices ==============================
public class DevicesPage : PageBase
{
    public override string Title => "Devices";
    public override string Subtitle => "Hotspot 192.0.2.19/24 and home LAN 192.0.2.20/24 · ARP + ping sweep · offline MAC vendor list";
    public record Row(string Mac, Brush Dot, string Name, string Ip, string Network, string Vendor, string Latency, string Uptime, string LastSeen, string Usage, string First);
    DataGrid grid; TextBox filter, rename; CheckBox onlineOnly; readonly TextBlock info = UI.T("", 12, null, UI.Sub), detail = UI.T("", 12, null, UI.Sub, true), selName = UI.T("Select a device", 15, FontWeights.SemiBold);
    readonly Timeline tl = new() { Slots = 48, Height = 18 }; int n;

    protected override UIElement Build()
    {
        filter = UI.Box("", 220); filter.TextChanged += (s, e) => Refresh();
        onlineOnly = new CheckBox { Content = "Online only", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(12, 0, 12, 0) }; onlineOnly.Click += (s, e) => Refresh();
        var refreshBox = new ComboBox { Width = 170, Margin = new Thickness(8, 0, 4, 0), ItemsSource = RefreshOpts.Select(o => o.label).ToList() };
        { var s0 = AppSettings.Current; int idx = s0.AutoRefresh ? Array.FindIndex(RefreshOpts, o => o.q == s0.QuickRefreshSeconds && o.f == s0.FullScanMinutes) : RefreshOpts.Length - 1; refreshBox.SelectedIndex = idx < 0 ? 0 : idx; }
        refreshBox.SelectionChanged += (s, e) => { var o = RefreshOpts[Math.Max(0, refreshBox.SelectedIndex)]; var st = AppSettings.Current; st.AutoRefresh = o.q > 0; if (o.q > 0) { st.QuickRefreshSeconds = o.q; st.FullScanMinutes = o.f; } AppSettings.RaiseChanged(); };
        var prune = new CheckBox { Content = $"Prune offline > {AppSettings.Current.PruneDays} d", IsChecked = AppSettings.Current.PruneStale, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 4, 0), ToolTip = "Remove devices not seen for this many days (named devices and Rokus are kept). Change days in settings.json (PruneDays)." };
        prune.Click += (s, e) => { AppSettings.Current.PruneStale = prune.IsChecked == true; AppSettings.Save(); };
        var bar = UI.Row(UI.Btn("Refresh devices", () => { info.Text = "   full rescan + merging duplicates..."; Task.Run(async () => { await Devices.ScanAsync(default, true); return Devices.Dedupe(true); }).ContinueWith(t => Application.Current.Dispatcher.BeginInvoke(() => { Refresh(); info.Text = $"   done; {t.Result} duplicate/stale entries merged"; })); }, true, "\uE72C"), prune, refreshBox,
            UI.T("  Filter ", 12, null, UI.Sub), filter, onlineOnly,
            UI.Btn("Export CSV", () => { var f = Reports.DevicesCsv(Core.ReportDir); UI.Toast("Exported", f); Core.Launch("explorer.exe", $"/select,\"{f}\""); }, false, "\uEDE1"), info);
        foreach (UIElement e in bar.Children) if (e is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center;
        grid = UI.Grid(GridX.DotCol(), UI.Col("Name", "Name", 220), UI.Col("IP", "Ip", 120), UI.Col("Network", "Network", 85), UI.Col("Vendor", "Vendor", 190), UI.Col("Ping", "Latency", 65), UI.Col("Up 24h", "Uptime", 70), UI.Col("Last seen", "LastSeen", 120), UI.Col("Traffic", "Usage", 170), UI.Col("MAC", "Mac", 140));
        grid.SelectionChanged += (s, e) => ShowDetail();
        rename = UI.Box("", 240);
        var save = UI.Btn("Save name", () =>
        {
            if (grid.SelectedItem is not Row r) return;
            AppSettings.Current.DeviceNames[r.Mac] = rename.Text.Trim(); AppSettings.RaiseChanged();
            if (Devices.All.TryGetValue(r.Mac, out var d)) d.Name = string.IsNullOrWhiteSpace(rename.Text) ? Devices.NameFor(r.Mac, d.Ip) : rename.Text.Trim();
            Refresh();
        }, true);
        var det = UI.Card(UI.Col(selName, detail, new Border { Height = 8 }, UI.T("Last 24 hours (30-minute blocks)", 11, null, UI.Sub), tl, new Border { Height = 10 }, UI.Row(UI.T("Rename  ", 12, null, UI.Sub), rename, new Border { Width = 8 }, save)), 14);
        ((StackPanel)((StackPanel)det.Child).Children[6]).Children[0].SetValue(FrameworkElement.VerticalAlignmentProperty, VerticalAlignment.Center);
        var dp = new DockPanel(); DockPanel.SetDock(bar, Dock.Top); DockPanel.SetDock(det, Dock.Bottom); dp.Children.Add(bar); dp.Children.Add(det); dp.Children.Add(UI.Card(grid, 8));
        Devices.Updated += () => Application.Current.Dispatcher.BeginInvoke(Refresh);
        Refresh(); return dp;
    }

    static readonly (string label, int q, int f)[] RefreshOpts = { ("Auto: 30s quick / 5m full", 30, 5), ("Auto: 15s quick / 2m full", 15, 2), ("Auto: 60s quick / 10m full", 60, 10), ("Auto: 2m quick / 15m full", 120, 15), ("Auto-refresh off", 0, 0) };
    public override void Tick() { if (++n % 5 == 0) Refresh(); }

    void Refresh()
    {
        if (grid == null) return;
        var f = filter.Text.Trim();
        var rows = Devices.All.Values.Where(d => onlineOnly.IsChecked != true || d.Online)
            .Where(d => f == "" || $"{d.Display} {d.Ip} {d.Mac} {d.Vendor} {d.Type} {d.Network}".Contains(f, StringComparison.OrdinalIgnoreCase))
            .OrderBy(d => d.Network != "Hotspot").ThenByDescending(d => d.Online).ThenBy(d => IpKey(d.Ip))
            .Select(d => new Row(d.Mac, d.Online ? UI.Green : UI.Red, d.Display, d.Ip, d.Network, d.VendorType, d.LatencyText, $"{d.UptimePct(TimeSpan.FromHours(24)):0}%", d.LastSeenText, d.UsageText, d.FirstSeen.ToString("MMM d"))).ToList();
        GridX.Keep(grid, rows, o => ((Row)o).Mac);
        int on = Devices.All.Values.Count(d => d.Online);
        info.Text = Devices.LastScan == default ? "   first scan running..." : $"   {on} online / {Devices.All.Count} known | last {Devices.LastScanKind} scan {Devices.LastScan:h:mm:ss tt} ({Devices.LastScanTook.TotalSeconds:0.0}s, {(int)(DateTime.Now - Devices.LastScan).TotalSeconds}s ago)" + (Devices.IsScanning ? " | scanning..." : "") + (Devices.LastError != null ? " | " + Devices.LastError : "");
        ShowDetail();
    }
    static long IpKey(string ip) { try { return BitConverter.ToUInt32(System.Net.IPAddress.Parse(ip).GetAddressBytes().Reverse().ToArray(), 0); } catch { return 0; } }

    void ShowDetail()
    {
        if (grid.SelectedItem is not Row r || !Devices.All.TryGetValue(r.Mac, out var d)) return;
        selName.Text = d.Display;
        if (!rename.IsKeyboardFocused) rename.Text = d.Name ?? "";
        detail.Text = $"{d.Status} · {d.Ip} · {d.Mac} · {d.VendorType}{(string.IsNullOrEmpty(d.PortsText) ? "" : " · ports " + d.PortsText)}{(string.IsNullOrEmpty(d.Upnp) ? "" : " · " + d.Upnp)}{(string.IsNullOrEmpty(d.HostName) ? "" : " · " + d.HostName)} · first seen {d.FirstSeen:MMM d h:mm tt} · {d.History.Count} state changes";
        var pts = new List<bool?>(); var now = DateTime.Now;
        for (int i = 47; i >= 0; i--)
        {
            var a = now.AddMinutes(-30 * (i + 1)); var b = now.AddMinutes(-30 * i);
            if (a < d.FirstSeen.AddMinutes(-30)) { pts.Add(null); continue; }
            var before = d.History.LastOrDefault(h => h.T <= a); bool any = before?.Up == true || d.History.Any(h => h.T > a && h.T <= b && h.Up);
            pts.Add(any);
        }
        tl.Points = pts; tl.InvalidateVisual();
    }
}
