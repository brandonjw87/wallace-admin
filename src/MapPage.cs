using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace WNH;

/// <summary>Live network diagram (homelable-style canvas): drag nodes, layout saved, PNG export.</summary>
public class MapPage : PageBase
{
    public override string Title => "Network Map";
    public override string Subtitle => "Internet → Spectrum router → MSI → WALLACE hotspot → devices · drag to rearrange";
    class Node { public string Id, Label, Sub, Glyph, Parent; public Func<bool?> Up; public Border View; public Ellipse Dot; public TextBlock SubText; }
    readonly Canvas canvas = new() { Width = 1500, Height = 950, Background = Brushes.Transparent };
    readonly Dictionary<string, Node> nodes = new(); readonly List<(Line line, string a, string b)> edges = new();
    Dictionary<string, double[]> layout = JsonStore.Load<Dictionary<string, double[]>>("map-layout.json");
    string sig = ""; int n; CheckBox allLan;
    Node drag; Point dragOff;

    protected override UIElement Build()
    {
        allLan = new CheckBox { Content = "Show offline devices", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(8, 0, 0, 0) };
        allLan.Click += (s, e) => { sig = ""; Sync(); };
        var bar = UI.Row(UI.Btn("Export PNG", ExportPng, true, "\uEB9F"), UI.Btn("Reset layout", () => { layout.Clear(); JsonStore.Save("map-layout.json", layout); sig = ""; Sync(); }, false, "\uE72C"), allLan);
        canvas.MouseMove += (s, e) => { if (drag == null) return; var p = e.GetPosition(canvas); Place(drag, Math.Clamp(p.X - dragOff.X, 0, canvas.Width - 150), Math.Clamp(p.Y - dragOff.Y, 0, canvas.Height - 60)); };
        canvas.MouseLeftButtonUp += (s, e) => EndDrag();
        canvas.LostMouseCapture += (s, e) => EndDrag();
        var board = new Border { CornerRadius = new CornerRadius(12), Background = UI.B(Color.FromArgb(255, 0x23, 0x23, 0x25)), Child = new ScrollViewer { Content = canvas, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto } };
        var dp = new DockPanel(); DockPanel.SetDock(bar, Dock.Top); dp.Children.Add(bar); dp.Children.Add(board);
        Sync(); return dp;
    }

    void EndDrag()
    {
        if (drag == null) return;
        layout[drag.Id] = new[] { Canvas.GetLeft(drag.View), Canvas.GetTop(drag.View) }; JsonStore.Save("map-layout.json", layout);
        drag.View.BorderBrush = UI.B(Color.FromArgb(30, 255, 255, 255)); drag = null; canvas.ReleaseMouseCapture();
    }

    public override void OnShow() => Sync();
    public override void Tick() { if (++n % 2 == 0) Sync(); }

    List<Node> Wanted()
    {
        bool? Mon(string t) => Monitors.Find(t)?.Up;
        var l = new List<Node>
        {
            new() { Id = "internet", Label = "Internet", Sub = "Cloudflare / Google", Glyph = "\uE774", Up = () => Mon("1.1.1.1") },
            new() { Id = "router", Label = "Spectrum router", Sub = "192.0.2.15", Glyph = "\uE839", Parent = "internet", Up = () => Mon("192.0.2.15") },
            new() { Id = "msi", Label = "MSI laptop", Sub = "Ethernet .229 · Wi-Fi .210 backup", Glyph = "\uE7F8", Parent = "router", Up = () => Health.Checks.Count == 0 ? null : Health.Red == 0 },
            new() { Id = "hotspot", Label = "WALLACE hotspot", Sub = "192.0.2.11 · AdGuard DNS", Glyph = "\uE701", Parent = "msi", Up = () => { lock (Bandwidth.Gate) return Bandwidth.Series["hotspot"].Present; } },
        };
        foreach (var d in Devices.All.Values.OrderBy(d => d.Ip))
        {
            bool hs = d.Network == "Hotspot"; bool named = !string.IsNullOrEmpty(d.Name);
            if (d.Ip == "192.0.2.15") continue;
            // every online device on both networks; offline ones only when named or when "Show offline devices" is ticked
            if (!d.Online && !named && allLan?.IsChecked != true) continue;
            var dev = d;
            l.Add(new Node { Id = d.Mac, Label = d.Display, Sub = d.Ip, Glyph = Glyph(d), Parent = hs ? "hotspot" : "router", Up = () => dev.Online });
        }
        return l;
    }
    static string Glyph(Device d)
    {
        var t = d.Type ?? "";
        if (t == "Camera") return "\uE722";
        if (t.StartsWith("Phone") || t.StartsWith("iPhone")) return "\uE8EA";
        if (t.StartsWith("TV") || t == "Roku" || t.StartsWith("Apple TV") || t.StartsWith("Google")) return "\uE7F4";
        if (t == "Computer") return "\uE7F8";
        if (t == "Printer") return "\uE749";
        if (t.StartsWith("Speaker") || t.StartsWith("Amazon")) return "\uE7F5";
        if (t.StartsWith("Smart-home")) return "\uE80F";
        if (t == "Game console") return "\uE7FC";
        var s = (d.Display + d.Vendor).ToLowerInvariant(); return s.Contains("tv") || s.Contains("roku") || s.Contains("lg") ? "\uE7F4" : s.Contains("phone") || s.Contains("apple") || s.Contains("samsung") ? "\uE8EA" : "\uE703"; }

    void Sync()
    {
        var want = Wanted(); var newSig = string.Join("|", want.Select(w => w.Id + w.Label));
        if (newSig != sig) { sig = newSig; Rebuild(want); }
        foreach (var nd in nodes.Values)
        {
            bool? up = null; try { up = nd.Up(); } catch { }
            nd.Dot.Fill = up == true ? UI.Green : up == false ? UI.Red : UI.Gray;
            nd.View.Background = up == false ? UI.B(Color.FromArgb(255, 0x3A, 0x22, 0x22)) : UI.CardBg;
            if (Devices.All.TryGetValue(nd.Id, out var d)) nd.SubText.Text = d.Ip + (string.IsNullOrEmpty(d.Type) ? "" : " · " + d.Type) + (d.Online && d.LatencyMs >= 0 ? $" · {d.LatencyMs:0} ms" : d.Online ? "" : " · offline");
            else if (nd.Id is "internet" or "router") { var m = Monitors.Find(nd.Id == "internet" ? "1.1.1.1" : "192.0.2.15"); if (m?.Ms >= 0) nd.SubText.Text = nd.Sub + $" · {m.Ms:0} ms"; }
        }
        foreach (var (line, a, b) in edges) { bool? up = null; try { up = nodes[b].Up(); } catch { } line.Stroke = up == false ? UI.Red : UI.B(Color.FromArgb(120, 10, 132, 255)); line.StrokeDashArray = up == false ? new DoubleCollection { 4, 3 } : null; }
    }

    void Rebuild(List<Node> want)
    {
        canvas.Children.Clear(); nodes.Clear(); edges.Clear();
        // default tree layout: core chain on the left column, devices fanned out on the right.
        var core = new[] { "internet", "router", "msi", "hotspot" };
        int hsI = 0, lanI = 0;
        int lanCount = want.Count(w => w.Parent == "router" && w.Id != "msi"), hsCount = want.Count(w => w.Parent == "hotspot");
        double hsTop = Math.Max(420, 20 + Math.Ceiling(lanCount / 4.0) * 80 + 60);
        canvas.Height = Math.Max(950, hsTop + Math.Ceiling(hsCount / 4.0) * 86 + 120);
        foreach (var w in want)
        {
            double x, y;
            if (layout.TryGetValue(w.Id, out var p) && p.Length == 2) { x = p[0]; y = p[1]; }
            else if (Array.IndexOf(core, w.Id) is int ci and >= 0) { x = 40; y = ci < 3 ? 40 + ci * 150 : hsTop; }
            else if (w.Parent == "hotspot") { x = 300 + (hsI % 4) * 230; y = hsTop + (hsI / 4) * 86; hsI++; }
            else { x = 300 + (lanI % 4) * 230; y = 20 + (lanI / 4) * 80; lanI++; }
            nodes[w.Id] = w; w.View = NodeView(w); canvas.Children.Add(w.View); Place(w, x, y, false);
        }
        foreach (var w in want.Where(w => w.Parent != null && nodes.ContainsKey(w.Parent)))
        {
            var line = new Line { StrokeThickness = 2, IsHitTestVisible = false }; Panel.SetZIndex(line, -1); canvas.Children.Add(line); edges.Add((line, w.Parent, w.Id));
        }
        UpdateLines();
    }

    Border NodeView(Node w)
    {
        w.Dot = UI.Dot(UI.Gray, 9); w.SubText = UI.T(w.Sub, 11, null, UI.Sub);
        var ic = new Border { Width = 30, Height = 30, CornerRadius = new CornerRadius(8), Background = UI.B(Color.FromArgb(60, 10, 132, 255)), Child = UI.Icon(w.Glyph, 15, UI.Accent), Margin = new Thickness(0, 0, 10, 0) };
        ((TextBlock)ic.Child).HorizontalAlignment = HorizontalAlignment.Center;
        var lbl = UI.T(w.Label, 13, FontWeights.SemiBold); lbl.MaxWidth = 140;
        var sp = new StackPanel { Orientation = Orientation.Horizontal }; sp.Children.Add(ic); sp.Children.Add(UI.Col(UI.Row(w.Dot, lbl), w.SubText));
        ((StackPanel)((StackPanel)sp.Children[1]).Children[0]).Margin = new Thickness(0);
        var b = new Border { Child = sp, Padding = new Thickness(10, 8, 14, 8), CornerRadius = new CornerRadius(12), Background = UI.CardBg, BorderBrush = UI.B(Color.FromArgb(30, 255, 255, 255)), BorderThickness = new Thickness(1), Cursor = Cursors.SizeAll, MinWidth = 180,
            Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 14, ShadowDepth = 2, Opacity = 0.45 } };
        b.MouseLeftButtonDown += (s, e) => { drag = w; dragOff = e.GetPosition(b); b.BorderBrush = UI.Accent; canvas.CaptureMouse(); e.Handled = true; };
        return b;
    }

    void Place(Node w, double x, double y, bool lines = true) { Canvas.SetLeft(w.View, x); Canvas.SetTop(w.View, y); if (lines) UpdateLines(); }

    void UpdateLines()
    {
        foreach (var (line, a, b) in edges)
        {
            if (!nodes.TryGetValue(a, out var na) || !nodes.TryGetValue(b, out var nb)) continue;
            Point C(Node q) { q.View.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity)); var sz = q.View.DesiredSize; return new Point(Canvas.GetLeft(q.View) + sz.Width / 2, Canvas.GetTop(q.View) + sz.Height / 2); }
            var pa = C(na); var pb = C(nb); line.X1 = pa.X; line.Y1 = pa.Y; line.X2 = pb.X; line.Y2 = pb.Y;
        }
    }

    void ExportPng()
    {
        var dlg = new Microsoft.Win32.SaveFileDialog { Filter = "PNG image|*.png", FileName = $"network-map-{DateTime.Now:yyyyMMdd-HHmm}.png", InitialDirectory = Core.ReportDir };
        if (dlg.ShowDialog() != true) return;
        SavePng(dlg.FileName); UI.Toast("Map exported", dlg.FileName);
    }
    public void SavePng(string path)
    {
        canvas.UpdateLayout();
        double w = canvas.Width, h = canvas.Height;
        var dv = new DrawingVisual();
        using (var dc = dv.RenderOpen()) { dc.DrawRectangle(UI.B(UI.C("#1E1E1E")), null, new Rect(0, 0, w, h)); dc.DrawRectangle(new VisualBrush(canvas), null, new Rect(0, 0, w, h)); }
        var bmp = new RenderTargetBitmap((int)w, (int)h, 96, 96, PixelFormats.Pbgra32); bmp.Render(dv);
        var enc = new PngBitmapEncoder(); enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path); enc.Save(fs);
    }
}
