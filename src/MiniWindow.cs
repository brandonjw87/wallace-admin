using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;

namespace WNH;

/// <summary>Compact always-on-top monitor: health, hotspot/Ethernet throughput, devices, sparkline.</summary>
public class MiniWindow : Window
{
    readonly DispatcherTimer t = new() { Interval = TimeSpan.FromSeconds(1) };
    readonly Ellipse dot = UI.Dot(UI.Gray, 10);
    readonly TextBlock health = UI.T("", 12.5, FontWeights.SemiBold), hs = UI.T("", 12), eth = UI.T("", 12), devs = UI.T("", 11, null, UI.Sub);
    readonly RateChart spark = new() { Height = 60 };

    public MiniWindow()
    {
        Title = "WALLACE Admin mini"; Width = 300; Height = 190; Topmost = true; WindowStyle = WindowStyle.None; ResizeMode = ResizeMode.NoResize; AllowsTransparency = true; Background = Brushes.Transparent; ShowInTaskbar = false;
        var wa = SystemParameters.WorkArea; Left = wa.Right - Width - 16; Top = wa.Top + 16;
        // Mac-style red close dot on the right (Windows position); glyph shows on hover
        var close = new Grid { Width = 13, Height = 13, Cursor = Cursors.Hand, ToolTip = "Close", VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 2, 0, 0) };
        close.Children.Add(new Ellipse { Fill = UI.B(UI.C("#FF5F57")), Stroke = UI.B(Color.FromArgb(50, 0, 0, 0)), StrokeThickness = 0.5 });
        var cg = new TextBlock { Text = "×", FontSize = 10, FontWeight = FontWeights.Bold, Foreground = UI.B(Color.FromArgb(170, 0, 0, 0)), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, -2, 0, 0), Opacity = 0 };
        close.Children.Add(cg); close.MouseEnter += (s, e) => cg.Opacity = 1; close.MouseLeave += (s, e) => cg.Opacity = 0;
        close.MouseLeftButtonUp += (s, e) => Close(); close.MouseLeftButtonDown += (s, e) => e.Handled = true;
        var open = new TextBlock { Text = "\uE8A7", FontFamily = UI.Icons, FontSize = 12, Foreground = UI.Sub, Cursor = Cursors.Hand, Margin = new Thickness(0, 3, 10, 0), ToolTip = "Open main window" };
        open.MouseLeftButtonUp += (s, e) => { var m = Application.Current.MainWindow; if (m != null) { m.Show(); if (m.WindowState == WindowState.Minimized) m.WindowState = WindowState.Normal; m.Activate(); } };
        var head = new DockPanel(); var right = new StackPanel { Orientation = Orientation.Horizontal }; right.Children.Add(open); right.Children.Add(close);
        DockPanel.SetDock(right, Dock.Right); head.Children.Add(right); var hl = UI.Row(dot, health); hl.Margin = new Thickness(0); head.Children.Add(hl);
        var body = UI.Col(head, new Border { Height = 6 }, hs, eth, devs, new Border { Height = 4 }, spark);
        Content = new Border { CornerRadius = new CornerRadius(14), Background = UI.B(Color.FromArgb(0xF0, 0x24, 0x24, 0x26)), BorderBrush = UI.B(Color.FromArgb(40, 255, 255, 255)), BorderThickness = new Thickness(1), Padding = new Thickness(14, 10, 14, 10), Child = body, Margin = new Thickness(8),
            Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 16, Opacity = 0.5, ShadowDepth = 2 } };
        MouseLeftButtonDown += (s, e) => { if (e.ButtonState == MouseButtonState.Pressed) try { DragMove(); } catch { } };
        t.Tick += (s, e) => Update(); Loaded += (s, e) => { Update(); t.Start(); }; Closed += (s, e) => t.Stop();
    }

    void Update()
    {
        try
        {
            dot.Fill = UI.StatusBrush(Health.Overall); health.Text = Health.Busy ? "Checking…" : Health.Summary;
            lock (Bandwidth.Gate)
            {
                var h = Bandwidth.Series["hotspot"]; var e = Bandwidth.Series["ethernet"];
                hs.Text = h.Present ? $"Hotspot   ↓ {Core.Rate(h.CurIn)}   ↑ {Core.Rate(h.CurOut)}" : "Hotspot   off";
                eth.Text = e.Present ? $"Ethernet  ↓ {Core.Rate(e.CurIn)}   ↑ {Core.Rate(e.CurOut)}" : "Ethernet  disconnected";
                var src = h.Present ? h : e; spark.In = src.Ordered(src.In).Skip(Bandwidth.Window - 120).ToArray(); spark.Out = src.Ordered(src.Out).Skip(Bandwidth.Window - 120).ToArray();
            }
            var on = Devices.All.Values.Count(d => d.Online && d.Network == "Hotspot");
            var mon = Monitors.Find("1.1.1.1");
            devs.Text = $"{on} on hotspot · internet {(mon?.Up == true ? $"{mon.Ms:0} ms" : mon?.Up == false ? "DOWN" : "…")}";
            spark.InvalidateVisual();
        }
        catch (Exception ex) { Core.Log("mini: " + ex.Message); }
    }
}
