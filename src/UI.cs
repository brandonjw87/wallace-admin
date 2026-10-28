using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;

namespace WNH;

/// <summary>Small factory for the macOS-style dark visual language.</summary>
public static class UI
{
    public static readonly Color AccentC = C("#0A84FF"), GreenC = C("#30D158"), YellowC = C("#FFD60A"), RedC = C("#FF453A"), GrayC = C("#8E8E93");
    public static readonly SolidColorBrush Accent = B(AccentC), Green = B(GreenC), Yellow = B(YellowC), Red = B(RedC), Gray = B(GrayC),
        Text = B(C("#F5F5F7")), Sub = B(C("#A1A1A6")), CardBg = B(C("#2C2C2E")), CardHover = B(C("#3A3A3C")), Stroke = B(C("#3A3A3C")), Inset = B(C("#1C1C1E"));
    public static Color C(string hex) => (Color)ColorConverter.ConvertFromString(hex);
    public static SolidColorBrush B(Color c) { var b = new SolidColorBrush(c); b.Freeze(); return b; }
    public static SolidColorBrush StatusBrush(string s) => s switch { "Green" => Green, "Yellow" => Yellow, "Red" => Red, _ => Gray };
    public static readonly FontFamily Font = new("Segoe UI Variable Text, Segoe UI"), Display = new("Segoe UI Variable Display, Segoe UI"), Icons = new("Segoe Fluent Icons, Segoe MDL2 Assets"), Mono = new("Cascadia Mono, Consolas");

    public static Border Card(UIElement child, double pad = 16) => new()
    {
        Background = CardBg, CornerRadius = new CornerRadius(12), Padding = new Thickness(pad), Margin = new Thickness(0, 0, 12, 12), Child = child,
        BorderBrush = B(Color.FromArgb(18, 255, 255, 255)), BorderThickness = new Thickness(1),
        Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 18, ShadowDepth = 2, Opacity = 0.35, Color = Colors.Black }
    };
    public static TextBlock T(string s, double size = 13, FontWeight? w = null, Brush fg = null, bool wrap = false) => new()
    { Text = s, FontSize = size, FontWeight = w ?? FontWeights.Normal, Foreground = fg ?? Text, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap, TextTrimming = wrap ? TextTrimming.None : TextTrimming.CharacterEllipsis, FontFamily = size >= 20 ? Display : Font };
    public static TextBlock H(string s) => T(s, 17, FontWeights.SemiBold);
    public static TextBlock Icon(string glyph, double size = 16, Brush fg = null) => new() { Text = glyph, FontFamily = Icons, FontSize = size, Foreground = fg ?? Text, VerticalAlignment = VerticalAlignment.Center };
    public static Ellipse Dot(Brush b, double d = 10) => new() { Width = d, Height = d, Fill = b, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, 0, 8, 0) };

    public static Button Btn(string text, Action click, bool accent = false, string glyph = null)
    {
        var sp = new StackPanel { Orientation = Orientation.Horizontal };
        if (glyph != null) { var i = Icon(glyph, 13, Brushes.White); i.Margin = new Thickness(0, 0, 7, 0); sp.Children.Add(i); }
        sp.Children.Add(new TextBlock { Text = text, Foreground = Brushes.White, FontFamily = Font, FontSize = 13 });
        var b = new Button { Content = sp, Style = (Style)Application.Current.FindResource(accent ? "AccentBtn" : "Btn") };
        b.Click += (s, e) => { try { click(); } catch (Exception ex) { Core.Log("button " + text + ": " + ex); Toast("Something went wrong", ex.Message); } };
        return b;
    }
    public static StackPanel Row(params UIElement[] kids) { var p = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 0, 0, 12) }; foreach (var k in kids) p.Children.Add(k); return p; }
    public static StackPanel Col(params UIElement[] kids) { var p = new StackPanel(); foreach (var k in kids) p.Children.Add(k); return p; }
    public static ScrollViewer Scroll(UIElement c) => new() { Content = c, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled, Padding = new Thickness(0, 0, 8, 0) };
    public static TextBox Box(string text = "", double width = double.NaN, bool multi = false, bool ro = false)
    {
        var t = new TextBox { Text = text, Width = width, IsReadOnly = ro, AcceptsReturn = multi, TextWrapping = multi ? TextWrapping.NoWrap : TextWrapping.NoWrap, VerticalScrollBarVisibility = multi ? ScrollBarVisibility.Auto : ScrollBarVisibility.Disabled, HorizontalScrollBarVisibility = multi ? ScrollBarVisibility.Auto : ScrollBarVisibility.Hidden };
        if (multi) { t.FontFamily = Mono; t.FontSize = 12; }
        return t;
    }
    public static DataGridTextColumn Col(string header, string path, double width = double.NaN) => new() { Header = header, Binding = new System.Windows.Data.Binding(path), Width = double.IsNaN(width) ? DataGridLength.Auto : new DataGridLength(width) };
    public static DataGrid Grid(params DataGridColumn[] cols) { var g = new DataGrid(); foreach (var c in cols) g.Columns.Add(c); return g; }

    public static void FadeIn(UIElement e, double fromY = 10)
    {
        var tt = new TranslateTransform(0, fromY); e.RenderTransform = tt; e.Opacity = 0;
        var ease = new CubicEase { EasingMode = EasingMode.EaseOut };
        e.BeginAnimation(UIElement.OpacityProperty, new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(220)) { EasingFunction = ease });
        tt.BeginAnimation(TranslateTransform.YProperty, new DoubleAnimation(fromY, 0, TimeSpan.FromMilliseconds(260)) { EasingFunction = ease });
    }

    public static Action<string, string> ToastSink;
    public static void Toast(string title, string body) { Core.Log($"UI toast: {title} {body}"); Application.Current?.Dispatcher.BeginInvoke(() => ToastSink?.Invoke(title, body)); }
}

/// <summary>Real-time in/out area chart (5-minute window) rendered directly for speed.</summary>
public class RateChart : FrameworkElement
{
    public double[] In = Array.Empty<double>(), Out = Array.Empty<double>();
    static readonly Pen grid = new(UI.B(Color.FromArgb(28, 255, 255, 255)), 1), inPen = new(UI.Accent, 1.6), outPen = new(UI.Green, 1.6);
    static readonly Brush inFill = new LinearGradientBrush(Color.FromArgb(110, 10, 132, 255), Color.FromArgb(0, 10, 132, 255), 90), outFill = new LinearGradientBrush(Color.FromArgb(70, 48, 209, 88), Color.FromArgb(0, 48, 209, 88), 90);
    static RateChart() { grid.Freeze(); inPen.Freeze(); outPen.Freeze(); inFill.Freeze(); outFill.Freeze(); }
    public RateChart() { Height = 150; SnapsToDevicePixels = true; }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight; if (w < 20 || h < 20) return;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        double max = Math.Max(1250, Math.Max(In.DefaultIfEmpty(0).Max(), Out.DefaultIfEmpty(0).Max())) * 1.15; // >= 10 Kbps scale
        double top = 4, bottom = h - 16, plotH = bottom - top, left = 0, right = w - 64;
        var tf = new Typeface(UI.Font, FontStyles.Normal, FontWeights.Normal, FontStretches.Normal); double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        for (int i = 0; i <= 3; i++)
        {
            double y = top + plotH * i / 3; dc.DrawLine(grid, new Point(left, y), new Point(right, y));
            dc.DrawText(new FormattedText(Core.Rate(max * (3 - i) / 3), CultureInfo.CurrentCulture, FlowDirection.LeftToRight, tf, 10, UI.Sub, dpi), new Point(right + 6, y - 7));
        }
        foreach (var (lbl, frac) in new[] { ("5m", 0.0), ("4m", 0.2), ("3m", 0.4), ("2m", 0.6), ("1m", 0.8), ("now", 1.0) })
            dc.DrawText(new FormattedText(lbl, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, tf, 10, UI.Sub, dpi), new Point(Math.Min(right - 18, left + (right - left) * frac), bottom + 2));
        void Series(double[] a, Pen pen, Brush fill)
        {
            if (a.Length < 2) return;
            var line = new StreamGeometry(); var area = new StreamGeometry();
            using (var c = line.Open()) using (var f = area.Open())
            {
                for (int i = 0; i < a.Length; i++)
                {
                    var p = new Point(left + (right - left) * i / (a.Length - 1), bottom - plotH * Math.Min(1, a[i] / max));
                    if (i == 0) { c.BeginFigure(p, false, false); f.BeginFigure(new Point(p.X, bottom), true, true); f.LineTo(p, false, false); }
                    else { c.LineTo(p, true, true); f.LineTo(p, false, false); }
                }
                f.LineTo(new Point(right, bottom), false, false);
            }
            line.Freeze(); area.Freeze(); dc.DrawGeometry(fill, null, area); dc.DrawGeometry(null, pen, line);
        }
        Series(In, inPen, inFill); Series(Out, outPen, outFill);
    }
}

/// <summary>homelable-style status timeline: one rounded bar per probe.</summary>
public class Timeline : FrameworkElement
{
    public IReadOnlyList<bool?> Points = Array.Empty<bool?>(); public int Slots = 60;
    public Timeline() { Height = 18; }
    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight; if (w < 10) return;
        double bw = w / Slots; int start = Math.Max(0, Points.Count - Slots), offset = Slots - (Points.Count - start);
        for (int i = 0; i < Slots; i++)
        {
            bool? v = i < offset ? null : Points[start + i - offset];
            var b = v == null ? UI.B(Color.FromArgb(40, 255, 255, 255)) : v.Value ? UI.Green : UI.Red;
            dc.DrawRoundedRectangle(b, null, new Rect(i * bw + 1, 0, Math.Max(1, bw - 2), h), 2, 2);
        }
    }
}
