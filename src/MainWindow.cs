using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Shapes;
using System.Windows.Shell;
using System.Windows.Threading;

namespace WNH;

public abstract class PageBase
{
    public abstract string Title { get; }
    public virtual string Subtitle => "";
    UIElement root; public UIElement Root => root ??= Build();
    protected abstract UIElement Build();
    public virtual void OnShow() { }
    public virtual void Tick() { }   // ~1 s, only while visible
}

public class MainWindow : Window
{
    readonly Dictionary<string, PageBase> pages = new();
    readonly List<(string key, string label, string glyph, string color, Func<PageBase> make)> nav;
    readonly StackPanel navPanel = new() { Margin = new Thickness(10, 6, 10, 10) };
    readonly ContentControl host = new();
    readonly TextBlock title = UI.T("", 26, FontWeights.Bold), subtitle = UI.T("", 13, null, UI.Sub);
    readonly Border toast = new() { Visibility = Visibility.Collapsed };
    readonly DispatcherTimer tick = new() { Interval = TimeSpan.FromSeconds(1) };
    readonly Grid root = new(); readonly Border sidebar = new();
    string current; MiniWindow mini; bool live;
    public List<string> PageNames => nav.Select(n => n.key).ToList();

    public MainWindow()
    {
        Title = "WALLACE Admin"; var wa = SystemParameters.WorkArea; Width = Math.Min(1300, wa.Width - 40); Height = Math.Min(860, wa.Height - 40); MinWidth = Math.Min(1000, Width); MinHeight = Math.Min(640, Height);
        WindowStartupLocation = WindowStartupLocation.CenterScreen; FontFamily = UI.Font; Foreground = UI.Text;
        try { Icon = System.Windows.Media.Imaging.BitmapFrame.Create(new Uri("pack://application:,,,/app.ico")); } catch { }
        bool translucent = AppSettings.Current.Translucent && Native.BackdropSupported;
        Background = translucent ? Brushes.Transparent : UI.B(UI.C("#1E1E1E"));
        WindowChrome.SetWindowChrome(this, new WindowChrome { CaptionHeight = 46, ResizeBorderThickness = new Thickness(6), GlassFrameThickness = translucent ? new Thickness(-1) : new Thickness(0), CornerRadius = new CornerRadius(0), UseAeroCaptionButtons = false });
        SourceInitialized += (s, e) => { if (!Native.ApplyDwm(this, translucent)) SetSolid(); };
        StateChanged += (s, e) => root.Margin = WindowState == WindowState.Maximized ? new Thickness(7) : new Thickness(0);

        nav = new()
        {
            ("dashboard", "Dashboard", "\uE80F", "#0A84FF", () => new DashboardPage()),
            ("wallace", "WALLACE Secure", "\uE72E", "#30D158", () => new WallacePage()),
            ("status", "Live Status", "\uE9D9", "#30D158", () => new StatusPage()),
            ("traffic", "Live Traffic", "\uE968", "#BF5AF2", () => new TrafficPage()),
            ("bandwidth", "Bandwidth", "\uEC27", "#64D2FF", () => new BandwidthPage()),
            ("devices", "Devices", "\uE772", "#FF9F0A", () => new DevicesPage()),
            ("map", "Network Map", "\uE909", "#5E5CE6", () => new MapPage()),
            ("safeguard", "Safe Guard", "\uE83D", "#FF375F", () => new SafeGuardPage()),
            ("admin", "Admin", "\uE7EF", "#FF9F0A", () => new AdminPage()),
            ("router", "Router (Flint)", "\uE839", "#64D2FF", () => new RouterPage()),
            ("alerts", "Alerts", "\uEA8F", "#FF453A", () => new AlertsPage()),
            ("reports", "Reports", "\uE9F9", "#32D74B", () => new ReportsPage()),
            ("backups", "Backups", "\uE8F1", "#8E8E93", () => new BackupsPage()),
            ("logs", "Logs", "\uE7C3", "#8E8E93", () => new LogsPage()),
            ("updates", "Updates", "\uE895", "#0A84FF", () => new UpdatesPage()),
            ("research", "Research", "\uE721", "#FFD60A", () => new ResearchPage()),
            ("repairs", "Repairs", "\uE90F", "#FF9F0A", () => new RepairsPage()),
            ("settings", "Settings", "\uE713", "#8E8E93", () => new SettingsPage()),
            ("about", "About", "\uE946", "#8E8E93", () => new AboutPage()),
        };

        root.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(232) });
        root.ColumnDefinitions.Add(new ColumnDefinition());
        root.Background = translucent ? UI.B(Color.FromArgb(0xC8, 0x1C, 0x1C, 0x1E)) : UI.B(UI.C("#1E1E1E"));

        // Sidebar
        sidebar.Background = translucent ? UI.B(Color.FromArgb(0x70, 0x2A, 0x2A, 0x2C)) : UI.B(UI.C("#262628"));
        sidebar.BorderBrush = UI.B(Color.FromArgb(40, 0, 0, 0)); sidebar.BorderThickness = new Thickness(0, 0, 1, 0);
        var sideStack = new DockPanel();
        var spacer = new Border { Height = 40 }; DockPanel.SetDock(spacer, Dock.Top); sideStack.Children.Add(spacer); // traffic lights moved to the top-right in 3.1.0
        var brand = UI.Row(UI.Icon("\uE701", 15, UI.Accent), UI.T("  WALLACE Admin", 13, FontWeights.SemiBold, UI.Sub)); brand.Margin = new Thickness(20, 4, 0, 8);
        DockPanel.SetDock(brand, Dock.Top); sideStack.Children.Add(brand);
        var miniBtn = UI.Btn("Mini monitor", OpenMini, false, "\uE8A7"); miniBtn.Margin = new Thickness(16, 6, 16, 14); DockPanel.SetDock(miniBtn, Dock.Bottom); sideStack.Children.Add(miniBtn);
        foreach (var n in nav) navPanel.Children.Add(NavItem(n.key, n.label, n.glyph, n.color));
        sideStack.Children.Add(new ScrollViewer { Content = navPanel, VerticalScrollBarVisibility = ScrollBarVisibility.Auto });
        sidebar.Child = sideStack; root.Children.Add(sidebar);

        // Content
        var content = new DockPanel { Margin = new Thickness(28, 14, 20, 16) };
        var head = new StackPanel { Margin = new Thickness(0, 4, 0, 14) }; head.Children.Add(title); head.Children.Add(subtitle);
        WindowChrome.SetIsHitTestVisibleInChrome(head, false);
        DockPanel.SetDock(head, Dock.Top); content.Children.Add(head); content.Children.Add(host);
        Grid.SetColumn(content, 1); root.Children.Add(content);

        var lights = TrafficLights(); Grid.SetColumn(lights, 1); Panel.SetZIndex(lights, 60); root.Children.Add(lights);
        toast.HorizontalAlignment = HorizontalAlignment.Right; toast.VerticalAlignment = VerticalAlignment.Top; toast.Margin = new Thickness(0, 44, 18, 0);
        Grid.SetColumn(toast, 1); Panel.SetZIndex(toast, 50); root.Children.Add(toast);
        Content = root;
        UI.ToastSink = ShowToast;
        tick.Tick += (s, e) => { try { if (current != null && pages.TryGetValue(current, out var p)) p.Tick(); } catch (Exception ex) { Core.Log("tick: " + ex); } };
        Loaded += (s, e) => StartLive();
        Closed += (s, e) => { tick.Stop(); try { mini?.Close(); } catch { } if (live) { Capture.Stop(); Health.SaveLast(); } };
        Navigate("dashboard");
    }

    void SetSolid() { Background = UI.B(UI.C("#1E1E1E")); root.Background = UI.B(UI.C("#1E1E1E")); sidebar.Background = UI.B(UI.C("#262628")); }

    void StartLive()
    {
        if (App.SelfTestMode) return;
        live = true; tick.Start();
        Bandwidth.Start(); Devices.Start(); Monitors.Start(); Wallace.Start();
        Task.Run(Capture.Start);
        Health.StartAuto();
        _ = Health.Recheck();
        _ = Task.Run(async () => { try { await Admin.EnsureQueryLog(); } catch (Exception ex) { Core.Log("querylog cfg: " + ex.Message); } });
        var hourly = new DispatcherTimer { Interval = TimeSpan.FromMinutes(30) }; hourly.Tick += (s, e) => _ = BlockReport.AutoTick(); hourly.Start(); _ = BlockReport.AutoTick();
        AppSettings.Changed += () => Dispatcher.BeginInvoke(() => { Health.StartAuto(); Monitors.Sync(); });
    }

    FrameworkElement TrafficLights()
    {
        // Mac look (round dots, hover glyphs), Windows position/order: top-right, minimize - maximize - close
        var sp = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 16, 10, 0), HorizontalAlignment = HorizontalAlignment.Right, VerticalAlignment = VerticalAlignment.Top };
        UIElement L(string color, string glyph, string tip, Action a)
        {
            var g = new Grid { Width = 13, Height = 13, Margin = new Thickness(0, 0, 8, 0), Cursor = Cursors.Hand, ToolTip = tip };
            g.Children.Add(new Ellipse { Fill = UI.B(UI.C(color)), Stroke = UI.B(Color.FromArgb(50, 0, 0, 0)), StrokeThickness = 0.5 });
            var t = new TextBlock { Text = glyph, FontSize = 10, FontWeight = FontWeights.Bold, Foreground = UI.B(Color.FromArgb(170, 0, 0, 0)), HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center, Margin = new Thickness(0, -2, 0, 0), Opacity = 0 };
            g.Children.Add(t); g.MouseLeftButtonUp += (s, e) => a();
            WindowChrome.SetIsHitTestVisibleInChrome(g, true);
            return g;
        }
        sp.Children.Add(L("#FEBC2E", "−", "Minimize", () => WindowState = WindowState.Minimized));
        sp.Children.Add(L("#28C840", "+", "Maximize", () => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized));
        sp.Children.Add(L("#FF5F57", "×", "Close", Close));
        sp.Background = Brushes.Transparent; WindowChrome.SetIsHitTestVisibleInChrome(sp, true);
        sp.MouseEnter += (s, e) => { foreach (Grid g in sp.Children) g.Children[1].Opacity = 1; };
        sp.MouseLeave += (s, e) => { foreach (Grid g in sp.Children) g.Children[1].Opacity = 0; };
        return sp;
    }

    readonly Dictionary<string, Border> navItems = new();
    UIElement NavItem(string key, string label, string glyph, string color)
    {
        var icon = new Border { Width = 24, Height = 24, CornerRadius = new CornerRadius(6), Background = UI.B(UI.C(color)), Child = UI.Icon(glyph, 13, Brushes.White), Margin = new Thickness(0, 0, 10, 0) };
        ((TextBlock)icon.Child).HorizontalAlignment = HorizontalAlignment.Center;
        var row = new StackPanel { Orientation = Orientation.Horizontal }; row.Children.Add(icon); row.Children.Add(UI.T(label, 13.5));
        var b = new Border { Child = row, Padding = new Thickness(8, 5, 8, 5), CornerRadius = new CornerRadius(7), Margin = new Thickness(0, 1, 0, 1), Background = Brushes.Transparent, Cursor = Cursors.Hand };
        b.MouseEnter += (s, e) => { if (current != key) b.Background = UI.B(Color.FromArgb(22, 255, 255, 255)); };
        b.MouseLeave += (s, e) => { if (current != key) b.Background = Brushes.Transparent; };
        b.MouseLeftButtonUp += (s, e) => Navigate(key);
        WindowChrome.SetIsHitTestVisibleInChrome(b, true);
        navItems[key] = b; return b;
    }

    public void Navigate(string key)
    {
        var n = nav.FirstOrDefault(x => x.key == key); if (n.key == null) return;
        if (!pages.TryGetValue(key, out var p)) pages[key] = p = n.make();
        current = key;
        foreach (var kv in navItems) kv.Value.Background = kv.Key == key ? UI.Accent : Brushes.Transparent;
        title.Text = p.Title; subtitle.Text = p.Subtitle;
        var r = p.Root; host.Content = r; UI.FadeIn(r);
        try { p.OnShow(); } catch (Exception ex) { Core.Log("OnShow " + key + ": " + ex); }
    }

    public void OpenMini()
    {
        if (mini == null || !mini.IsLoaded) { mini = new MiniWindow(); mini.Closed += (s, e) => mini = null; mini.Show(); }
        else mini.Activate();
    }

    void ShowToast(string t, string b)
    {
        var sp = new StackPanel { MaxWidth = 360 }; sp.Children.Add(UI.T(t, 13, FontWeights.SemiBold)); sp.Children.Add(UI.T(b, 12, null, UI.Sub, true));
        toast.Child = new Border { Background = UI.B(UI.C("#3A3A3C")), CornerRadius = new CornerRadius(12), Padding = new Thickness(14, 10, 14, 10), Child = sp, BorderBrush = UI.B(Color.FromArgb(30, 255, 255, 255)), BorderThickness = new Thickness(1), Effect = new System.Windows.Media.Effects.DropShadowEffect { BlurRadius = 24, Opacity = 0.5, ShadowDepth = 3 } };
        toast.Visibility = Visibility.Visible; UI.FadeIn(toast, -12);
        var hide = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        hide.Tick += (s, e) => { hide.Stop(); var a = new DoubleAnimation(0, TimeSpan.FromMilliseconds(250)); a.Completed += (_, _) => toast.Visibility = Visibility.Collapsed; toast.BeginAnimation(OpacityProperty, a); };
        hide.Start();
    }
}
