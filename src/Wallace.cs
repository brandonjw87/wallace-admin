using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WNH;

/// <summary>WALLACE hotspot host info: which physical adapter hosts the hotspot, band, clients, Wi-Fi adapter
/// capabilities and the watchdog task. Read-only; polled every 30 s while the app runs.</summary>
public static class Wallace
{
    public class Info
    {
        public string State = "?", Ssid = "", Band = "", Uplink = "", Virtual = "", Host = "", HostDesc = "", Watchdog = "", Error = "";
        public int Clients = -1, MaxClients = -1;
        public List<(string name, string desc, string status, string link, List<string> props)> Adapters = new();
        public List<string> Radios = new(), WatchdogLog = new();
        public DateTime Time;
        public bool On => State == "On";
        public bool HostIsIntel => HostDesc.Contains("Intel", StringComparison.OrdinalIgnoreCase);
        public string BandText => Band switch { "FiveGigahertz" => "5 GHz", "TwoPointFourGigahertz" => "2.4 GHz", "SixGigahertz" => "6 GHz", "Auto" => "Auto (2.4/5 GHz)", "" => "?", _ => Band };
    }
    public static Info Current { get; private set; } = new();
    public static event Action Changed;
    static System.Threading.Timer timer; static int busy;
    static string lastState;

    public const string TpLinkNote =
        "The TP-Link Archer TX20U Plus (Wi-Fi 6) cannot host WALLACE with its current driver: Windows parents its Wi-Fi Direct virtual adapters (which the hotspot runs on) " +
        "to the Intel card, and starting the hotspot on the TP-Link fails with 'WiFiDeviceOff'. Driver changes are off-limits, so WALLACE stays on the Intel Wireless-AC 9462 " +
        "(Wi-Fi 5 / 802.11ac, 1 stream, up to 433 Mbps on 5 GHz at 80 MHz). The TP-Link stays available as a fast Wi-Fi client / backup uplink.";

    const string Script = @"
$ErrorActionPreference='SilentlyContinue'
$o=[ordered]@{}
try {
  $p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
  if($p){ $o.Uplink=$p.ProfileName
    $m=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($p)
    $o.State=[string]$m.TetheringOperationalState; $o.Clients=[int]$m.ClientCount; $o.MaxClients=[int]$m.MaxClientCount
    $c=$m.GetCurrentAccessPointConfiguration(); $o.Ssid=$c.Ssid; try{ $o.Band=[string]$c.Band }catch{} }
  else { $o.State='NoUplink' }
} catch { $o.Error=$_.Exception.Message }
$ip=Get-NetIPAddress -IPAddress 192.0.2.11 -AddressFamily IPv4
if($ip){ $v=Get-NetAdapter -InterfaceIndex $ip.InterfaceIndex -IncludeHidden; $o.Virtual=$v.InterfaceDescription
  $par=(Get-PnpDeviceProperty -InstanceId $v.PnPDeviceID -KeyName DEVPKEY_Device_Parent).Data
  $h=Get-NetAdapter -Physical | ?{ $_.PnPDeviceID -eq $par }; if($h){ $o.Host=$h.Name; $o.HostDesc=$h.InterfaceDescription } }
$o.Adapters=@(foreach($a in (Get-NetAdapter -Physical | ?{ $_.NdisPhysicalMedium -eq 9 })){
  [ordered]@{ Name=$a.Name; Desc=$a.InterfaceDescription; Status=[string]$a.Status; Link=$a.LinkSpeed;
    Props=@(Get-NetAdapterAdvancedProperty -Name $a.Name | ?{ $_.DisplayName -match 'Band|Width|Wireless Mode|Throughput|Roam|SMPS|Transmit Power' } | %{ $_.DisplayName+' = '+$_.DisplayValue }) } })
$o.Radios=@((netsh wlan show drivers) -match 'Interface name|Radio types' | %{ $_.Trim() })
$t=Get-ScheduledTask -TaskName 'WALLACE Watchdog'
if($t){ $i=$t | Get-ScheduledTaskInfo; $o.Watchdog=('{0}; last run {1:h:mm tt}; result 0x{2:X}' -f $t.State,$i.LastRunTime,$i.LastTaskResult) }
$lf='C:\Users\YOU\Tools\wallace-roku-v2\logs\watchdog.log'
if(Test-Path $lf){ $o.WatchdogLog=@(Get-Content $lf -Tail 8) }
$o | ConvertTo-Json -Depth 4 -Compress
";

    public static void Start() { timer ??= new System.Threading.Timer(_ => _ = RefreshAsync(), null, 0, 30000); }

    public static async Task<Info> RefreshAsync()
    {
        if (Interlocked.Exchange(ref busy, 1) == 1) return Current;
        try
        {
            var (_, o) = await Task.Run(() => Core.RunPs(Script, 60000));
            var line = o.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.StartsWith("{")) ?? "";
            var i = new Info { Time = DateTime.Now };
            if (line == "") i.Error = "probe returned nothing: " + Core.Redact(o.Length > 200 ? o[..200] : o);
            else
            {
                using var d = JsonDocument.Parse(line); var r = d.RootElement;
                string S(string n) => r.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.ToString() : "";
                int N(string n) => r.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.Number ? v.GetInt32() : -1;
                List<string> L(JsonElement e, string n) => e.TryGetProperty(n, out var v) ? (v.ValueKind == JsonValueKind.Array ? v.EnumerateArray().Select(x => Core.Redact(x.ToString())).ToList() : new() { Core.Redact(v.ToString()) }) : new();
                i.State = S("State"); i.Ssid = S("Ssid"); i.Band = S("Band"); i.Uplink = S("Uplink"); i.Virtual = S("Virtual"); i.Host = S("Host"); i.HostDesc = S("HostDesc");
                i.Watchdog = S("Watchdog"); i.Error = S("Error"); i.Clients = N("Clients"); i.MaxClients = N("MaxClients");
                i.Radios = L(r, "Radios"); i.WatchdogLog = L(r, "WatchdogLog");
                if (r.TryGetProperty("Adapters", out var ad))
                {
                    var arr = ad.ValueKind == JsonValueKind.Array ? ad.EnumerateArray().ToList() : new List<JsonElement> { ad };
                    foreach (var a in arr) i.Adapters.Add((a.GetProperty("Name").ToString(), a.GetProperty("Desc").ToString(), a.GetProperty("Status").ToString(), a.GetProperty("Link").ToString(), L(a, "Props")));
                }
            }
            Current = i;
            if (lastState != null && lastState == "On" && i.State != "On") Alerts.Raise("wallace-off", "red", "WALLACE hotspot is " + i.State, "The watchdog (every 3 min) will try to restart it. Use WALLACE page > Start / repair hotspot to do it now.", 10);
            if (lastState != null && lastState != "On" && i.State == "On") Alerts.Raise("wallace-on", "green", "WALLACE hotspot is back On", $"{i.BandText} on {i.HostDesc}", 1);
            lastState = i.State;
            Changed?.Invoke();
            return i;
        }
        catch (Exception ex) { Core.Log("wallace refresh: " + ex.Message); return Current; }
        finally { Interlocked.Exchange(ref busy, 0); }
    }

    public static void StartHotspot() => Core.Launch("powershell.exe", $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{Path.Combine(Core.V2, "start-hotspot.ps1")}\"");

    /// <summary>Compact card used on the Dashboard and the WALLACE page.</summary>
    public static Border HostCard(out Action render)
    {
        var dot = UI.Dot(UI.Gray, 14); var head = UI.T("WALLACE hotspot", 17, FontWeights.SemiBold);
        var line1 = UI.T("", 13, null, UI.Text, true); var line2 = UI.T("", 12, null, UI.Sub, true); var note = UI.T(TpLinkNote, 11.5, null, UI.Sub, true); note.FontStyle = FontStyles.Italic; note.Margin = new Thickness(0, 6, 0, 0);
        render = () =>
        {
            var i = Current;
            dot.Fill = i.Time == default ? UI.Gray : i.On ? UI.Green : UI.Red;
            head.Text = $"WALLACE hotspot: {(i.Time == default ? "checking." : i.State)}";
            var host = i.Adapters.FirstOrDefault(a => a.name == i.Host);
            line1.Text = i.Time == default ? "Reading adapter info." :
                $"Hosted by: {(i.HostDesc == "" ? "(hotspot adapter not found)" : $"{i.HostDesc} ('{i.Host}')")}  |  Band: {i.BandText}  |  Clients: {(i.Clients < 0 ? "?" : $"{i.Clients}/{i.MaxClients}")}  |  Sharing: {i.Uplink}";
            string rate; lock (Bandwidth.Gate) { var s = Bandwidth.Series.TryGetValue("hotspot", out var x) ? x : null; rate = s != null && s.Present ? $"{Core.Rate(s.CurOut)} down to clients / {Core.Rate(s.CurIn)} up" : "n/a"; }
            line2.Text = i.Time == default ? "" : $"Link: Intel radio negotiates per client (max 433 Mbps, Wi-Fi 5 1x1 @ 80 MHz on 5 GHz; virtual adapter reports 0 bps). Live: {rate}." +
                (host.props != null && host.props.Count > 0 ? "  Settings: " + string.Join("; ", host.props.Where(p => p.Contains("Band") || p.Contains("Throughput") || p.Contains("5GHz"))) : "") +
                (i.Error != "" ? "  Error: " + i.Error : "");
        };
        var start = UI.Btn("Start / repair hotspot", () => { StartHotspot(); UI.Toast("WALLACE", "start-hotspot.ps1 launched (hidden); refreshing in 20 s"); _ = Task.Delay(20000).ContinueWith(_ => RefreshAsync()); }, false, "\uE701");
        var refresh = UI.Btn("Refresh", () => _ = RefreshAsync(), false, "\uE72C");
        var top = new DockPanel(); var btns = UI.Row(refresh, start); btns.Margin = new Thickness(0); DockPanel.SetDock(btns, Dock.Right); top.Children.Add(btns);
        var hl = UI.Row(dot, head); hl.Margin = new Thickness(0); top.Children.Add(hl);
        render();
        return UI.Card(UI.Col(top, line1, line2, note), 16);
    }
}

/// <summary>Secure / monitor role: one page that watches WALLACE health, new devices, blocking and the watchdog.</summary>
public class WallacePage : PageBase
{
    public override string Title => "WALLACE Secure";
    public override string Subtitle => "Monitor and secure the WALLACE hotspot: host adapter, blocking, new devices, watchdog";
    Action renderHost; readonly TextBlock sec = UI.T("Loading Safe Guard.", 13, null, UI.Text, true), devs = UI.T("", 12.5, null, UI.Text, true), wd = UI.T("", 12, null, UI.Text, true), radios = UI.T("", 12, null, UI.Text, true);
    readonly TextBox wdlog = P.Viewer(); DateTime lastSg;

    protected override UIElement Build()
    {
        var host = Wallace.HostCard(out renderHost);
        Wallace.Changed += () => Application.Current?.Dispatcher.BeginInvoke(Render);
        wdlog.Height = 150;
        var links = UI.Row(UI.Btn("AdGuard Home", () => Core.Launch("http://127.0.0.1:3000", shell: true), false, "\uE83D"), UI.Btn("Uptime Kuma", () => Core.Launch("http://127.0.0.1:3001", shell: true), false, "\uE9D9"), UI.Btn("Watchdog log", () => Core.Launch(Path.Combine(Core.V2, @"logs\watchdog.log"), shell: true), false, "\uE7C3"));
        return UI.Scroll(UI.Col(host,
            UI.Card(UI.Col(UI.H("Security (AdGuard Safe Guard)"), sec)),
            UI.Card(UI.Col(UI.H("New devices on WALLACE (last 24 h)"), devs)),
            UI.Card(UI.Col(UI.H("Watchdog (every 3 min)"), wd, wdlog)),
            UI.Card(UI.Col(UI.H("Wi-Fi adapters"), radios)), links));
    }
    public override void OnShow() { _ = Wallace.RefreshAsync(); _ = LoadSg(); Render(); }
    public override void Tick() { renderHost?.Invoke(); if (DateTime.Now - lastSg > TimeSpan.FromSeconds(60)) _ = LoadSg(); }

    async Task LoadSg()
    {
        lastSg = DateTime.Now;
        try
        {
            var s = await SafeGuard.Load();
            string Y(bool b) => b ? "ON" : "OFF";
            sec.Text = !s.Reachable ? "AdGuard Home not reachable: " + s.Error :
                $"Porn/nudity: {Y(s.Adult)}   Instagram: {Y(s.Instagram)}   Snapchat: {(s.Snapchat ? "Blocked on WALLACE" : "NOT blocked")}   Dating apps: {(s.Dating ? "Blocked on WALLACE (owner phone exempt)" : "NOT blocked")}   SafeSearch forced: {Y(s.SafeSearch)}   DNS-bypass block: {Y(s.Bypass)}   Parental: {Y(s.Parental)}\n" +
                $"Blocked in last 24 h: {s.Blocked24h:N0}   Top blocked: {string.Join(", ", s.Top.Take(5).Select(t => $"{t.domain} ({t.n})"))}\n" +
                "Rokus and YouTube / SponsorBlock / iSponsorBlockTV are always allowed; exempt clients keep their own settings.";
            sec.Foreground = s.Reachable && s.Adult && !s.Instagram ? UI.Text : UI.Red; // 3.4.1 Instagram allowed
        }
        catch (Exception ex) { sec.Text = "Safe Guard load failed: " + ex.Message; sec.Foreground = UI.Red; }
    }

    void Render()
    {
        renderHost?.Invoke();
        var i = Wallace.Current;
        var nd = Devices.All.Values.Where(d => d.Network == "Hotspot" && d.FirstSeen > DateTime.Now.AddHours(-24)).OrderByDescending(d => d.FirstSeen).ToList();
        var on = Devices.All.Values.Where(d => d.Online && d.Network == "Hotspot").ToList();
        devs.Text = (nd.Count == 0 ? "No new devices in the last 24 h." : string.Join("\n", nd.Select(d => $"NEW  {d.FirstSeen:MMM d h:mm tt}  {d.Display}  {d.Ip}  {d.Mac}  {d.Vendor}"))) +
            $"\nOnline now ({on.Count}): " + string.Join(", ", on.Select(d => d.Display));
        wd.Text = i.Watchdog == "" ? "Scheduled task 'WALLACE Watchdog' not found." : i.Watchdog;
        wdlog.Text = string.Join("\r\n", i.WatchdogLog);
        radios.Text = string.Join("\n", i.Adapters.Select(a => $"{a.name}: {a.desc} - {a.status} {a.link}{(a.name == i.Host ? "   <- hosts WALLACE" : "")}\n    " + string.Join("; ", a.props))) + "\n" + string.Join("  ", i.Radios);
    }
}
