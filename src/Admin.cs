using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WNH;

public class PausedDevice { public string Ip { get; set; } public string Mac { get; set; } public string Name { get; set; } public DateTime At { get; set; } }

/// <summary>Owner-only administrative actions. Anything that needs admin rights goes through wnh-admin.ps1 via one UAC prompt per action.</summary>
public static class Admin
{
    public static string HelperPath => Path.Combine(Core.DataDir, "wnh-admin.ps1");
    public static string HelperLog => Path.Combine(Core.LogDir, "admin-helper.log");
    public const string CustomBegin = "! WALLACE custom begin", CustomEnd = "! WALLACE custom end";

    static void WriteHelper() { var t = Core.ResText("wnh-admin.ps1"); if (t.Length > 0) File.WriteAllText(HelperPath, t, new UTF8Encoding(true)); }

    /// <summary>Runs one elevated helper action (Brandon clicks UAC). Returns success + the new helper-log lines.</summary>
    public static async Task<(bool ok, string log)> Elevate(string action, string arg = "")
    {
        WriteHelper(); long start = File.Exists(HelperLog) ? new FileInfo(HelperLog).Length : 0;
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{HelperPath}\" -Action {action} -Arg \"{arg}\" -Log \"{HelperLog}\"") { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
            using var p = Process.Start(psi); await p.WaitForExitAsync().WaitAsync(TimeSpan.FromMinutes(3));
            string log = ""; try { using var fs = new FileStream(HelperLog, FileMode.Open, FileAccess.Read, FileShare.ReadWrite); fs.Seek(start, SeekOrigin.Begin); log = new StreamReader(fs).ReadToEnd(); } catch { }
            Core.Log($"admin helper {action}: exit {p.ExitCode}"); return (p.ExitCode == 0, Core.Redact(log.Trim()));
        }
        catch (System.ComponentModel.Win32Exception) { return (false, "UAC prompt was cancelled."); }
        catch (Exception ex) { return (false, Core.Redact(ex.Message)); }
    }

    public static bool Confirm(string what) => App.SelfTestMode || MessageBox.Show(what, "WALLACE Admin \u2013 confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) == MessageBoxResult.Yes;

    // ---------- pause (block internet) ----------
    public static List<PausedDevice> Paused() => JsonStore.Load<List<PausedDevice>>("paused.json");
    static bool IsProtected(string ip, string mac) => ip is "192.0.2.11" or "127.0.0.1" or "192.0.2.15" || SafeGuard.RokuMacs().Contains(mac ?? "") ||
        (SafeGuard.LastClients?.Any(c => ((string)c["name"] ?? "").Contains("(owner)") && c["ids"].AsArray().Any(i => string.Equals((string)i, ip, StringComparison.OrdinalIgnoreCase) || string.Equals((string)i, mac, StringComparison.OrdinalIgnoreCase))) ?? false);
    /// <summary>Hotspot devices: WFP forward-layer block (real cut-off) + AdGuard disallowed_clients (DNS refused if AdGuard ever sees its IP).
    /// Spectrum devices: traffic never passes this PC, so only the AdGuard entry is added and the UI tells Brandon to use the Spectrum app.</summary>
    public static async Task<string> Pause(string ip, string mac, string name, bool on, bool force = false)
    {
        if (on && Messaging.IsPhone(ip, mac, name)) return "Refused: phones can never be paused - texts, one-time codes, RCS/iMessage and Wi-Fi Calling must always work. (Messaging protected)";
        if (on && !force && IsProtected(ip, mac)) return "Refused: this device is protected (router, this PC, a Roku or the owner's phone). Use force from code only.";
        bool hs = ip?.StartsWith("192.168.137.") == true; string res = "";
        if (hs) { var (ok, log) = await Elevate(on ? "pause" : "unpause", ip); res = (ok ? "Firewall (WFP) " + (on ? "block added" : "block removed") : "Firewall step failed: " + log) + ". "; if (!ok) return res; }
        await SetDisallowed(new[] { ip, mac?.ToLowerInvariant() }.Where(x => !string.IsNullOrEmpty(x)), on);
        var l = Paused(); l.RemoveAll(p => p.Ip == ip); if (on) l.Add(new PausedDevice { Ip = ip, Mac = mac, Name = name, At = DateTime.Now }); JsonStore.Save("paused.json", l);
        Core.Log($"pause {name} {ip} -> {on}");
        return res + (on ? "AdGuard access list: DNS refused for this device." : "AdGuard access entry removed.") + (hs ? "" : " NOTE: Spectrum Wi-Fi devices do not pass through this PC; pause them in the My Spectrum app too.");
    }
    public static async Task SetDisallowed(IEnumerable<string> ids, bool on)
    {
        var a = await SafeGuard.Get("access/list");
        var dis = (a["disallowed_clients"]?.AsArray() ?? new JsonArray()).Select(x => (string)x).ToList();
        foreach (var i in ids) { if (i is "127.0.0.1" or "::1" or "192.0.2.11") continue; dis.RemoveAll(x => string.Equals(x, i, StringComparison.OrdinalIgnoreCase)); if (on) dis.Add(i); }
        await SafeGuard.Send("POST", "access/set", new JsonObject { ["allowed_clients"] = a["allowed_clients"]?.DeepClone() ?? new JsonArray(), ["disallowed_clients"] = new JsonArray(dis.Select(x => (JsonNode)x).ToArray()), ["blocked_hosts"] = a["blocked_hosts"]?.DeepClone() ?? new JsonArray() });
    }

    // ---------- custom rules ----------
    public static async Task<List<string>> CustomRules()
    {
        var r = (await SafeGuard.Get("filtering/status"))["user_rules"]?.AsArray().Select(x => (string)x).ToList() ?? new();
        int b = r.IndexOf(CustomBegin), e = r.IndexOf(CustomEnd); return b >= 0 && e > b ? r.GetRange(b + 1, e - b - 1) : new();
    }
    /// <summary>domain → "||domain^" (block) or "@@||domain^" (allow); raw AdGuard syntax passes through.</summary>
    public static string MakeRule(string input, bool allow)
    {
        var s = (input ?? "").Trim(); if (s == "" || s.StartsWith("!")) throw new Exception("Empty rule");
        if (s.Contains('|') || s.Contains('^') || s.Contains('$') || s.StartsWith("/")) return s;
        s = s.Replace("https://", "").Replace("http://", "").Split('/')[0].Trim('.').ToLowerInvariant();
        if (!System.Text.RegularExpressions.Regex.IsMatch(s, @"^[a-z0-9.-]+\.[a-z0-9-]+$")) throw new Exception("Not a domain: " + s);
        return (allow ? "@@||" : "||") + s + "^";
    }
    public static async Task EditCustom(Action<List<string>> edit)
    {
        var all = (await SafeGuard.Get("filtering/status"))["user_rules"]?.AsArray().Select(x => (string)x).Where(x => x != "").ToList() ?? new();
        int b = all.IndexOf(CustomBegin), e = all.IndexOf(CustomEnd); var mine = new List<string>();
        if (b >= 0 && e > b) { mine = all.GetRange(b + 1, e - b - 1); all.RemoveRange(b, e - b + 1); }
        edit(mine); mine = mine.Distinct().ToList();
        if (mine.Count > 0) { all.Add(CustomBegin); all.AddRange(mine); all.Add(CustomEnd); }
        await SafeGuard.Send("POST", "filtering/set_rules", new JsonObject { ["rules"] = new JsonArray(all.Select(x => (JsonNode)x).ToArray()) });
    }

    // ---------- backup / restore (AdGuard settings through the API, no secrets) ----------
    public static async Task<string> BackupConfig(string dir = null)
    {
        dir ??= Path.Combine(Core.BackupRoot, "wallace-admin-config"); Directory.CreateDirectory(dir);
        var o = new JsonObject { ["time"] = DateTime.Now.ToString("s"), ["version"] = Core.Version };
        foreach (var k in new[] { "filtering/status", "clients", "blocked_services/get", "safesearch/status", "access/list", "parental/status", "safebrowsing/status", "querylog/config" })
            try { o[k] = await SafeGuard.Get(k); } catch (Exception ex) { o[k] = "ERROR " + Core.Redact(ex.Message); }
        if (o["clients"] is JsonObject c) c.Remove("auto_clients"); // runtime only
        var f = Path.Combine(dir, $"adguard-settings-{DateTime.Now:yyyyMMdd-HHmmss}.json");
        File.WriteAllText(f, o.ToJsonString(new JsonSerializerOptions { WriteIndented = true })); Core.Log("config backup " + f); return f;
    }
    public static async Task RestoreConfig(string file)
    {
        var o = JsonNode.Parse(File.ReadAllText(file));
        var fs = o["filtering/status"];
        if (fs?["user_rules"] is JsonArray ur) await SafeGuard.Send("POST", "filtering/set_rules", new JsonObject { ["rules"] = ur.DeepClone() });
        var cur = (await SafeGuard.Get("filtering/status"))["filters"]?.AsArray() ?? new JsonArray();
        foreach (var x in fs?["filters"]?.AsArray() ?? new JsonArray())
        {
            string url = (string)x["url"], name = (string)x["name"]; bool en = (bool)x["enabled"];
            if (!cur.Any(c => (string)c["url"] == url)) await SafeGuard.Send("POST", "filtering/add_url", new JsonObject { ["name"] = name, ["url"] = url, ["whitelist"] = false });
            await SafeGuard.Send("POST", "filtering/set_url", new JsonObject { ["url"] = url, ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = name, ["url"] = url, ["enabled"] = en } });
        }
        if (o["blocked_services/get"] is JsonObject bs) await SafeGuard.Send("PUT", "blocked_services/update", new JsonObject { ["ids"] = new JsonArray((bs["ids"]?.AsArray() ?? new JsonArray()).Select(x => (string)x).Where(x => x != "instagram").Append(SnapchatBlock.ServiceId).Distinct().Select(x => (JsonNode)x).ToArray()), ["schedule"] = bs["schedule"]?.DeepClone() ?? new JsonObject { ["time_zone"] = "Local" } });
        if (o["safesearch/status"] is JsonObject ss) await SafeGuard.Send("PUT", "safesearch/settings", ss.DeepClone());
        if (o["access/list"] is JsonObject al) await SafeGuard.Send("POST", "access/set", al.DeepClone());
        var have = (await SafeGuard.Get("clients"))["clients"]?.AsArray() ?? new JsonArray();
        foreach (var c in o["clients"]?["clients"]?.AsArray() ?? new JsonArray())
        {
            var name = (string)c["name"]; var body = c.DeepClone().AsObject();
            if (have.Any(h => (string)h["name"] == name)) await SafeGuard.Send("POST", "clients/update", new JsonObject { ["name"] = name, ["data"] = body });
            else await SafeGuard.Send("POST", "clients/add", body);
        }
        Core.Log("config restored from " + file);
    }

    public static string Watchdog => Path.Combine(Core.V2, "watchdog.ps1");
    public static void RunWatchdog() => Core.Launch("powershell.exe", $"-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File \"{Watchdog}\"");
    public static int ClearAppLogs()
    {
        int n = 0; foreach (var f in Directory.GetFiles(Core.LogDir, "app-*.log")) if (!f.EndsWith($"app-{DateTime.Now:yyyyMMdd}.log")) try { File.Delete(f); n++; } catch { }
        Core.Log($"cleared {n} old app log files"); return n;
    }

    /// <summary>Make the querylog useful for reports: 14-day retention, real client IPs.</summary>
    public static async Task EnsureQueryLog()
    {
        var q = await SafeGuard.Get("querylog/config"); long want = 14L * 24 * 3600 * 1000;
        if ((bool?)q["enabled"] != true || ((long?)q["interval"] ?? 0) < want || (bool?)q["anonymize_client_ip"] == true)
        {
            var b = q.DeepClone().AsObject(); b["enabled"] = true; b["anonymize_client_ip"] = false; if (((long?)q["interval"] ?? 0) < want) b["interval"] = want;
            await SafeGuard.Send("PUT", "querylog/config/update", b); Core.Log("querylog: enabled, 14 day retention, client IPs kept");
        }
    }
}

public class AdminPage : PageBase
{
    public override string Title => "Admin";
    public override string Subtitle => "Owner controls: Roku/phone exemptions, per-device pause/filter/rename/type, custom rules, maintenance, backup/restore";
    readonly StackPanel devList = new(), ruleList = new(); readonly TextBlock status = UI.T("", 12.5, null, UI.Sub, true), helperOut = UI.T("", 11.5, null, UI.Sub, true);
    CheckBox rokuTog; TextBox ruleBox; bool busy;

    protected override UIElement Build()
    {
        rokuTog = new CheckBox { Content = "Exempt Rokus from Safe Guard", FontWeight = FontWeights.SemiBold, IsChecked = AppSettings.Current.ExemptRokus };
        rokuTog.Click += async (s, e) =>
        {
            bool v = rokuTog.IsChecked == true;
            if (!Admin.Confirm(v ? "Exempt all Rokus again? They will skip porn/Instagram/SafeSearch/parental filtering (ad lists still apply)." : "Filter the Rokus like every other device (ads, porn, Instagram, malware, trackers, SafeSearch, all categories)?")) { rokuTog.IsChecked = !v; return; }
            await Run(async () => { await SafeGuard.SetRokuExempt(v); return v ? "Rokus exempt." : "Rokus fully filtered."; });
        };
        var rokuHelp = UI.T("ON = old behaviour: 'SG Roku -' clients skip Safe Guard extras. OFF = Rokus get every block. Either way a minimal allow list keeps Roku working: " +
            "api/image/channels/captive/ntp/time/cloudservices/sr/wwwimg/my/firmware.roku.com (home screen, channel store, activation, clock, firmware) and YouTube/googlevideo/ytimg/SponsorBlock so YouTube plays. " +
            "Roku ad/telemetry hosts (ads.roku.com, logs.roku.com, events.roku.com, ravm.tv\u2026) stay blocked. Note: on the WALLACE hotspot AdGuard sees most queries as this PC, so per-device rules mostly matter for devices AdGuard sees directly.", 11.5, null, UI.Sub, true);
        ruleBox = UI.Box("", 300);
        var rules = UI.Card(UI.Col(UI.H("Custom block / allow rules"), UI.T("Type a domain (example.com) or a raw AdGuard rule. Kept in their own '! WALLACE custom' section.", 11.5, null, UI.Sub, true), new Border { Height = 6 },
            UI.Row(ruleBox, new Border { Width = 8 }, UI.Btn("Block", () => _ = AddRule(false), true, "\uE8F8"), new Border { Width = 6 }, UI.Btn("Allow", () => _ = AddRule(true), false, "\uE73E")), ruleList));
        var maint = UI.Card(UI.Col(UI.H("Maintenance"),
            UI.Row(UI.Btn("Update all lists", () => _ = Run(async () => { await Blocking.UpdateLists(); return "AdGuard is re-downloading lists."; }), false, "\uE895"), new Border { Width = 6 },
                   UI.Btn("Restart AdGuard (UAC)", () => { if (Admin.Confirm("Restart AdGuard Home? DNS pauses for ~5 s.")) _ = Run(async () => { var (ok, l) = await Admin.Elevate("restart-adguard"); return (ok ? "OK " : "FAILED ") + l; }); }, false, "\uE777"), new Border { Width = 6 },
                   UI.Btn("Restart hotspot", () => { if (Admin.Confirm("Restart/repair the WALLACE hotspot? Clients drop for ~20 s.")) { Wallace.StartHotspot(); status.Text = "start-hotspot.ps1 launched."; } }, false, "\uE701"), new Border { Width = 6 },
                   UI.Btn("Run watchdog now", () => { Admin.RunWatchdog(); status.Text = "Watchdog launched (see Logs)."; }, false, "\uE9D9")),
            UI.Row(UI.Btn("View logs", () => ((MainWindow)Application.Current.MainWindow).Navigate("logs"), false, "\uE7C3"), new Border { Width = 6 },
                   UI.Btn("Clear old app logs", () => { if (Admin.Confirm("Delete WALLACE Admin's own log files older than today?")) status.Text = $"Deleted {Admin.ClearAppLogs()} old app logs."; }, false, "\uE74D"), new Border { Width = 6 },
                   UI.Btn("Back up AdGuard settings", () => _ = Run(async () => "Saved " + await Admin.BackupConfig()), false, "\uE8F1"), new Border { Width = 6 },
                   UI.Btn("Restore settings\u2026", Restore, false, "\uE777")),
            helperOut));
        var devs = UI.Card(UI.Col(UI.H("Devices"), Messaging.Badge(), UI.Row(UI.Btn("Refresh devices", () => _ = RefreshDevices(), true, "\uE72C"), new Border { Width = 10 }, status),
            UI.T("Pause = block internet. Hotspot (WALLACE) devices: a Windows Filtering Platform block on the forward path (the only layer ICS traffic passes; normal firewall rules do not apply) plus an AdGuard access-list entry; needs one UAC click; " +
                 "IPs can change when a device reconnects, so re-pause if it gets a new IP. Spectrum devices never pass through this PC, so only the AdGuard entry is set; use the My Spectrum app to really pause them. Rokus, the router, this PC and the owner's phone cannot be paused here.", 11.5, null, UI.Sub, true),
            new Border { Height = 6 }, devList));
        return UI.Scroll(UI.Col(UI.Card(UI.Col(UI.H("Roku exemption"), rokuTog, rokuHelp)), devs, rules, maint));
    }

    public override void OnShow() => _ = Reload();

    async Task Run(Func<Task<string>> a)
    {
        if (busy) return; busy = true; status.Text = "Working\u2026";
        try { var m = await a(); status.Text = m; helperOut.Text = m.Length > 300 ? m[..300] : ""; }
        catch (Exception ex) { status.Text = "Failed: " + Core.Redact(ex.Message); Core.Log("admin: " + ex.Message); }
        finally { busy = false; await Reload(); }
    }

    async Task AddRule(bool allow)
    {
        string r; try { r = Admin.MakeRule(ruleBox.Text, allow); } catch (Exception ex) { status.Text = ex.Message; return; }
        await Run(async () => { await Admin.EditCustom(l => l.Add(r)); ruleBox.Text = ""; return "Added " + r; });
    }

    void Restore()
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { InitialDirectory = Path.Combine(Core.BackupRoot, "wallace-admin-config"), Filter = "AdGuard settings backup|adguard-settings-*.json" };
        if (dlg.ShowDialog() != true) return;
        if (!Admin.Confirm("Restore AdGuard rules, lists, clients, blocked services, SafeSearch and access list from\n" + dlg.FileName + "?\nA backup of the current settings is taken first.")) return;
        _ = Run(async () => { await Admin.BackupConfig(); await Admin.RestoreConfig(dlg.FileName); return "Restored."; });
    }

    async Task RefreshDevices()
    {
        status.Text = "Scanning\u2026"; await Task.Run(() => Devices.ScanAsync(default, true)); int m = Devices.Dedupe(true); status.Text = $"Scan done; {m} duplicate/stale entries merged."; await Reload();
    }

    async Task Reload()
    {
        rokuTog.IsChecked = AppSettings.Current.ExemptRokus;
        SafeGuard.State st; try { st = await SafeGuard.Load(); } catch { return; }
        ruleList.Children.Clear();
        try { foreach (var r in await Admin.CustomRules()) { var rr = r; ruleList.Children.Add(UI.Row(UI.T(r, 12.5, null, r.StartsWith("@@") ? UI.Green : UI.Red), new Border { Width = 10 }, UI.Btn("Remove", () => { if (Admin.Confirm("Remove rule " + rr + "?")) _ = Run(async () => { await Admin.EditCustom(l => l.Remove(rr)); return "Removed " + rr; }); }, false, "\uE74D"))); } }
        catch (Exception ex) { ruleList.Children.Add(UI.T("Could not read rules: " + Core.Redact(ex.Message), 12, null, UI.Red)); }
        devList.Children.Clear(); var paused = Admin.Paused(); var macs = SafeGuard.RokuMacs();
        foreach (var d in Devices.Merged(st.Clients))
        {
            var client = SafeGuard.FindClient(st.Clients, d.Ip, d.Mac); bool roku = SafeGuard.IsRokuDevice(d, macs); bool ex = SafeGuard.IsExempt(client);
            bool isPaused = paused.Any(p => p.Ip == d.Ip || (p.Mac != null && p.Mac == d.Mac)); var dd = d;
            var type = new ComboBox { Width = 90, ItemsSource = new[] { "auto", "Roku", "Phone", "TV", "PC", "Other" }, SelectedItem = AppSettings.Current.DeviceTypes.GetValueOrDefault(d.Mac ?? "", "auto") };
            type.SelectionChanged += (s, e) => _ = Run(async () => await SetType(dd, (string)type.SelectedItem, st));
            var exCb = new CheckBox { Content = "Exempt", IsChecked = roku ? AppSettings.Current.ExemptRokus : ex, IsEnabled = !roku, VerticalAlignment = VerticalAlignment.Center, ToolTip = roku ? "Controlled by the Roku toggle above" : "No filtering at all for this device" };
            exCb.Click += (s, e) => { bool v = exCb.IsChecked == true; if (!Admin.Confirm($"{(v ? "Exempt" : "Filter")} {dd.Display}?")) { exCb.IsChecked = !v; return; } _ = Run(async () => { await SafeGuard.SetDevice(st.Clients, dd.Display, dd.Ip, dd.Mac, v ? "exempt" : "filtered", dd.Display.Contains("Pixel") || dd.Display.Contains("Phone") ? "Phone - " : ""); return $"{dd.Display}: {(v ? "exempt" : "Safe Guard on")}"; }); };
            var pauseBtn = UI.Btn(isPaused ? "Resume" : "Pause", () => { if (Admin.Confirm($"{(isPaused ? "Resume" : "Pause (block internet for)")} {dd.Display} ({dd.Ip})?")) _ = Run(() => Admin.Pause(dd.Ip, dd.Mac, dd.Display, !isPaused)); }, !isPaused, isPaused ? "\uE768" : "\uE769");
            var renameBtn = UI.Btn("Rename", () => Rename(dd, client), false, "\uE8AC");
            var row = new Grid { Margin = new Thickness(0, 3, 0, 3) };
            foreach (var w in new[] { 14.0, 220, 115, 135, 75, 150, 80 }) row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w) }); for (int i = 0; i < 4; i++) row.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            string prot = isPaused ? "PAUSED" : roku ? (AppSettings.Current.ExemptRokus ? "Roku \u2013 exempt" : "Roku \u2013 fully filtered") : ex ? "Exempt" : d.Network == "Hotspot" ? "Safe Guard" : "Spectrum DNS (not filtered)";
            UIElement[] cells = { UI.Dot(d.Online ? UI.Green : UI.Gray, 9), UI.T(d.Display, 13), UI.T(d.Ip ?? "", 12, null, UI.Sub), UI.T(d.Mac ?? "", 12, null, UI.Sub), UI.T(d.Network == "Hotspot" ? "WALLACE" : "WALLACE Admin (Spectrum)", 12, null, UI.Sub), UI.T(prot, 12, null, isPaused ? UI.Red : ex || (roku && AppSettings.Current.ExemptRokus) ? UI.Yellow : UI.Green), exCb, pauseBtn, renameBtn, type };
            for (int i = 0; i < cells.Length; i++) { Grid.SetColumn(cells[i], i); if (cells[i] is FrameworkElement fe) { fe.VerticalAlignment = VerticalAlignment.Center; fe.Margin = new Thickness(0, 0, 6, 0); } row.Children.Add(cells[i]); }
            devList.Children.Add(row);
        }
    }

    async Task<string> SetType(Device d, string t, SafeGuard.State st)
    {
        if (d.Mac == null) return "No MAC for this device.";
        AppSettings.Current.DeviceTypes[d.Mac] = t; AppSettings.Save();
        if (t == "Roku")
        {
            var f = Path.Combine(Core.Tools, @"roku-dhcp\roku-macs.txt");
            if (!SafeGuard.RokuMacs().Contains(d.Mac)) File.AppendAllText(f, $"\r\n{d.Mac},{d.Ip},{d.Display},added by WALLACE Admin");
            await SafeGuard.SetDevice(st.Clients, d.Display, d.Ip, d.Mac, AppSettings.Current.ExemptRokus ? "roku" : "filtered", "Roku - ");
        }
        return $"{d.Display} set as {t}.";
    }

    void Rename(Device d, JsonNode client)
    {
        var box = new TextBox { Text = d.Display, Width = 280, Margin = new Thickness(10) };
        var w = new Window { Title = "Rename device", SizeToContent = SizeToContent.WidthAndHeight, WindowStartupLocation = WindowStartupLocation.CenterOwner, Owner = Application.Current.MainWindow, ResizeMode = ResizeMode.NoResize };
        var ok = new Button { Content = "Save", Margin = new Thickness(10), IsDefault = true, Padding = new Thickness(12, 4, 12, 4) }; ok.Click += (s, e) => w.DialogResult = true;
        var sp = new StackPanel(); sp.Children.Add(box); sp.Children.Add(ok); w.Content = sp;
        if (w.ShowDialog() != true || string.IsNullOrWhiteSpace(box.Text)) return;
        var name = box.Text.Trim();
        _ = Run(async () =>
        {
            if (d.Mac != null) { AppSettings.Current.DeviceNames[d.Mac] = name; AppSettings.Save(); if (Devices.All.TryGetValue(d.Mac, out var x)) x.Name = name; }
            if (client != null)
            {
                var old = (string)client["name"]; var prefix = System.Text.RegularExpressions.Regex.Match(old, @"^SG (Roku - |Phone - )?").Value; var nn = prefix + name;
                if (old.Contains("(owner)") && !nn.Contains("(owner)")) nn += " (owner)";
                var body = client.DeepClone().AsObject(); body["name"] = nn; await SafeGuard.Send("POST", "clients/update", new JsonObject { ["name"] = old, ["data"] = body });
            }
            return "Renamed to " + name;
        });
    }
}
