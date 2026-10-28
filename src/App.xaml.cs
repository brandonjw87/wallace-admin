using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;
using System.Windows.Threading;

namespace WNH;

public partial class App : Application
{
    static Mutex single;
    public static bool SelfTestMode;

    protected override void OnStartup(StartupEventArgs e)
    {
        AppDomain.CurrentDomain.UnhandledException += (s, a) => Core.Log("FATAL (domain): " + a.ExceptionObject);
        TaskScheduler.UnobservedTaskException += (s, a) => { Core.Log("unobserved task: " + (a.Exception?.InnerException?.Message ?? a.Exception?.Message)); a.SetObserved(); };
        DispatcherUnhandledException += (s, a) => { Core.Log("UI exception: " + a.Exception); a.Handled = true; UI.Toast("Recovered from an error", a.Exception.Message + " (details in logs)"); };
        base.OnStartup(e);
        Core.Migrate();
        Core.Log($"start v{Core.Version} args=[{string.Join(" ", e.Args)}]");

        if (e.Args.Any(a => a.Equals("--selftest", StringComparison.OrdinalIgnoreCase)))
        {
            SelfTestMode = true; ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Dispatcher.BeginInvoke(async () => { int code = 1; try { code = await SelfTest.Run(); } catch (Exception ex) { Core.Log("selftest crash: " + ex); } Shutdown(code); });
            return;
        }
        var rk = e.Args.FirstOrDefault(a => a.StartsWith("--roku-exempt=", StringComparison.OrdinalIgnoreCase));
        if (rk != null)
        {   // owner/automation switch, same code path as the Admin page toggle: --roku-exempt=on|off
            ShutdownMode = ShutdownMode.OnExplicitShutdown; bool on = rk.EndsWith("on", StringComparison.OrdinalIgnoreCase);
            Dispatcher.BeginInvoke(async () => { int code = 0; try { await SafeGuard.SetRokuExempt(on); } catch (Exception ex) { code = 1; Core.Log("roku-exempt switch: " + ex.Message); } Shutdown(code); });
            return;
        }
        if (e.Args.Any(a => a.Equals("--encdns-check", StringComparison.OrdinalIgnoreCase)))
        {   // 3.3.0 weekly scheduled task: read-only check, toast if a stronger setup is available (never applies by itself)
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            Dispatcher.BeginInvoke(async () => { int code = 0; try { await EncDns.RunScheduled(); } catch (Exception ex) { code = 1; Core.Log("encdns-check: " + ex.Message); } Shutdown(code); });
            return;
        }
        single = new Mutex(true, @"Local\WALLACEAdminV3", out bool first);
        if (!first) { BringExisting(); Shutdown(0); return; }
        var w = new MainWindow(); MainWindow = w; w.Show(); EncDns.StartWeekly();
        if (e.Args.Any(a => a.Equals("--mini", StringComparison.OrdinalIgnoreCase))) w.OpenMini();
    }

    static void BringExisting()
    {
        foreach (var p in System.Diagnostics.Process.GetProcessesByName("WALLACEAdmin"))
            if (p.Id != Environment.ProcessId && p.MainWindowHandle != IntPtr.Zero) { Native.ShowWindow(p.MainWindowHandle, 9); Native.SetForegroundWindow(p.MainWindowHandle); }
    }
}

public static class SelfTest
{
    public static async Task<int> Run()
    {
        var r = new Dictionary<string, object> { ["time"] = DateTime.Now.ToString("s"), ["version"] = Core.Version, ["exe"] = Environment.ProcessPath };
        var fails = new List<string>();
        void Check(string name, Func<object> f) { try { r[name] = f(); } catch (Exception ex) { r[name] = "ERROR " + ex.Message; fails.Add(name); } }
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew(); var checks = await Task.Run(Core.RunAllChecks); sw.Stop();
            r["checksSeconds"] = Math.Round(sw.Elapsed.TotalSeconds, 1);
            r["counts"] = checks.GroupBy(c => c.Status).ToDictionary(g => g.Key, g => g.Count());
            r["checks"] = checks;
            if (checks.Any(c => c.Layer == "Engine")) fails.Add("probe");
        }
        catch (Exception ex) { r["checks"] = "ERROR " + ex.Message; fails.Add("checks"); }
        try { var sg = await SafeGuard.Load(); r["safeGuard"] = new { sg.Reachable, sg.Adult, sg.Instagram, sg.SafeSearch, sg.Bypass, sg.Parental, sg.Blocked24h, clients = sg.Clients.Count }; if (!sg.Reachable || !sg.Adult || sg.Instagram) fails.Add("safeGuard"); r["snapchatService"] = sg.Snapchat; if (!sg.Snapchat) fails.Add("snapchatService"); r["datingBlocked"] = sg.Dating; if (!sg.Dating) fails.Add("datingService"); /* 3.4.1: Instagram must be ALLOWED */ } catch (Exception ex) { r["safeGuard"] = "ERROR " + ex.Message; fails.Add("safeGuard"); }
        try
        {
            await Blocking.ApplyDefaultsOnce();
            var cats = await Blocking.Load(); r["blocking"] = cats.Select(c => $"{c.Cat.Key}: {(c.On ? "ON" : "off")} rules={c.Rules} blocked24h={c.Blocked24h}").ToList();
            var want = new (string host, bool blocked)[] { ("doubleclick.net", true), ("pornhub.com", true), ("instagram.com", false), ("i.instagram.com", false), ("scontent.cdninstagram.com", false), ("coinhive.com", true), ("snapchat.com", true), ("app.snapchat.com", true), ("sc-cdn.net", true), ("tinder.com", true), ("bumble.com", true), ("facebook.com", false), ("www.messenger.com", false),
                ("googlevideo.com", false), ("youtubei.googleapis.com", false), ("s.youtube.com", false), ("www.youtube.com", false), ("i.ytimg.com", false), ("sponsor.ajay.app", false), ("api.roku.com", false), ("example.com", false) };
            var lk = new List<string>();
            foreach (var (h, b) in want) { var rs = await Blocking.Check(h); bool isB = rs.StartsWith("Filtered"); lk.Add($"{h}: {rs}{(isB == b ? "" : "  <-- UNEXPECTED")}"); if (isB != b) fails.Add("lookup " + h); }
            r["lookups"] = lk;
        }
        catch (Exception ex) { r["blocking"] = "ERROR " + ex.Message; fails.Add("blocking"); }
        // ---- 3.2.0 messaging protection + per-device DNS ----
        try
        {
            var ur = (await SafeGuard.Get("filtering/status"))["user_rules"]?.AsArray().Select(x => (string)x).ToList() ?? new();
            var igb = InstagramAllow.Block(); bool igFirst = ur.Count >= igb.Count && ur.Take(igb.Count).SequenceEqual(igb); r["instagramAllowFirst"] = igFirst; if (!igFirst) fails.Add("instagramAllowBlock");
            var blk = Messaging.Block(); bool first = ur.Count >= igb.Count + blk.Count && ur.Skip(igb.Count).Take(blk.Count).SequenceEqual(blk);
            var ml = new List<string> { $"protected block first and complete: {first}" }; if (!first) fails.Add("messagingAllowlist");
            var snb = SnapchatBlock.Block(); bool snOk = ur.Skip(igb.Count + blk.Count).Take(snb.Count).SequenceEqual(snb); r["snapchatBlockBelowMessaging"] = snOk; if (!snOk) fails.Add("snapchatBlock");
            var dtb = DatingBlock.Block(); bool dtOk = ur.Skip(igb.Count + blk.Count + snb.Count).Take(dtb.Count).SequenceEqual(dtb); r["datingBlockBelowSnapchat"] = dtOk; if (!dtOk) fails.Add("datingBlock");
            if (blk.Any(x => x.StartsWith("@@") && SnapchatBlock.Domains.Any(d => x.Contains(d)))) fails.Add("messagingAllowsSnapchat");
            var rokuIp = SafeGuard.LastClients?.Where(c => ((string)c["name"] ?? "").StartsWith("SG Roku -")).SelectMany(c => c["ids"].AsArray().Select(i => (string)i)).FirstOrDefault(i => i.Count(ch => ch == '.') == 3);
            foreach (var h in Messaging.SelfTestHosts)
                foreach (var who in new[] { (string)null, rokuIp }.Distinct())
                { if (who == null && ml.Any(x => x.StartsWith(h + " (global)"))) continue; var rs = await Blocking.Check(h, who); bool bad = rs.StartsWith("Filtered"); ml.Add($"{h} ({(who == null ? "global" : "Roku " + who)}): {rs}{(bad ? "  <-- BLOCKED" : "")}"); if (bad) fails.Add("messaging " + h); }
            r["messaging"] = ml;
            var (_, own) = await Task.Run(() => Core.RunPs("$e=Get-NetUDPEndpoint -LocalAddress 192.0.2.11 -LocalPort 53 -ErrorAction SilentlyContinue; if($e){ ($e | %{ (Get-Process -Id $_.OwningProcess).Name }) -join ',' } else { 'none' }", 15000));
            r["hotspotDnsListener"] = own.Trim(); if (!own.Contains("AdGuardHome")) fails.Add("perDevice(AdGuard not bound on 192.0.2.11)");
            var ql = await SafeGuard.Get("querylog?limit=500"); var since = DateTime.Now.AddMinutes(-30);
            var hs = (ql["data"]?.AsArray() ?? new JsonArray()).Where(e => DateTime.TryParse((string)e["time"], out var t) && t > since).Select(e => (string)e["client"]).Where(c => c != null && c.StartsWith("192.168.137.") && c != "192.0.2.11").Distinct().ToList();
            r["perClientIps"] = hs; if (hs.Count == 0 && Wallace.Current?.Clients > 0) fails.Add("perClientIps(no hotspot device IPs in querylog)");
        }
        catch (Exception ex) { r["messaging"] = "ERROR " + ex.Message; fails.Add("messaging"); }
        // ---- 3.1.0 admin features ----
        try
        {
            await Admin.EnsureQueryLog();
            var sg = await SafeGuard.Load(); var rokus = sg.Clients.Where(c => ((string)c["name"] ?? "").StartsWith("SG Roku -")).ToList();
            bool want = AppSettings.Current.ExemptRokus; var bad = rokus.Where(c => (bool)c["use_global_settings"] == want).Select(c => (string)c["name"]).ToList();
            var owner = sg.Clients.FirstOrDefault(c => ((string)c["name"] ?? "").Contains("(owner)"));
            r["rokuExemption"] = new { setting = want ? "ON (exempt)" : "OFF (fully filtered)", clients = rokus.Count, mismatched = bad, ownerPhoneExempt = SafeGuard.IsExempt(owner) };
            if (bad.Count > 0 || rokus.Count == 0) fails.Add("rokuExemption"); if (!SafeGuard.IsExempt(owner)) fails.Add("ownerPhoneExempt");
            var rip = rokus.SelectMany(c => c["ids"].AsArray().Select(i => (string)i)).FirstOrDefault(i => i.Count(ch => ch == '.') == 3);
            if (rip != null)
            {
                var lk = new List<string>();
                foreach (var (h, b) in new[] { ("pornhub.com", true), ("doubleclick.net", true), ("ads.roku.com", true), ("logs.roku.com", true), ("cooper.logs.roku.com", true), ("api.roku.com", false), ("googlevideo.com", false), ("www.youtube.com", false), ("sponsor.ajay.app", false) })
                { var rs = await Blocking.Check(h, rip); bool isB = rs.StartsWith("Filtered"); lk.Add($"{h} as Roku {rip}: {rs}{(isB == b ? "" : "  <-- UNEXPECTED")}"); if (isB != b) fails.Add("rokuLookup " + h); }
                r["rokuLookups"] = lk;
            }
            const string tr = "||wallace-selftest.example.org^";
            await Admin.EditCustom(l => l.Add(tr)); bool on = false; // AdGuard rebuilds its filter engine asynchronously after set_rules
            for (int i = 0; i < 30 && !on; i++) { await Task.Delay(1000); on = (await Blocking.Check("wallace-selftest.example.org")).StartsWith("Filtered"); }
            await Admin.EditCustom(l => l.Remove(tr)); var off = !(await Admin.CustomRules()).Contains(tr);
            r["customRuleRoundtrip"] = $"blocked-after-add={on} removed={off}"; if (!on || !off) fails.Add("customRule");
            var q = await SafeGuard.Get("querylog/config"); r["querylog"] = $"enabled={q["enabled"]} days={((long?)q["interval"] ?? 0) / 86400000.0:0.#} anonymize={q["anonymize_client_ip"]}";
            if ((bool?)q["anonymize_client_ip"] == true || (bool?)q["enabled"] != true) fails.Add("querylog");
            var helper = Core.ResText("wnh-admin.ps1"); r["adminHelper"] = helper.Contains("FWPM_LAYER") || helper.Contains("a82acc24") ? "embedded (WFP forward-layer pause)" : "MISSING"; if (!helper.Contains("a82acc24")) fails.Add("adminHelper");
            r["routerFeatures"] = Router.Features.Length;
        }
        catch (Exception ex) { r["admin"] = "ERROR " + ex.Message; fails.Add("admin"); }
        try
        {
            var wi = await Wallace.RefreshAsync();
            r["wallace"] = new { wi.State, wi.Ssid, band = wi.BandText, wi.Clients, hostAdapter = wi.HostDesc, hostAlias = wi.Host, wi.Uplink, wi.Watchdog, adapters = wi.Adapters.Select(a => $"{a.name}: {a.desc} {a.status} {a.link} | {string.Join("; ", a.props)}").ToList(), wi.Error };
            if (!wi.On) fails.Add("wallace(hotspot not On)");
            if (wi.Band != "FiveGigahertz") fails.Add("wallace(band not 5 GHz)");
        }
        catch (Exception ex) { r["wallace"] = "ERROR " + ex.Message; fails.Add("wallace"); }
        try
        {
            // SafeSearch must be forced: AdGuard answers www.google.com with Google's forcesafesearch address (216.239.38.120)
            var (_, o) = await Task.Run(() => Core.RunPs("(Resolve-DnsName www.google.com -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction Stop | ?{ $_.IPAddress } | select -ExpandProperty IPAddress) -join ','", 20000));
            r["safeSearchDns"] = o.Trim(); if (!o.Contains("216.239.38.120")) fails.Add("safeSearch(google not forced)");
            var (_, y) = await Task.Run(() => Core.RunPs("(Resolve-DnsName www.youtube.com -Server 127.0.0.1 -Type A -DnsOnly -ErrorAction Stop | ?{ $_.IPAddress } | select -ExpandProperty IPAddress) -join ','", 20000));
            r["youtubeDns"] = y.Trim(); if (y.Contains("0.0.0.0") || y.Trim() == "" || y.Contains("ERR")) fails.Add("youtube(dns)");
        }
        catch (Exception ex) { r["safeSearchDns"] = "ERROR " + ex.Message; fails.Add("safeSearchDns"); }
        // ---- 3.3.0 encrypted DNS ----
        try
        {
            var es = await EncDns.Load();
            r["encryption"] = new { es.Summary, rows = es.Rows.Select(x => $"{x.Role}: {x.Protocol} {x.Server} enc={x.Encrypted} avg={x.AvgMs}ms").ToList() };
            if (!es.AllEncrypted) fails.Add("encryption: plain upstream/bootstrap/fallback");
            if (!es.Dnssec) fails.Add("encryption: DNSSEC off");
            if (!es.EcsOff) fails.Add("encryption: ECS on");
            bool bogus = await EncDns.DnssecRejectsBogus(); r["dnssecBogusRejected"] = bogus; if (!bogus) fails.Add("encryption: DNSSEC not validating (dnssec-failed.org resolved)");
            var (_, lk) = await Task.Run(() => Core.RunPs("$c=Get-NetTCPConnection -State Established -RemotePort 53 -OwningProcess (Get-Process AdGuardHome -EA 0).Id -EA 0 | ?{ $_.RemoteAddress -notmatch '^(127\\.|192\\.168\\.|::1)' }; @($c).Count", 20000));
            r["leakPlainTcp53"] = lk.Trim(); if (int.TryParse(lk.Trim(), out var n) && n > 0) fails.Add("encryption: plain DNS leak to internet");
            var msgOk = true; foreach (var h in Messaging.SelfTestHosts.Take(2)) { var rs = await Blocking.Check(h); if (rs.StartsWith("Filtered")) msgOk = false; }
            r["messagingAfterEncryption"] = msgOk; if (!msgOk) fails.Add("encryption: messaging blocked");
        }
        catch (Exception ex) { r["encryption"] = "ERROR " + ex.Message; fails.Add("encryption"); }
        try { var up = await Core.CheckUpdates(false).WaitAsync(TimeSpan.FromSeconds(60)); r["updates"] = up.Select(u => $"{u.Item}: installed={u.Installed} latest={u.Latest} -> {u.Verdict}").ToList(); }
        catch (Exception ex) { r["updates"] = "ERROR " + ex.Message; } // informational only (needs internet); never fails the selftest
        Check("blocklistSources", () => { var rows = Task.Run(BlocklistSources.Load).GetAwaiter().GetResult(); if (rows.Count < 15 || rows.Sum(x => x.RuleCount) < 1000000 || !rows.Any(x => x.Category == "Adult/NSFW") || !rows.Any(x => x.Category == "Malware/phishing")) fails.Add("blocklistSources"); return new { lists = rows.Count, rules = rows.Sum(x => x.RuleCount) }; });
        Check("backupsFolders", () => Directory.Exists(Core.BackupRoot) ? Directory.GetDirectories(Core.BackupRoot).Length : -1);
        Check("npcap", () => new { installed = NpcapInfo.Installed, version = NpcapInfo.Version, adminOnly = NpcapInfo.AdminOnly, desktopInstaller = NpcapInfo.DesktopInstaller });
        Check("adapters", () =>
        {
            var l = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces().Select(n => new { n.Name, n.Description, kind = Bandwidth.Classify(n, out var ip), ip, up = n.OperationalStatus.ToString() }).Where(x => x.kind != null).ToList();
            if (!l.Any(x => x.kind == "hotspot")) fails.Add("adapters(hotspot missing)");
            return l;
        });
        Check("ouiEntries", () => { var n = Oui.Count; if (n < 10000) fails.Add("oui"); return n; });
        Check("ouiSample", () => Oui.Lookup("00:00:5E:00:53:01") + " / " + Oui.Lookup("00:00:5E:00:53:02"));
        Check("geoDb", () => { var o = Intel.Owner("8.8.8.8"); if (string.IsNullOrEmpty(o.asn)) fails.Add("geo"); return $"{o.asn} {o.country}"; });
        Check("portName443", () => Intel.PortName(443, "TCP"));
        Check("serviceTag", () => Intel.Tag("rr3---sn-abc.googlevideo.com", "", 443, "TCP") + " / " + Intel.Tag("scribe.logs.roku.com", "", 443, "TCP") + " / " + Intel.Tag("ipv4-c001.1.oca.nflxvideo.net", "", 443, "TCP"));
        Check("blacklistCidr", () => Intel.InCidr("192.0.2.16", "192.0.2.17/16") && !Intel.InCidr("192.0.2.18", "192.0.2.17/16") ? "ok" : throw new Exception("cidr"));
        Check("arpEntries", () => Devices.ReadArp().Count);
        try
        {
            var sw = System.Diagnostics.Stopwatch.StartNew(); var n = await Devices.ScanAsync().WaitAsync(TimeSpan.FromSeconds(150));
            r["scan"] = new { found = n, seconds = Math.Round(sw.Elapsed.TotalSeconds, 1), hotspot = Devices.All.Values.Where(d => d.Online && d.Network == "Hotspot").Select(d => $"{d.Display} {d.Ip}").ToList(), lan = Devices.All.Values.Count(d => d.Online && d.Network == "Home LAN"), devices = Devices.All.Values.Where(d => d.Online).OrderBy(d => d.Network).ThenBy(d => System.Version.TryParse(d.Ip, out var v) ? v : new System.Version()).Select(d => new { d.Network, d.Ip, d.Mac, d.Vendor, d.Type, name = d.Display, d.HostName, d.NbName, d.MdnsName, d.Upnp, d.WebInfo, ports = d.PortsText, d.LatencyMs }).ToList() };
            if (n < 0) fails.Add("scan");
        }
        catch (Exception ex) { r["scan"] = "ERROR " + ex.Message; fails.Add("scan"); }
        try
        {
            Monitors.Sync(); await Monitors.RunAllAsync().WaitAsync(TimeSpan.FromSeconds(30));
            lock (Monitors.Gate) r["monitors"] = Monitors.States.Select(s => $"{s.Def.Name}: {(s.Up == true ? "UP" : "DOWN")} {s.Ms:0}ms {s.Note}").ToList();
        }
        catch (Exception ex) { r["monitors"] = "ERROR " + ex.Message; fails.Add("monitors"); }
        try { Bandwidth.Start(); await Task.Delay(2500); lock (Bandwidth.Gate) r["bandwidth"] = Bandwidth.Series.Values.Select(s => $"{s.Key}: present={s.Present} in={Core.Rate(s.CurIn)} out={Core.Rate(s.CurOut)}").ToList(); }
        catch (Exception ex) { r["bandwidth"] = "ERROR " + ex.Message; fails.Add("bandwidth"); }
        if (NpcapInfo.Installed)
        {
            try { Capture.Start(); await Task.Delay(4000); var st = Capture.Status; r["capture"] = new { status = st, Capture.Packets, conns = Capture.Conns.Count, names = Intel.Names.Count }; Capture.Stop(); if (!st.StartsWith("Capturing")) fails.Add("capture"); }
            catch (Exception ex) { r["capture"] = "ERROR " + ex.Message; fails.Add("capture"); }
        }
        else r["capture"] = "skipped: Npcap not installed (app shows the 'Install Npcap' card instead)";
        Check("reports", () => Reports.WriteAll(Path.Combine(Core.DataDir, "selftest-reports")));
        Check("devicesNoDuplicates", () =>
        {
            Devices.Dedupe(true); var v = Devices.All.Values.ToList();
            var dupIp = v.Where(d => d.Online && d.Ip != null).GroupBy(d => d.Ip).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            var merged = Devices.Merged(SafeGuard.LastClients); var dupMac = merged.Where(d => d.Mac != null).GroupBy(d => d.Mac, StringComparer.OrdinalIgnoreCase).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
            if (dupIp.Count > 0 || dupMac.Count > 0) fails.Add("devicesNoDuplicates");
            return new { cached = v.Count, merged = merged.Count, dupOnlineIps = dupIp, dupMacs = dupMac, rows = merged.Select(d => $"{d.Display} {d.Ip} {d.Mac} {d.Network} {(d.Online ? "online" : "offline")}").ToList() };
        });
        try
        {
            var ev = await BlockReport.Load(DateTime.Now.AddHours(-24), DateTime.Now);
            var f = BlockReport.Pdf(ev, DateTime.Now.AddHours(-24), DateTime.Now, "WALLACE blocked-content report (self-test sample)", Path.Combine(Core.DataDir, "selftest-reports"));
            var len = new FileInfo(f).Length; r["blockReportPdf"] = new { file = f, bytes = len, events = ev.Count, byCategory = ev.GroupBy(e => e.Category).ToDictionary(g => g.Key, g => g.Count()), exact = ev.Count(e => e.Attribution.StartsWith("exact")) };
            if (len < 2000) fails.Add("blockReportPdf");
        }
        catch (Exception ex) { r["blockReportPdf"] = "ERROR " + ex.Message; fails.Add("blockReportPdf"); }
        Check("guiConstructs", () =>
        {
            var w = new MainWindow(); foreach (var p in w.PageNames) w.Navigate(p);
            var mini = new MiniWindow(); mini.Close(); w.Close(); return $"ok ({w.PageNames.Count} pages)";
        });
        r["failures"] = fails; r["result"] = fails.Count == 0 ? "PASS" : "FAIL";
        File.WriteAllText(Path.Combine(Core.DataDir, "selftest.json"), Core.Redact(JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true })), new UTF8Encoding(false));
        return fails.Count == 0 ? 0 : 1;
    }
}
