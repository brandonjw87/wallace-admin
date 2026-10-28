using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;

namespace WNH;

/// <summary>3.3.0: encrypted-DNS status, research check (GitHub) and safe apply with backup + automatic rollback.
/// Only touches AdGuard's DNS upstream settings (dns_config) - never user rules, so the Messaging guard is unaffected.</summary>
public static class EncDns
{
    // Recommended set, chosen from MSI benchmarks (Oct 2026): Quad9 (malware filtering + DNSSEC) over DNSCrypt and DoH3, Cloudflare security over DoH3.
    public const string Quad9DnsCryptName = "quad9-dnscrypt-ip4-filter-pri";
    public const string Quad9DnsCryptStamp = "sdns://AQMAAAAAAAAADDkuOS45Ljk6ODQ0MyBnyEe4yHWM0SAkVUO-dWdG3zTfHYTAC4xHA2jfgh2GPhkyLmRuc2NyeXB0LWNlcnQucXVhZDkubmV0";
    public static readonly string[] RecUpstreams = { Quad9DnsCryptStamp, "h3://dns.quad9.net/dns-query", "h3://security.cloudflare-dns.com/dns-query" };
    public static readonly string[] RecBootstrap = { "tls://9.9.9.9", "tls://149.112.112.112", "tls://1.1.1.2", "tls://1.0.0.2" };
    public static readonly string[] RecFallback = { "tls://dns.quad9.net", "tls://security.cloudflare-dns.com", "quic://unfiltered.adguard-dns.com" };
    public const string MinAdGuard = "v0.107.79";

    public record UpRow(string Role, string Server, string Protocol, string Encrypted, string AvgMs);
    public record Status(List<UpRow> Rows, bool Dnssec, bool EcsOff, string Mode, int Timeout, bool AllEncrypted, string Summary);

    public static string Proto(string u)
    {
        u = (u ?? "").Trim();
        if (u.StartsWith("[/")) { var i = u.IndexOf("/]"); if (i > 0) u = u[(i + 2)..]; }
        if (u.StartsWith("sdns://")) return u.Length > 8 && u[7] == 'A' && u[8] == 'Q' ? "DNSCrypt" : u.StartsWith("sdns://Ag") ? "DoH (stamp)" : u.StartsWith("sdns://Aw") ? "DoT (stamp)" : u.StartsWith("sdns://BA") ? "DoQ (stamp)" : u.StartsWith("sdns://BQ") ? "ODoH (stamp)" : "stamp";
        if (u.StartsWith("h3://")) return "DoH3 (HTTP/3 QUIC)";
        if (u.StartsWith("https://")) return "DoH (HTTP/2)";
        if (u.StartsWith("quic://")) return "DoQ (QUIC)";
        if (u.StartsWith("tls://")) return "DoT (TLS)";
        if (u.StartsWith("tcp://")) return "PLAIN TCP";
        return "PLAIN UDP";
    }
    public static bool IsEncrypted(string u) => !Proto(u).StartsWith("PLAIN");
    static bool IsPrivate(string u) => Regex.IsMatch(u ?? "", @"^(udp://|tcp://)?(192\.168\.|10\.|127\.|172\.(1[6-9]|2\d|3[01])\.)");

    static string Key(string u) { if (u.StartsWith("h3://")) u = "https://" + u[5..]; var m = Regex.Match(u, @"^(https|tls|quic)://([^/:]+)(:\d+)?(/.*)?$"); if (!m.Success) return u; var port = m.Groups[3].Success && m.Groups[3].Value != "" ? m.Groups[3].Value : m.Groups[1].Value == "https" ? ":443" : ":853"; return $"{m.Groups[1].Value}://{m.Groups[2].Value}{port}{m.Groups[4].Value}"; }

    public static async Task<Status> Load()
    {
        var d = await SafeGuard.Get("dns_info");
        var avg = new Dictionary<string, double>();
        try { var st = await SafeGuard.Get("stats"); foreach (var o in st["top_upstreams_avg_time"]?.AsArray() ?? new JsonArray()) foreach (var kv in o.AsObject()) avg[kv.Key] = (double)kv.Value * 1000; } catch { }
        var rows = new List<UpRow>();
        void Add(string role, JsonNode arr) { foreach (var x in arr?.AsArray() ?? new JsonArray()) { var u = (string)x; if (string.IsNullOrWhiteSpace(u) || u.StartsWith("#")) continue; var ms = avg.TryGetValue(Key(u), out var a) ? Math.Round(a).ToString() : avg.TryGetValue(u, out a) ? Math.Round(a).ToString() : "-"; rows.Add(new(role, u.StartsWith("sdns://") ? "DNSCrypt stamp " + u[..20] + "..." : u, Proto(u), IsEncrypted(u) ? "yes" : "NO", ms)); } }
        Add("upstream", d["upstream_dns"]); Add("bootstrap", d["bootstrap_dns"]); Add("fallback", d["fallback_dns"]);
        foreach (var x in d["local_ptr_upstreams"]?.AsArray() ?? new JsonArray()) rows.Add(new("LAN reverse-lookup", (string)x, "plain (LAN only, never leaves the house)", "n/a", avg.TryGetValue((string)x + ":53", out var p) ? Math.Round(p).ToString() : "-"));
        bool all = rows.Where(r => r.Role is "upstream" or "bootstrap" or "fallback").All(r => r.Encrypted == "yes");
        bool dnssec = (bool?)d["dnssec_enabled"] == true, ecsOff = (bool?)d["edns_cs_enabled"] != true;
        string mode = (string)d["upstream_mode"]; if (string.IsNullOrEmpty(mode)) mode = "load_balance";
        int to = (int?)d["upstream_timeout"] ?? 0;
        string sum = $"{(all ? "All upstream, bootstrap and fallback DNS is encrypted" : "WARNING: some DNS leaves the house unencrypted")} - DNSSEC {(dnssec ? "ON" : "OFF")} - ECS {(ecsOff ? "off (private)" : "ON")} - mode {mode} - timeout {to}s";
        return new(rows, dnssec, ecsOff, mode, to, all, sum);
    }

    public record Finding(string Item, string Detail, string Action);
    /// <summary>Pulls latest AdGuardHome + dnscrypt-proxy releases and the DNSCrypt public resolver list from GitHub, compares with current config.</summary>
    public static async Task<(List<Finding> findings, bool canUpgrade)> CheckStronger()
    {
        var f = new List<Finding>(); bool up = false;
        var st = await Load();
        var agLatest = await Core.LatestRelease("AdguardTeam/AdGuardHome"); var agHave = await SafeGuard.Version() ?? "?";
        f.Add(new("AdGuard Home", $"installed {agHave}, latest {agLatest}", Newer(agLatest, agHave) ? "Update AdGuard Home (newer encryption/QUIC fixes) - Updates grid below / AdGuard dashboard" : "up to date"));
        var dcLatest = await Core.LatestRelease("DNSCrypt/dnscrypt-proxy");
        f.Add(new("dnscrypt-proxy (reference)", "latest " + dcLatest, "Info only: AdGuard already speaks DNSCrypt/DoH3/DoQ natively, so no extra proxy is needed"));
        try
        {
            var md = await Core.Http.GetStringAsync("https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md");
            var m = Regex.Match(md, $@"(?ms)^## {Regex.Escape(Quad9DnsCryptName)}\s*\n.*?(sdns://\S+)");
            if (!m.Success) f.Add(new("DNSCrypt resolver list", Quad9DnsCryptName + " no longer listed", "Keep DoH3/DoT upstreams; review list manually"));
            else if (m.Groups[1].Value != Quad9DnsCryptStamp) { f.Add(new("DNSCrypt resolver list", "Quad9 DNSCrypt stamp changed upstream", "Apply will switch to the new stamp")); up = true; newStamp = m.Groups[1].Value; }
            else f.Add(new("DNSCrypt resolver list", "Quad9 DNSCrypt stamp still current (" + Regex.Matches(md, "(?m)^## ").Count + " resolvers listed)", "ok"));
            int odoh = Regex.Matches(md, @"sdns://BQ").Count; f.Add(new("ODoH (oblivious DoH)", $"{odoh} ODoH targets in list", "Not used: AdGuard Home 0.107 has no ODoH relay support; Quad9/Cloudflare + ECS off + no logging (Quad9) is the practical best"));
        }
        catch (Exception ex) { f.Add(new("DNSCrypt resolver list", "check failed: " + ex.Message, "")); }
        if (!st.AllEncrypted) { f.Add(new("Plain DNS in config", string.Join(", ", st.Rows.Where(r => r.Encrypted == "NO").Select(r => r.Server)), "Apply will replace with encrypted servers")); up = true; }
        if (!st.Dnssec) { f.Add(new("DNSSEC", "off", "Apply will enable DNSSEC validation")); up = true; }
        if (!st.EcsOff) { f.Add(new("EDNS Client Subnet", "on (leaks your subnet)", "Apply will turn it off")); up = true; }
        var cur = (await SafeGuard.Get("dns_info"))["upstream_dns"]?.AsArray().Select(x => (string)x).ToList() ?? new();
        var missing = RecUpstreams.Where(r => !cur.Contains(r) && !(r == Quad9DnsCryptStamp && newStamp != null)).ToList();
        if (missing.Count > 0) { f.Add(new("Recommended upstreams", "missing: " + string.Join(", ", missing.Select(x => x.StartsWith("sdns") ? "Quad9 DNSCrypt" : x)), "Apply will set the recommended encrypted set")); up = true; }
        if (!up) f.Add(new("Result", "Already on the strongest recommended setup", "nothing to do"));
        File.WriteAllText(Path.Combine(Core.DataDir, "encdns-lastcheck.json"), JsonSerializer.Serialize(new { at = DateTime.Now, canUpgrade = up, findings = f }, new JsonSerializerOptions { WriteIndented = true }));
        return (f, up);
    }
    static string newStamp;
    static bool Newer(string a, string b) { Version Pv(string s) { var m = Regex.Match(s ?? "", @"(\d+)\.(\d+)\.(\d+)"); return m.Success ? new Version(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value), int.Parse(m.Groups[3].Value)) : null; } var x = Pv(a); var y = Pv(b); return x != null && y != null && x > y; }

    /// <summary>Backs up dns_info to dev-config-backup\pre-encdns-*, applies the recommended encrypted set, verifies lookups, rolls back if DNS breaks.</summary>
    public static async Task<string> Apply()
    {
        var old = await SafeGuard.Get("dns_info");
        var dir = Path.Combine(Core.BackupRoot, "pre-encdns-" + DateTime.Now.ToString("yyyyMMdd-HHmmss")); Directory.CreateDirectory(dir);
        File.WriteAllText(Path.Combine(dir, "dns_info.json"), old.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        var ups = RecUpstreams.Select(u => u == Quad9DnsCryptStamp && newStamp != null ? newStamp : u).ToArray();
        JsonArray A(IEnumerable<string> s) => new(s.Select(x => (JsonNode)x).ToArray());
        var body = new JsonObject { ["upstream_dns"] = A(ups), ["bootstrap_dns"] = A(RecBootstrap), ["fallback_dns"] = A(RecFallback), ["upstream_mode"] = "load_balance", ["dnssec_enabled"] = true, ["edns_cs_enabled"] = false, ["cache_optimistic"] = true, ["upstream_timeout"] = 5 };
        var test = await SafeGuard.Get_Post("test_upstream_dns", new JsonObject { ["upstream_dns"] = A(ups), ["bootstrap_dns"] = A(RecBootstrap), ["private_upstream"] = new JsonArray() });
        var bad = test.AsObject().Where(kv => (string)kv.Value != "OK").Select(kv => kv.Key).ToList();
        if (bad.Count == ups.Length) return "Not applied: none of the recommended upstreams answered (" + string.Join(", ", bad) + ")";
        await SafeGuard.Send("POST", "dns_config", body);
        await Task.Delay(2000);
        int fails = 0; foreach (var h in new[] { "example.com", "api.roku.com", "www.youtube.com" }) if (!await Resolves(h)) fails++;
        if (fails >= 2)
        {
            var rb = new JsonObject(); foreach (var k in new[] { "upstream_dns", "bootstrap_dns", "fallback_dns", "upstream_mode", "dnssec_enabled", "edns_cs_enabled", "cache_optimistic", "upstream_timeout" }) rb[k] = old[k]?.DeepClone();
            await SafeGuard.Send("POST", "dns_config", rb);
            Core.Log("encdns: apply failed lookups, rolled back"); return "Rolled back: DNS lookups failed after the change. Backup: " + dir;
        }
        Core.Log("encdns: applied recommended encrypted set; backup " + dir);
        return "Applied. Backup: " + dir + (bad.Count > 0 ? " (note: not answering now: " + string.Join(", ", bad) + ")" : "");
    }
    public static async Task<bool> Resolves(string host)
    {
        var (_, o) = await Task.Run(() => Core.RunPs($"try {{ (Resolve-DnsName '{host}' -Server 127.0.0.1 -DnsOnly -Type A -ErrorAction Stop | ?{{ $_.IPAddress }} | select -First 1).IPAddress }} catch {{ 'ERR' }}", 20000));
        return Regex.IsMatch(o.Trim(), @"^\d+\.\d+\.\d+\.\d+") && !o.Contains("0.0.0.0");
    }
    public static async Task<bool> DnssecRejectsBogus()
    {
        var (_, o) = await Task.Run(() => Core.RunPs("try { Resolve-DnsName dnssec-failed.org -Server 127.0.0.1 -DnsOnly -Type A -ErrorAction Stop | Out-Null; 'RESOLVED' } catch { 'FAIL' }", 20000));
        return o.Contains("FAIL");
    }

    // ---- weekly check: in-app (on start, if >7 days) + a per-user scheduled task (no admin) running --encdns-check ----
    public static string LastCheckFile => Path.Combine(Core.DataDir, "encdns-lastcheck.json");
    public static void StartWeekly()
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var (c, o) = Core.RunPs("schtasks /Query /TN 'WALLACE Admin encryption check' 2>$null | Out-Null; $LASTEXITCODE", 20000);
                if (o.Trim() != "0") { var exe = Environment.ProcessPath; Core.RunPs($"schtasks /Create /F /SC WEEKLY /D SUN /ST 10:00 /TN 'WALLACE Admin encryption check' /TR '\\\"{exe}\\\" --encdns-check' | Out-Null", 20000); Core.Log("encdns: weekly per-user task registered"); }
                await Task.Delay(TimeSpan.FromMinutes(2));
                if (!File.Exists(LastCheckFile) || DateTime.Now - File.GetLastWriteTime(LastCheckFile) > TimeSpan.FromDays(7)) await RunScheduled();
            }
            catch (Exception ex) { Core.Log("encdns weekly: " + ex.Message); }
        });
    }
    public static async Task RunScheduled()
    {
        var (f, up) = await CheckStronger();
        if (up) Alerts.Raise("encdns", "yellow", "Stronger DNS encryption available", "Open Updates > Encryption to review and apply (backup + auto-rollback).", 60 * 24);
        else Core.Log("encdns: weekly check - already strongest");
    }
}

public class EncryptionPanel
{
    public static UIElement Build()
    {
        var sum = UI.T("loading encryption status.", 13, null, null, true);
        var grid = UI.Grid(UI.Col("Role", "Role", 110), UI.Col("Server", "Server", 330), UI.Col("Protocol", "Protocol", 200), UI.Col("Encrypted", "Encrypted", 80), UI.Col("Avg ms (24h)", "AvgMs", 100));
        grid.MaxHeight = 220;
        var fgrid = UI.Grid(UI.Col("Item", "Item", 200), UI.Col("Detail", "Detail", 360), UI.Col("Recommendation", "Action", 420)); fgrid.MaxHeight = 200;
        var info = UI.T("", 12, null, UI.Sub);
        var last = UI.T(File.Exists(EncDns.LastCheckFile) ? "   last check " + File.GetLastWriteTime(EncDns.LastCheckFile).ToString("g") + " (weekly, Sun 10:00)" : "   weekly check: Sun 10:00", 12, null, UI.Sub);
        Button apply = null;
        async Task Reload() { try { var s = await EncDns.Load(); grid.ItemsSource = s.Rows; sum.Text = s.Summary; sum.Foreground = s.AllEncrypted && s.Dnssec ? UI.Green : UI.Yellow; } catch (Exception ex) { sum.Text = "AdGuard not reachable: " + ex.Message; sum.Foreground = UI.Red; } }
        Button chk = null;
        chk = UI.Btn("Check for stronger encryption", async () =>
        {
            chk.IsEnabled = false; info.Text = "   checking GitHub (AdGuardHome, dnscrypt-proxy, DNSCrypt resolvers).";
            try { var (f, up) = await EncDns.CheckStronger(); fgrid.ItemsSource = f; apply.IsEnabled = up; info.Text = up ? "   upgrade available - press Apply" : "   already strongest"; last.Text = "   last check " + DateTime.Now.ToString("g"); }
            catch (Exception ex) { info.Text = "   failed: " + ex.Message; }
            finally { chk.IsEnabled = true; }
        }, true, "\uE72E");
        apply = UI.Btn("Apply recommended (backup + rollback)", async () =>
        {
            if (!Admin.Confirm("Apply the recommended encrypted DNS upstreams?\nA backup is saved first and the change is rolled back automatically if lookups fail.\nBlocking rules and the messaging allowlist are not touched.")) return;
            apply.IsEnabled = false; info.Text = "   applying.";
            try { info.Text = "   " + await EncDns.Apply(); await Reload(); } catch (Exception ex) { info.Text = "   failed: " + ex.Message; }
        }, false, "\uE8FB");
        apply.IsEnabled = false;
        var bar = UI.Row(chk, new Border { Width = 8 }, apply, new Border { Width = 8 }, UI.Btn("Refresh", () => _ = Reload(), false, "\uE72C"), info, last); P.Center(bar);
        _ = Reload();
        return UI.Card(UI.Col(UI.H("Encryption (DNS)"), sum, new Border { Height = 8 }, grid, new Border { Height = 8 }, bar, fgrid), 12);
    }
}
