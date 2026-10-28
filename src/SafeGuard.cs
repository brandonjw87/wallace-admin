using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace WNH;

/// <summary>Safe Guard: adult / Instagram / social / SafeSearch / bypass blocking through the local AdGuard Home API.
/// Credentials are read from the local admin file only to build the auth header; they are never logged or shown.</summary>
public static class SafeGuard
{
    const string Base = "http://127.0.0.1:3000/control/";
    public static readonly (string name, string url, bool core)[] AdultLists =
    {
        ("Safe Guard: HaGeZi NSFW", "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/nsfw.txt", true),
        ("Safe Guard: OISD NSFW", "https://nsfw.oisd.nl", true),
        ("Safe Guard: StevenBlack porn-only", "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn-only/hosts", true),
        ("Safe Guard: Block List Project porn (optional)", "https://blocklistproject.github.io/Lists/adguard/porn-ags.txt", false),
    };
    public static readonly string[] BypassListUrls = { "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/doh.txt", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/doh-vpn-proxy-bypass.txt" };
    public static readonly string[] BypassRules = { "||mask.icloud.com^", "||mask-h2.icloud.com^", "||use-application-dns.net^" };
    public static readonly string[] GoogleAllow = { "@@|google.com^", "@@|www.google.com^" };
    public static readonly string[] OtherSocial = { "tiktok", "snapchat", "facebook", "twitter", "reddit", "discord", "tinder", "onlyfans" };
    const string BypBegin = "! SafeGuard:bypass begin", BypEnd = "! SafeGuard:bypass end", Paused = "! SG-paused ";

    static HttpClient http;
    static HttpClient Http()
    {
        if (http != null) return http;
        lock (httpLock) { if (http != null) return http;
        var t = File.ReadAllText(Path.Combine(Core.Tools, @"AdGuardHome\ADMIN-LOGIN.txt"));
        string u = Regex.Match(t, @"(?i)user\w*\s*[:=]\s*(\S+)").Groups[1].Value, p = Regex.Match(t, @"(?i)pass\w*\s*[:=]\s*(\S+)").Groups[1].Value;
        var h = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        h.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(u + ":" + p)));
        return http = h; }
    }
    static readonly object httpLock = new();
    /// <summary>Sends; on 401 drops the cached client, re-reads ADMIN-LOGIN.txt and retries once (fixes stale credentials after AdGuard restart/update).</summary>
    static async Task<HttpResponseMessage> Do(Func<HttpRequestMessage> mk)
    {
        var r = await Http().SendAsync(mk());
        if (r.StatusCode == System.Net.HttpStatusCode.Unauthorized) { Core.Log("safeguard: 401 from AdGuard, reloading credentials and retrying"); lock (httpLock) http = null; r = await Http().SendAsync(mk()); }
        return r;
    }
    /// <summary>AdGuard Home version from /control/status (works even though the AdGuardHome folder is admin-only).</summary>
    public static async Task<string> Version() { try { var s = await Get("status"); var v = (string)s["version"]; return string.IsNullOrEmpty(v) ? null : (v.StartsWith("v") ? v : "v" + v); } catch { return null; } }
    public static async Task<JsonNode> Get(string path) { var r = await Do(() => new HttpRequestMessage(HttpMethod.Get, Base + path)); r.EnsureSuccessStatusCode(); return JsonNode.Parse(await r.Content.ReadAsStringAsync()); }
    /// <summary>3.3.0: POST that returns the JSON reply (used by encrypted-DNS upstream tests). Never used for user rules.</summary>
    public static async Task<JsonNode> Get_Post(string path, JsonNode body)
    {
        if (path.StartsWith("filtering/")) throw new InvalidOperationException("use Send for filtering writes (messaging guard)");
        HttpRequestMessage Mk() { var req = new HttpRequestMessage(HttpMethod.Post, Base + path) { Content = new StringContent(body?.ToJsonString() ?? "{}", Encoding.UTF8, "application/json") }; req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json"); return req; }
        var r = await Do(Mk); r.EnsureSuccessStatusCode(); return JsonNode.Parse(await r.Content.ReadAsStringAsync());
    }
    public static async Task Send(string method, string path, JsonNode body)
    {
        // 3.2.0: every user-rule write is forced through the messaging guard (messaging can never be blocked, and the protected block stays first)
        if (path == "filtering/set_rules" && body is JsonObject bo) bo["rules"] = new JsonArray(Messaging.Enforce((bo["rules"]?.AsArray() ?? new JsonArray()).Select(x => (string)x)).Select(x => (JsonNode)x).ToArray());
        HttpRequestMessage Mk() { var req = new HttpRequestMessage(new HttpMethod(method), Base + path) { Content = new StringContent(body?.ToJsonString() ?? "{}", Encoding.UTF8, "application/json") }; req.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json"); return req; } // AdGuard 0.107.7x rejects "; charset=utf-8"
        var r = await Do(Mk);
        if (!r.IsSuccessStatusCode) throw new Exception($"AdGuard {path}: {(int)r.StatusCode} {await r.Content.ReadAsStringAsync()}");
    }

    public class State
    {
        public bool Reachable; public string Error = "";
        public bool Snapchat, Dating; public bool Adult, AdultExtra, Instagram, Social, SafeSearch, Bypass, Parental;
        public List<string> BlockedIds = new(); public JsonArray Clients = new(); public HashSet<long> SgFilterIds = new();
        public int Blocked24h; public List<(string domain, int n)> Top = new();
        public bool Master => Adult || Instagram || Social || SafeSearch;
    }

    public static async Task<State> Load()
    {
        var s = new State();
        try
        {
            var f = await Get("filtering/status");
            var filters = f["filters"]?.AsArray() ?? new JsonArray();
            bool En(string url) => filters.Any(x => (string)x["url"] == url && (bool)x["enabled"]);
            foreach (var x in filters) if (((string)x["name"] ?? "").StartsWith("Safe Guard")) s.SgFilterIds.Add((long)x["id"]);
            s.Adult = AdultLists.Where(a => a.core).All(a => En(a.url)); s.AdultExtra = En(AdultLists[3].url);
            var rules = (f["user_rules"]?.AsArray() ?? new JsonArray()).Select(r => (string)r).ToList();
            s.Bypass = rules.Contains(BypBegin) && BypassListUrls.All(En);
            var ss = await Get("safesearch/status"); s.SafeSearch = (bool)ss["enabled"] && !GoogleAllow.Any(rules.Contains);
            s.Parental = (bool)(await Get("parental/status"))["enabled"];
            var bs = await Get("blocked_services/get"); s.BlockedIds = (bs["ids"]?.AsArray() ?? new JsonArray()).Select(x => (string)x).ToList();
            s.Instagram = s.BlockedIds.Contains("instagram"); s.Snapchat = s.BlockedIds.Contains(SnapchatBlock.ServiceId); s.Dating = s.BlockedIds.Contains("tinder") && rules.Contains(DatingBlock.Begin); s.Social = OtherSocial.All(s.BlockedIds.Contains);
            s.Clients = (await Get("clients"))["clients"]?.AsArray() ?? new JsonArray(); LastClients = s.Clients;
            var q = await Get("querylog?response_status=blocked&limit=1000"); var since = DateTime.Now.AddHours(-24); var tally = new Dictionary<string, int>();
            foreach (var e in q["data"]?.AsArray() ?? new JsonArray())
            {
                if (!DateTime.TryParse((string)e["time"], out var t) || t < since) continue;
                string reason = (string)e["reason"] ?? ""; bool sg = reason is "FilteredBlockedService" or "FilteredParental" or "FilteredSafeSearch";
                foreach (var r in e["rules"]?.AsArray() ?? new JsonArray()) if (r?["filter_list_id"] != null && s.SgFilterIds.Contains((long)r["filter_list_id"])) sg = true;
                if (!sg) continue; s.Blocked24h++; var d = (string)e["question"]?["name"] ?? "?"; tally[d] = tally.GetValueOrDefault(d) + 1;
            }
            s.Top = tally.OrderByDescending(k => k.Value).Take(8).Select(k => (k.Key, k.Value)).ToList();
            s.Reachable = true;
        }
        catch (Exception ex) { s.Error = Core.Redact(ex.Message); Core.Log("safeguard load: " + ex.Message); }
        return s;
    }

    public static async Task SetAdult(bool on, bool extra)
    {
        var f = await Get("filtering/status"); var filters = f["filters"]?.AsArray() ?? new JsonArray();
        foreach (var a in AdultLists)
        {
            bool want = on && (a.core || extra);
            if (!filters.Any(x => (string)x["url"] == a.url)) { if (!want) continue; await Send("POST", "filtering/add_url", new JsonObject { ["name"] = a.name, ["url"] = a.url, ["whitelist"] = false }); }
            await Send("POST", "filtering/set_url", new JsonObject { ["url"] = a.url, ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = a.name, ["url"] = a.url, ["enabled"] = want } });
        }
        await Send("POST", on ? "parental/enable" : "parental/disable", new JsonObject());
    }

    public static async Task SetServices(bool insta, bool social)
    {
        var cur = (await Get("blocked_services/get"))["ids"]?.AsArray().Select(x => (string)x).ToList() ?? new();
        cur.Remove("instagram"); cur.RemoveAll(OtherSocial.Contains);
        /* 3.4.1: Instagram is always allowed (owner rule) - the instagram service is never re-added */ if (social) cur.AddRange(OtherSocial); cur.Add(SnapchatBlock.ServiceId); try { var known = (await Get("blocked_services/all"))["blocked_services"]?.AsArray().Select(x => (string)x["id"]).ToHashSet() ?? new(); cur.AddRange(DatingBlock.ServiceIds.Where(known.Contains)); } catch { cur.Add("tinder"); } /* 3.4.2: Snapchat always blocked on WALLACE */
        await Send("PUT", "blocked_services/update", new JsonObject { ["ids"] = new JsonArray(cur.Distinct().Select(x => (JsonNode)x).ToArray()), ["schedule"] = new JsonObject { ["time_zone"] = "Local" } });
    }

    static async Task EditRules(Func<List<string>, List<string>> edit)
    {
        var f = await Get("filtering/status"); var rules = (f["user_rules"]?.AsArray() ?? new JsonArray()).Select(r => (string)r).Where(r => r != "").ToList();
        rules = edit(rules); await Send("POST", "filtering/set_rules", new JsonObject { ["rules"] = new JsonArray(rules.Select(r => (JsonNode)r).ToArray()) });
    }

    /// <summary>YouTube stays unrestricted globally on purpose: hotspot Rokus share one DNS identity (see coverage note).</summary>
    public static async Task SetSafeSearch(bool on)
    {
        await Send("PUT", "safesearch/settings", new JsonObject { ["enabled"] = on, ["bing"] = true, ["duckduckgo"] = true, ["ecosia"] = true, ["google"] = true, ["pixabay"] = true, ["yandex"] = true, ["youtube"] = false });
        // the pre-existing google.com allow rules override SafeSearch rewrites, so pause them (commented, never deleted) while SafeSearch is on
        await EditRules(r => r.Select(x => on && GoogleAllow.Contains(x) ? Paused + x : !on && x.StartsWith(Paused) && GoogleAllow.Contains(x[Paused.Length..]) ? x[Paused.Length..] : x).ToList());
    }

    public static async Task SetBypass(bool on)
    {
        await EditRules(r =>
        {
            int b = r.IndexOf(BypBegin), e = r.IndexOf(BypEnd); if (b >= 0 && e > b) r.RemoveRange(b, e - b + 1);
            if (on) { r.Add(BypBegin); r.AddRange(BypassRules); r.Add(BypEnd); }
            return r;
        });
        var f = await Get("filtering/status");
        foreach (var x in f["filters"]?.AsArray() ?? new JsonArray())
            if (BypassListUrls.Contains((string)x["url"]))
                await Send("POST", "filtering/set_url", new JsonObject { ["url"] = (string)x["url"], ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = (string)x["name"], ["url"] = (string)x["url"], ["enabled"] = on } });
    }

    // ---- devices / exemptions ----
    public static JsonArray LastClients;
    public static bool IsRokuDevice(Device d, HashSet<string> macs) => macs.Contains(d.Mac ?? "") || AppSettings.Current.DeviceTypes.GetValueOrDefault(d.Mac ?? "") == "Roku" || (d.Vendor ?? "").Contains("Roku", StringComparison.OrdinalIgnoreCase) || (d.Display ?? "").Contains("Roku", StringComparison.OrdinalIgnoreCase);
    /// <summary>Owner toggle 'Exempt Rokus from Safe Guard'. ON = "roku" mode (own settings, ad lists only); OFF = global settings (every block).</summary>
    public static async Task SetRokuExempt(bool exempt)
    {
        AppSettings.Current.ExemptRokus = exempt; AppSettings.Save();
        var st = await Load(); var mode = exempt ? "roku" : "filtered";
        try
        {
            foreach (var l in File.ReadAllLines(Path.Combine(Core.Tools, @"roku-dhcp\roku-macs.txt")).Where(l => !l.TrimStart().StartsWith("#") && l.Contains(',')))
            { var p = l.Split(','); var mac = p[0].Trim(); var ip = p.Length > 1 ? p[1].Trim() : ""; var nm = p.Length > 2 ? p[2].Trim() : mac; await SetDevice(st.Clients, nm, ip, mac, mode, "Roku - "); st = await Load(); }
        }
        catch (Exception ex) { Core.Log("roku clients: " + ex.Message); }
        foreach (var c in st.Clients.Where(c => ((string)c["name"] ?? "").StartsWith("SG Roku -")).ToList())
        {
            var name = (string)c["name"]; var ids = c["ids"].AsArray().Select(i => (string)i);
            await Send("POST", "clients/update", new JsonObject { ["name"] = name, ["data"] = ClientBody(name, ids, mode, c["tags"]?.DeepClone() as JsonArray) });
        }
        await Blocking.EnsureAllow();
        Core.Log("Roku exemption -> " + (exempt ? "ON" : "OFF (fully filtered)"));
    }
    public static HashSet<string> RokuMacs()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try { foreach (var l in File.ReadAllLines(Path.Combine(Core.Tools, @"roku-dhcp\roku-macs.txt"))) if (!l.TrimStart().StartsWith("#") && l.Contains(',')) set.Add(l.Split(',')[0].Trim()); } catch { }
        return set;
    }
    public static JsonNode FindClient(JsonArray clients, string ip, string mac) =>
        clients.FirstOrDefault(c => (c["ids"]?.AsArray() ?? new JsonArray()).Any(i => string.Equals((string)i, ip, StringComparison.OrdinalIgnoreCase) || (mac != null && string.Equals((string)i, mac, StringComparison.OrdinalIgnoreCase))));
    public static bool IsExempt(JsonNode c) => c != null && !(bool)c["use_global_settings"] && !(bool)c["filtering_enabled"];

    static JsonObject ClientBody(string name, IEnumerable<string> ids, string mode, JsonArray tags)
    {
        bool exempt = mode == "exempt", roku = mode == "roku";
        return new JsonObject
        {
            ["name"] = name, ["ids"] = new JsonArray(ids.Distinct(StringComparer.OrdinalIgnoreCase).Select(i => (JsonNode)i).ToArray()), ["tags"] = tags ?? new JsonArray(),
            ["use_global_settings"] = !(exempt || roku), ["filtering_enabled"] = !exempt, ["parental_enabled"] = false, ["safebrowsing_enabled"] = false,
            ["safe_search"] = new JsonObject { ["enabled"] = false }, ["use_global_blocked_services"] = !(exempt || roku), ["blocked_services"] = new JsonArray(),
            ["blocked_services_schedule"] = new JsonObject { ["time_zone"] = "Local" }, ["upstreams"] = new JsonArray(), ["ignore_querylog"] = false, ["ignore_statistics"] = false,
        };
    }

    /// <summary>mode: "exempt" (no filtering at all), "roku" (existing ad/tracker lists only, no Safe Guard extras), "filtered" (global Safe Guard).</summary>
    public static async Task SetDevice(JsonArray clients, string display, string ip, string mac, string mode, string prefix = null)
    {
        var c = FindClient(clients, ip, mac);
        var ids = new List<string>(); if (!string.IsNullOrEmpty(ip)) ids.Add(ip); if (!string.IsNullOrEmpty(mac)) ids.Add(mac.ToLowerInvariant());
        if (c != null)
        {
            // keep MACs/ClientIDs; drop stale IPv4s when the client is MAC-identified and we know the current IP (stale IPs caused duplicate rows)
            bool macKnown = !string.IsNullOrEmpty(mac) && c["ids"].AsArray().Any(x => string.Equals((string)x, mac, StringComparison.OrdinalIgnoreCase));
            foreach (var i in c["ids"].AsArray()) { var v = (string)i; if (macKnown && !string.IsNullOrEmpty(ip) && System.Net.IPAddress.TryParse(v, out var a) && a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) continue; ids.Add(v); }
            string name = (string)c["name"];
            await Send("POST", "clients/update", new JsonObject { ["name"] = name, ["data"] = ClientBody(name, ids, mode, c["tags"]?.DeepClone() as JsonArray) });
        }
        else await Send("POST", "clients/add", ClientBody("SG " + (prefix ?? (mode == "roku" ? "Roku - " : "")) + display, ids, mode, null));
    }
}

public class SafeGuardPage : PageBase
{
    public override string Title => "Safe Guard";
    public override string Subtitle => "WALLACE network blocking through AdGuard Home: adult, Instagram, ads, trackers, malware/phishing, scams, crypto-mining, bypass \u00B7 Roku core + YouTube minimal allow list";
    readonly StackPanel devList = new(), topList = new();
    readonly TextBlock status = UI.T("Loading\u2026", 13, null, UI.Sub, true), counter = UI.T("\u2013", 34, FontWeights.Bold), coverage = UI.T("", 12.5, null, UI.Text, true);
    CheckBox snap, dating; CheckBox master, adult, adultX, insta, social, safe, bypass; bool busy; SafeGuard.State st;
    readonly StackPanel catList = new(); readonly TextBlock catStatus = UI.T("", 12, null, UI.Sub, true);
    readonly TextBox testHost = new() { Width = 260, Text = "doubleclick.net", Margin = new Thickness(0, 0, 8, 0), VerticalContentAlignment = VerticalAlignment.Center };
    static readonly string Prefs = Path.Combine(Core.DataDir, "safeguard.json");

    protected override UIElement Build()
    {
        CheckBox Tog(string t) => new() { Content = t, Margin = new Thickness(0, 4, 0, 4) };
        master = Tog("Safe Guard ON (master switch)"); master.FontWeight = FontWeights.SemiBold;
        adult = Tog("Adult / pornography / nudity sites and adult image hosts (HaGeZi NSFW + OISD NSFW + StevenBlack porn + AdGuard parental control)");
        adultX = Tog("  Extra-strict: Block List Project porn list (~950k domains, more false positives, more RAM)");
        insta = Tog("Instagram: Allowed for every device (owner allow-all rule, locked)"); insta.IsEnabled = false;
        snap = Tog("Snapchat: Blocked on WALLACE (owner exception, locked)"); snap.IsEnabled = false; snap.IsChecked = true;
        dating = Tog("Dating apps: Blocked on WALLACE (owner phone exempt)"); dating.IsEnabled = false; dating.IsChecked = true;
        social = Tog("Other social / dating: TikTok, Snapchat, Facebook, X/Twitter, Reddit, Discord, Tinder, OnlyFans");
        safe = Tog("SafeSearch: Google, Bing, DuckDuckGo, Ecosia, Yandex, Pixabay (YouTube left unrestricted so Rokus are untouched)");
        bypass = Tog("Block bypass tricks: DoH/DoT resolvers, VPN/proxy, iCloud Private Relay, Firefox DoH canary");
        master.Click += async (s, e) => await Apply(async () =>
        {
            bool on = master.IsChecked == true;
            if (!on) File.WriteAllText(Prefs, JsonSerializer.Serialize(new[] { st.Adult, st.AdultExtra, st.Instagram, st.Social, st.SafeSearch }));
            bool[] p = { true, false, true, false, true };
            if (on) try { p = JsonSerializer.Deserialize<bool[]>(File.ReadAllText(Prefs)); if (!p.Any(x => x)) p = new[] { true, false, true, false, true }; } catch { }
            await SafeGuard.SetAdult(on && p[0], on && p[1]); await SafeGuard.SetServices(on && p[2], on && p[3]); await SafeGuard.SetSafeSearch(on && p[4]);
        });
        adult.Click += async (s, e) => await Apply(() => SafeGuard.SetAdult(adult.IsChecked == true, adult.IsChecked == true && adultX.IsChecked == true));
        adultX.Click += async (s, e) => await Apply(() => SafeGuard.SetAdult(adult.IsChecked == true || adultX.IsChecked == true, adultX.IsChecked == true));
        insta.Click += async (s, e) => await Apply(() => SafeGuard.SetServices(insta.IsChecked == true, social.IsChecked == true));
        social.Click += async (s, e) => await Apply(() => SafeGuard.SetServices(insta.IsChecked == true, social.IsChecked == true));
        safe.Click += async (s, e) => await Apply(() => SafeGuard.SetSafeSearch(safe.IsChecked == true));
        bypass.Click += async (s, e) => await Apply(() => SafeGuard.SetBypass(bypass.IsChecked == true));

        var cats = UI.Card(UI.Col(UI.H("Protection"), Messaging.Badge(), status, new Border { Height = 8 }, master, new Border { Height = 1, Background = UI.Stroke, Margin = new Thickness(0, 6, 0, 6) }, adult, adultX, insta, snap, dating, social, safe, bypass,
            UI.Row(UI.Btn("Refresh", () => _ = Reload(), false, "\uE72C"), new Border { Width = 8 }, UI.Btn("Re-apply Roku setting", () => _ = Apply(() => SafeGuard.SetRokuExempt(AppSettings.Current.ExemptRokus)), false, "\uE72E"), new Border { Width = 8 }, UI.Btn("Open AdGuard", () => Core.Launch("http://127.0.0.1:3000", "", false, true), false, "\uE774"))));
        var stats = UI.Card(UI.Col(UI.H("Blocked attempts (last 24 h)"), counter, UI.T("Safe Guard blocks only (adult lists, parental, Instagram/social, SafeSearch rewrites) from the AdGuard query log", 11.5, null, UI.Sub, true), new Border { Height = 8 }, topList));
        var devs = UI.Card(UI.Col(UI.H("Devices"), UI.T("Tick Exempt for a phone that should have NO restrictions (e.g. your own). Rokus follow the 'Exempt Rokus from Safe Guard' toggle on the Admin page.", 12, null, UI.Sub, true), new Border { Height = 8 }, devList));
        var cov = UI.Card(UI.Col(UI.H("What is actually protected"), coverage));
        var blk = UI.Card(UI.Col(UI.H("Enhanced blocking (Safe Guard+)"),
            UI.T("Extra GitHub blocklists by category. Each switch adds/enables the lists in AdGuard Home; numbers are rules loaded and blocks in the last 24 h.", 12, null, UI.Sub, true),
            new Border { Height = 8 }, catList, catStatus,
            UI.Row(UI.Btn("Update all lists now", () => _ = Apply(Blocking.UpdateLists), false, "\uE895"), new Border { Width = 8 }, UI.Btn("Re-apply Roku/YouTube allow rules", () => _ = Apply(Blocking.EnsureAllow), false, "\uE73E")),
            new Border { Height = 8 },
            UI.Row(testHost, UI.Btn("Test an address", () => _ = TestHost(), false, "\uE721")),
            new Border { Height = 10 }, UI.H("Plain-English help"), UI.T(Blocking.Help, 12, null, UI.Text, true)));
        var g = new Grid(); g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) }); g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
        Grid.SetColumn(stats, 1); g.Children.Add(cats); g.Children.Add(stats);
        return UI.Scroll(UI.Col(g, blk, cov, devs));
    }

    public override void OnShow() => _ = Reload();

    async Task TestHost()
    {
        var h = (testHost.Text ?? "").Trim(); if (h == "") return;
        try { var r = await Blocking.Check(h); bool blocked = r.StartsWith("Filtered"); catStatus.Text = $"{h}: {(blocked ? "BLOCKED" : "allowed")} ({r})"; catStatus.Foreground = blocked ? UI.Green : UI.Sub; }
        catch (Exception ex) { catStatus.Text = "Test failed: " + Core.Redact(ex.Message); }
    }

    async Task ReloadCats()
    {
        List<Blocking.CatState> cats;
        try { cats = await Blocking.Load(); } catch (Exception ex) { catStatus.Text = "Could not read lists: " + Core.Redact(ex.Message); return; }
        catList.Children.Clear();
        foreach (var c in cats)
        {
            var cb = new CheckBox { Content = c.Cat.Title, IsChecked = c.On, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 6, 0, 0) };
            var key = c.Cat.Key; cb.Click += async (s, e) => await Apply(() => Blocking.Set(key, cb.IsChecked == true));
            var meta = c.On ? $"{c.Rules:N0} rules \u00B7 {c.Blocked24h:N0} blocked (24 h){(c.Updated is DateTime u ? " \u00B7 lists updated " + u.ToString("MMM d HH:mm") : "")}" : "off";
            catList.Children.Add(cb);
            catList.Children.Add(UI.T("    " + c.Cat.Help + "  [" + meta + "]", 11.5, null, UI.Sub, true));
        }
    }

    async Task Apply(Func<Task> act)
    {
        if (busy) return; busy = true; status.Text = "Applying\u2026";
        try { await act(); UI.Toast("Safe Guard updated", "AdGuard Home settings saved (persist across restarts)."); }
        catch (Exception ex) { Core.Log("safeguard apply: " + ex.Message); UI.Toast("Safe Guard change failed", Core.Redact(ex.Message)); }
        finally { busy = false; await Reload(); }
    }

    static bool IsRoku(Device d, HashSet<string> macs) => SafeGuard.IsRokuDevice(d, macs);

    async Task Reload()
    {
        st = await SafeGuard.Load();
        if (!st.Reachable) { status.Text = "AdGuard Home API not reachable: " + st.Error; status.Foreground = UI.Red; return; }
        status.Foreground = UI.Sub; status.Text = st.Master ? "Safe Guard is active on AdGuard Home." : "Safe Guard is OFF.";
        master.IsChecked = st.Master; adult.IsChecked = st.Adult; adultX.IsChecked = st.AdultExtra; insta.IsChecked = false /* 3.4.1 Instagram always Allowed */; snap.IsChecked = true; dating.IsChecked = true; social.IsChecked = st.Social; safe.IsChecked = st.SafeSearch; bypass.IsChecked = st.Bypass;
        _ = ReloadCats();
        counter.Text = st.Blocked24h.ToString("N0"); topList.Children.Clear();
        foreach (var (d, n) in st.Top) topList.Children.Add(UI.T($"{n,5}  {d}", 12, null, UI.Sub));
        if (st.Top.Count == 0) topList.Children.Add(UI.T("Nothing blocked yet.", 12, null, UI.Sub));

        var macs = SafeGuard.RokuMacs(); devList.Children.Clear();
        var devs = Devices.Merged(st.Clients); // one row per device: scanner + AdGuard clients merged by MAC, then IP
        int hsProt = 0, lan = 0;
        foreach (var d in devs)
        {
            bool roku = IsRoku(d, macs); var client = SafeGuard.FindClient(st.Clients, d.Ip, d.Mac); bool ex = SafeGuard.IsExempt(client);
            bool hs = d.Network == "Hotspot"; if (hs && (!roku || !AppSettings.Current.ExemptRokus) && !ex) hsProt++; if (!hs && !roku) lan++;
            string cov = roku ? (AppSettings.Current.ExemptRokus ? "Roku \u2013 exempt (toggle on Admin page)" : "Roku \u2013 fully filtered") : ex ? "Exempt \u2013 no restrictions*" : hs ? "Protected (hotspot \u2192 AdGuard)" : "NOT covered \u2013 uses Spectrum router DNS";
            var cb = new CheckBox { Content = "Exempt", IsChecked = roku ? AppSettings.Current.ExemptRokus : ex, IsEnabled = !roku, Width = 90, VerticalAlignment = VerticalAlignment.Center };
            var dd = d; cb.Click += async (s, e) => await Apply(() => SafeGuard.SetDevice(st.Clients, dd.Display, dd.Ip, dd.Mac, cb.IsChecked == true ? "exempt" : "filtered"));
            var row = new Grid { Margin = new Thickness(0, 2, 0, 2) };
            foreach (var w in new[] { 90.0, 230, 120, 80, 150 }) row.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w) }); row.ColumnDefinitions.Add(new ColumnDefinition());
            UIElement[] cells = { cb, UI.T(d.Display ?? "", 13), UI.T(d.Ip, 12, null, UI.Sub), UI.T(hs ? "WALLACE hotspot" : "WALLACE Admin (Spectrum)", 12, null, UI.Sub), UI.T(d.Mac ?? "", 12, null, UI.Sub), UI.T(cov, 12, null, roku || ex ? UI.Yellow : hs ? UI.Green : UI.Red) };
            for (int i = 0; i < cells.Length; i++) { Grid.SetColumn(cells[i], i); if (cells[i] is FrameworkElement fe) fe.VerticalAlignment = VerticalAlignment.Center; row.Children.Add(cells[i]); }
            devList.Children.Add(row);
        }
        coverage.Text =
            $"\u2022 Hotspot (WALLACE, 192.168.137.x): FILTERED. These devices get DNS from this PC, which forwards to AdGuard Home. {hsProt} non-Roku hotspot device(s) currently covered.\n" +
            "\u2022 Important limitation: Windows hotspot (ICS) answers DNS itself and re-asks AdGuard as this PC (127.0.0.1/::1), so AdGuard usually cannot tell hotspot devices apart. Global Safe Guard rules therefore hit every hotspot device. *An Exempt tick only takes effect for queries AdGuard sees with the device's own IP (TCP DNS, or after the hotspot DNS proxy is changed). Rokus keep working either way: a minimal Roku core + YouTube allow list is always kept (Roku ad/telemetry hosts stay blocked), and YouTube Restricted Mode is not forced.\n" +
            $"\u2022 Spectrum Wi-Fi (192.168.1.x): {lan} non-Roku device(s) NOT covered. They use the Spectrum router's DNS and the Spectrum router cannot point clients at a custom DNS server. To cover a phone there: Android \u2192 Settings \u203A Network \u203A Private DNS \u2192 family.adguard-dns.com (or connect it to the WALLACE hotspot); iPhone \u2192 install an AdGuard DNS Family profile or Screen Time \u203A Content & Privacy \u203A Limit Adult Websites and block Instagram there. Replacing Spectrum DHCP with AdGuard would mean disabling the router's DHCP, which we have not done.\n" +
            "\u2022 This PC itself is filtered (it uses AdGuard at 127.0.0.1).";
    }
}
