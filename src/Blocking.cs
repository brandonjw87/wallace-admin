using System.IO;
using System.Text.Json.Nodes;

namespace WNH;

/// <summary>Enhanced blocking categories on top of Safe Guard. Every list is a public GitHub/project DNS blocklist that
/// AdGuard Home downloads itself; lists are named "Safe Guard+ [cat] ..." so they can be found, counted and toggled.
/// Defaults were picked to avoid breaking Roku, YouTube and iSponsorBlockTV (see Allow rules, always kept first).</summary>
public static class Blocking
{
    public record ListDef(string Name, string Url, bool Default);
    public record Category(string Key, string Title, string Help, ListDef[] Lists, bool DefaultOn);

    public static readonly Category[] Categories =
    {
        new("ads", "Ads on websites and apps", "AdGuard DNS filter + HaGeZi Pro (ads, trackers, pop-ups). The best-balanced DNS ad lists on GitHub.",
            new ListDef[] { new("Safe Guard+ [ads] AdGuard DNS filter", "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", true),
                            new("Safe Guard+ [ads] HaGeZi Pro", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.txt", true),
                            new("Safe Guard+ [ads] HaGeZi pop-up ads", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/popupads.txt", true) }, true),
        new("strict", "Extra-strict ads, trackers and cookie/consent trackers", "HaGeZi Pro++ + OISD Big + 1Hosts Lite. Catches more tracking/consent-tracker domains; slightly higher chance a site breaks.",
            new ListDef[] { new("Safe Guard+ [strict] HaGeZi Pro++", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/pro.plus.txt", true),
                            new("Safe Guard+ [strict] OISD Big", "https://big.oisd.nl", true),
                            new("Safe Guard+ [strict] 1Hosts Lite", "https://o0.pages.dev/Lite/adblock.txt", true) }, false),
        new("malware", "Malware, phishing and scam / fake shops", "HaGeZi Threat Intelligence Feeds, URLhaus, Phishing Army, phishing-filter, HaGeZi Fake (scam shops, fake support) + AdGuard browsing security.",
            new ListDef[] { new("Safe Guard+ [malware] HaGeZi TIF medium", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.medium.txt", true),
                            new("Safe Guard+ [malware] URLhaus", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-agh.txt", true),
                            new("Safe Guard+ [malware] Phishing Army", "https://phishing.army/download/phishing_army_blocklist.txt", true),
                            new("Safe Guard+ [malware] phishing-filter", "https://malware-filter.gitlab.io/malware-filter/phishing-filter-agh.txt", true),
                            new("Safe Guard+ [malware] HaGeZi Fake (scams)", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/fake.txt", true) }, true),
        new("crypto", "Crypto-mining in the browser", "NoCoin list (hoshsadiq). HaGeZi TIF also covers mining pools.",
            new ListDef[] { new("Safe Guard+ [crypto] NoCoin", "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt", true) }, true),
        new("telemetry", "Device telemetry (Windows/Office, TikTok)", "HaGeZi native trackers for Windows/Office and TikTok. Does not block Windows Update or Defender. Roku/LG telemetry lists are NOT used (they can break the TVs).",
            new ListDef[] { new("Safe Guard+ [telemetry] HaGeZi Windows/Office", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.winoffice.txt", true),
                            new("Safe Guard+ [telemetry] HaGeZi TikTok", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/native.tiktok.extended.txt", true) }, false),
        new("gambling", "Gambling", "HaGeZi Gambling list.",
            new ListDef[] { new("Safe Guard+ [gambling] HaGeZi Gambling", "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/gambling.txt", true) }, false),
    };

    /// <summary>Always-on allow rules so YouTube on the Rokus, iSponsorBlockTV and Roku itself keep working whatever lists are on.</summary>
    public static readonly string[] AllowRules =
    {
        "@@||googlevideo.com^", "@@||youtubei.googleapis.com^", "@@||s.youtube.com^", "@@||youtube.com^", "@@||www.youtube.com^", "@@||m.youtube.com^",
        "@@||ytimg.com^", "@@||ggpht.com^", "@@||youtube-nocookie.com^", "@@||sponsor.ajay.app^", "@@||sponsorblock.hankmccord.dev^",
        // Roku: only what the TV needs to boot, sign in, show the home screen/channel store, keep time and update firmware.
        // (cooper.logs.roku.com was allow-listed before, which overrode the logs.roku.com block - removed in 3.1.0.)
        "@@||api.roku.com^", "@@||image.roku.com^", "@@||channels.roku.com^", "@@||captive.roku.com^", "@@||ntp.roku.com^", "@@||time.roku.com^",
        "@@||cloudservices.roku.com^", "@@||sr.roku.com^", "@@||wwwimg.roku.com^", "@@||my.roku.com^", "@@||firmware.roku.com^",
        "@@||lgtvsdp.com^", "@@||lgappstv.com^",
    };
    const string AllowBegin = "! SafeGuard+:allow begin (Roku/YouTube/iSponsorBlockTV)", AllowEnd = "! SafeGuard+:allow end";

    public class CatState { public Category Cat; public bool On; public int Rules; public int Blocked24h; public DateTime? Updated; }

    public static async Task<List<CatState>> Load()
    {
        var f = await SafeGuard.Get("filtering/status"); var filters = f["filters"]?.AsArray() ?? new JsonArray();
        var res = new List<CatState>(); var idToCat = new Dictionary<long, CatState>();
        foreach (var c in Categories)
        {
            var cs = new CatState { Cat = c };
            var mine = filters.Where(x => c.Lists.Any(l => l.Url == (string)x["url"])).ToList();
            cs.On = mine.Count > 0 && c.Lists.Where(l => l.Default).All(l => mine.Any(x => (string)x["url"] == l.Url && (bool)x["enabled"]));
            foreach (var x in mine)
            {
                cs.Rules += (int?)x["rules_count"] ?? 0; idToCat[(long)x["id"]] = cs;
                if (DateTime.TryParse((string)x["last_updated"], out var u) && (cs.Updated == null || u < cs.Updated)) cs.Updated = u;
            }
            res.Add(cs);
        }
        try
        {
            var q = await SafeGuard.Get("querylog?response_status=blocked&limit=2000"); var since = DateTime.Now.AddHours(-24);
            foreach (var e in q["data"]?.AsArray() ?? new JsonArray())
            {
                if (!DateTime.TryParse((string)e["time"], out var t) || t < since) continue;
                foreach (var r in e["rules"]?.AsArray() ?? new JsonArray())
                    if (r?["filter_list_id"] != null && idToCat.TryGetValue((long)r["filter_list_id"], out var cs)) { cs.Blocked24h++; break; }
            }
        }
        catch (Exception ex) { Core.Log("blocking stats: " + ex.Message); }
        return res;
    }

    public static async Task Set(string key, bool on)
    {
        var c = Categories.First(x => x.Key == key);
        await EnsureAllow();
        var f = await SafeGuard.Get("filtering/status"); var filters = f["filters"]?.AsArray() ?? new JsonArray();
        foreach (var l in c.Lists)
        {
            bool want = on && l.Default;
            if (!filters.Any(x => (string)x["url"] == l.Url)) { if (!want) continue; await SafeGuard.Send("POST", "filtering/add_url", new JsonObject { ["name"] = l.Name, ["url"] = l.Url, ["whitelist"] = false }); }
            await SafeGuard.Send("POST", "filtering/set_url", new JsonObject { ["url"] = l.Url, ["whitelist"] = false, ["data"] = new JsonObject { ["name"] = l.Name, ["url"] = l.Url, ["enabled"] = want } });
        }
        if (key == "malware" && on) await SafeGuard.Send("POST", "safebrowsing/enable", new JsonObject());
        Core.Log($"blocking: {key} -> {(on ? "on" : "off")}");
    }

    /// <summary>Apply defaults once (first run of v2.1) without touching anything the owner already switched.</summary>
    public static async Task ApplyDefaultsOnce()
    {
        var flag = Path.Combine(Core.DataDir, "blocking-defaults-applied.txt"); if (File.Exists(flag)) return;
        foreach (var c in Categories.Where(c => c.DefaultOn)) await Set(c.Key, true);
        await EnsureAllow(); File.WriteAllText(flag, DateTime.Now.ToString("s"));
    }

    public static async Task EnsureAllow()
    {
        var f = await SafeGuard.Get("filtering/status"); var rules = (f["user_rules"]?.AsArray() ?? new JsonArray()).Select(r => (string)r).Where(r => r != "").ToList();
        int b = rules.IndexOf(AllowBegin), e = rules.IndexOf(AllowEnd); if (b >= 0 && e > b) rules.RemoveRange(b, e - b + 1);
        // drop exact duplicates of managed allow rules elsewhere + any repeated rule lines (same meaning, less clutter); comments kept
        var seen = new HashSet<string>(AllowRules); rules = rules.Where(r => r.StartsWith("!") || seen.Add(r)).ToList();
        rules.RemoveAll(r => r == "@@||cooper.logs.roku.com^");
        var block = new List<string> { AllowBegin }; block.AddRange(AllowRules); block.Add(AllowEnd); rules.InsertRange(0, block);
        await SafeGuard.Send("POST", "filtering/set_rules", new JsonObject { ["rules"] = new JsonArray(rules.Select(r => (JsonNode)r).ToArray()) });
    }

    /// <summary>Ask AdGuard to re-download every enabled blocklist now (normally it does this every 24 h).</summary>
    public static Task UpdateLists() => SafeGuard.Send("POST", "filtering/refresh", new JsonObject { ["whitelist"] = false });

    /// <summary>Look up a host through AdGuard's own checker: returns reason (e.g. FilteredBlackList / NotFilteredAllowList / NotFilteredNotFound).</summary>
    public static async Task<string> Check(string host, string client = null)
    {
        // AdGuard Home v0.107.58+ accepts ?client= so per-client rules (Roku allow, Pixel exempt) can be verified too
        var r = await SafeGuard.Get("filtering/check_host?name=" + Uri.EscapeDataString(host) + (string.IsNullOrEmpty(client) ? "" : "&client=" + Uri.EscapeDataString(client)));
        return (string)r["reason"] ?? "?";
    }

    public const string Help =
        "How this works, in plain English: AdGuard Home on this PC answers every web-address lookup for devices on the WALLACE hotspot. " +
        "If an address is on one of the lists below, the device simply cannot reach it, so ads, trackers, scam and malware sites, porn sites and Instagram never load.\n\n" +
        "What DNS blocking CANNOT do: it works on whole web addresses, not on pictures. It cannot see or remove a bikini or nude photo that sits inside an otherwise-allowed site " +
        "(for example a news site, Google Images or a social network). The strongest DNS-level tools for that are: SafeSearch (forces Google, Bing and DuckDuckGo to hide explicit " +
        "images and results), the adult lists (block porn and adult image-host sites outright), and blocking Instagram and other social apps. For image-level filtering on a phone " +
        "you would need a device app such as Google Family Link or Screen Time.\n\n" +
        "Ads inside YouTube videos are served from the same addresses as the videos themselves, so DNS cannot remove them without breaking YouTube; iSponsorBlockTV handles " +
        "sponsor segments on the Rokus instead. Cookie pop-ups are drawn by the website itself; DNS blocks the consent-tracking companies behind many of them (Extra-strict), but a browser " +
        "extension is needed to hide the banners. A minimal set of Roku core addresses plus YouTube and iSponsorBlockTV are always allowed so the TVs keep working; Roku ad and telemetry addresses stay blocked.";
}