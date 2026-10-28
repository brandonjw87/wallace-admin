namespace WNH;

/// <summary>3.4.2 OWNER RULE (Brandon 2026-10-27): ALL dating apps are BLOCKED for everyone on WALLACE. Brandon's Pixel 10 Pro XL keeps its own
/// unfiltered client settings and is therefore exempt. facebook.com / Messenger / Instagram / messaging are NOT touched (Facebook Dating is not separable by DNS).
/// Enforced by Messaging.Enforce() (backstop below Messaging:protected, after Snapchat) and SetServices (dating service ids always kept).</summary>
public static class DatingBlock
{
    public const string Begin = "! Dating:block (Brandon 2026-10-27)", End = "! Dating:block end";
    public static readonly string[] ServiceIds = { "tinder", "bumble", "hinge", "grindr", "okcupid", "match", "plentyoffish", "badoo", "happn", "zoosk", "eharmony", "coffeemeetsbagel", "feeld", "raya", "hily", "tagged", "skout", "meetme", "lovoo", "taimi", "ashleymadison", "seeking", "adultfriendfinder" };
    public static readonly string[] Domains = { "tinder.com", "gotinder.com", "bumble.com", "bumble.net", "bumbleapp.com", "badoo.com", "badoocdn.com", "hinge.co", "hingeaws.net", "match.com", "okcupid.com", "okccdn.com", "pof.com", "plentyoffish.com",
        "grindr.com", "grindr.mobi", "grindr.io", "coffeemeetsbagel.com", "feeld.co", "weareher.com", "zoosk.com", "eharmony.com", "raya.app", "hily.com", "tagged.com", "skout.com", "meetme.com", "lovoo.com", "lovoo.net", "happn.com", "happn.fr", "happn.app",
        "taimi.com", "ashleymadison.com", "seeking.com", "adultfriendfinder.com", "friendfinder.com", "ffn.com" };
    public static readonly string[] SelfTestHosts = { "tinder.com", "bumble.com" };
    public static List<string> Block() { var l = new List<string> { Begin }; l.AddRange(Domains.Select(d => "||" + d + "^")); l.Add(End); return l; }
    public static bool IsDatingHost(string host)
    {
        host = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant(); if (host == "") return false;
        return Domains.Any(d => host == d || host.EndsWith("." + d));
    }
}