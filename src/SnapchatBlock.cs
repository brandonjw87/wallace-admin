namespace WNH;

/// <summary>3.4.2 OWNER EXCEPTION (Brandon 2026-10-27): Snapchat is BLOCKED for everyone on WALLACE (explicit exception to the never-block-chat rule).
/// Enforced at code level: 'snapchat' always stays in the global blocked services, and Messaging.Enforce() puts this backstop block directly
/// below the Instagram allow-all and Messaging:protected blocks and comments out any allow rule that would re-allow Snapchat.
/// Clients with their own settings (Brandon's Pixel 10 Pro XL, unfiltered) are not changed.</summary>
public static class SnapchatBlock
{
    public const string Begin = "! Snapchat:block (Brandon 2026-10-27)", End = "! Snapchat:block end", ServiceId = "snapchat";
    public static readonly string[] Domains = { "snapchat.com", "snapchat.net", "snap.com", "snapkit.com", "snapads.com", "sc-cdn.net", "sc-static.net", "snap-dev.net", "snapcdn.io", "feelinsonice.com", "feelinsonice-hrd.appspot.com", "bitmoji.com", "sc-prod.net", "sc-gw.com" };
    public static readonly string[] SelfTestHosts = { "snapchat.com", "app.snapchat.com", "sc-cdn.net" };
    public static List<string> Block() { var l = new List<string> { Begin }; l.AddRange(Domains.Select(d => "||" + d + "^")); l.Add(End); return l; }
    public static bool IsSnapchatHost(string host)
    {
        host = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant(); if (host == "") return false;
        return Domains.Any(d => host == d || host.EndsWith("." + d));
    }
}