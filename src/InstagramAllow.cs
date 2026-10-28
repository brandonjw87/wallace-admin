namespace WNH;

/// <summary>3.4.1 OWNER RULE (Brandon 2026-10-27): Instagram is ALLOWED for every device on every network, no per-device exceptions.
/// Enforced at code level: every user-rule write goes through Messaging.Enforce(), which puts this allow block at the VERY TOP
/// (above the Messaging block) and comments out any Instagram block rule; SetServices never re-adds the 'instagram' blocked service.</summary>
public static class InstagramAllow
{
    public const string Begin = "! Instagram:allow-all (Brandon 2026-10-27)", End = "! Instagram:allow-all end";
    public static readonly string[] Domains = { "instagram.com", "cdninstagram.com", "ig.me", "instagr.am", "igcdn.com", "igsonar.com", "fbcdn.net" };
    public static List<string> Block() { var l = new List<string> { Begin }; l.AddRange(Domains.Select(d => "@@||" + d + "^$important")); l.Add(End); return l; }
    public static bool IsInstagramHost(string host)
    {
        host = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant(); if (host == "") return false;
        return Domains.Any(d => host == d || host.EndsWith("." + d));
    }
}