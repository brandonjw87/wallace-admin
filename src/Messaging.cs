using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace WNH;

/// <summary>3.2.0 ABSOLUTE RULE: messaging of any kind (SMS/MMS over Wi-Fi Calling, RCS, iMessage/FaceTime, carrier Wi-Fi Calling,
/// push (FCM/APNs), WhatsApp/Signal/Telegram/Messenger, OTP senders, visual voicemail) is NEVER blocked for any phone on any Wi-Fi.
/// Enforced here at code level: every AdGuard user-rule write goes through Enforce(), phones can never be paused or scheduled off,
/// and the self-test verifies that representative messaging hosts resolve.</summary>
public static class Messaging
{
    public const string Begin = "! Messaging:protected begin (WALLACE: messaging/calls/OTP are NEVER blocked - do not edit)", End = "! Messaging:protected end";
    public static readonly string[] Domains =
    {
        // Google Messages / RCS (Jibe), Google push (FCM), Google account + connectivity checks
        "jibe.google.com", "telephony.goog", "messages.google.com", "messages-pa.googleapis.com", "instantmessaging-pa.googleapis.com", "tachyon.googleapis.com",
        "mtalk.google.com", "fcm.googleapis.com", "fcmtoken.googleapis.com", "fcmregistrations.googleapis.com", "firebaseinstallations.googleapis.com",
        "android.googleapis.com", "android.clients.google.com", "play.googleapis.com", "www.googleapis.com", "oauth2.googleapis.com", "accounts.google.com",
        "clients3.google.com", "connectivitycheck.gstatic.com", "voice.google.com", "fi.google.com",
        // Apple iMessage / FaceTime / push (APNs) / activation
        "push.apple.com", "ess.apple.com", "identity.apple.com", "albert.apple.com", "gs.apple.com", "icloud-content.com", "setup.icloud.com", "gateway.icloud.com",
        "keyvalueservice.icloud.com", "ckdatabasews.icloud.com", "facetime.apple.com",
        // Carrier Wi-Fi Calling (ePDG / IMS / XCAP / visual voicemail)
        "3gppnetwork.org", "t-mobile.com", "tmobile.com", "vzw.com", "verizon.com", "verizonwireless.com", "att.com", "att.net", "sprint.com", "uscc.com", "mintmobile.com", "spectrummobile.com",
        // Chat apps
        "whatsapp.net", "whatsapp.com", "wa.me", "signal.org", "whispersystems.org", "signal.art", "telegram.org", "telegram.me", "t.me", "messenger.com", "edge-mqtt.facebook.com", "mqtt-mini.facebook.com",
        // One-time-code / 2FA senders
        "twilio.com", "authy.com", "duosecurity.com", "sinch.com", "nexmo.com", "vonage.com", "messagebird.com", "plivo.com",
    };
    public const string GoogleApiRegex = @"@@/^(instantmessaging|rcs|tachyon|messages)[a-z0-9-]*\.googleapis\.com$/$important";
    public static readonly string[] SelfTestHosts = { "instantmessaging-pa.googleapis.com", "courier.push.apple.com", "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org", "mtalk.google.com", "g.whatsapp.net" };

    public static List<string> Block() { var l = new List<string> { Begin }; l.AddRange(Domains.Where(d => !SnapchatBlock.IsSnapchatHost(d) && !DatingBlock.IsDatingHost(d)).Select(d => "@@||" + d + "^$important")); l.Add(GoogleApiRegex); l.Add(End); return l; }

    /// <summary>True if host is (a subdomain of) a protected messaging domain.</summary>
    public static bool IsProtectedHost(string host)
    {
        host = (host ?? "").Trim().TrimEnd('.').ToLowerInvariant(); if (host == "") return false;
        if (Regex.IsMatch(host, @"^(instantmessaging|rcs|tachyon|messages)[a-z0-9-]*\.googleapis\.com$")) return true;
        return Domains.Any(d => host == d || host.EndsWith("." + d));
    }

    /// <summary>Applied to EVERY user-rule list before it is sent to AdGuard: removes block rules that target messaging hosts,
    /// then puts the protected allow block (with $important) first so it overrides every list, category and blocked service.</summary>
    public static List<string> Enforce(IEnumerable<string> input)
    {
        var rules = (input ?? Enumerable.Empty<string>()).Where(r => r != null).ToList();
        int b = rules.FindIndex(r => r.StartsWith("! Messaging:protected begin")), e = rules.IndexOf(End);
        if (b >= 0 && e > b) rules.RemoveRange(b, e - b + 1); else if (b >= 0) rules.RemoveAt(b);
        int ib = rules.IndexOf(InstagramAllow.Begin), ie = rules.IndexOf(InstagramAllow.End); // 3.4.1 Instagram allow-all block is re-added on top
        if (ib >= 0 && ie > ib) rules.RemoveRange(ib, ie - ib + 1); else if (ib >= 0) rules.RemoveAt(ib);
        int sb = rules.IndexOf(SnapchatBlock.Begin), se = rules.IndexOf(SnapchatBlock.End); // 3.4.2 Snapchat backstop is re-added right below Messaging:protected
        if (sb >= 0 && se > sb) rules.RemoveRange(sb, se - sb + 1); else if (sb >= 0) rules.RemoveAt(sb);
        int db = rules.IndexOf(DatingBlock.Begin), de = rules.IndexOf(DatingBlock.End); // 3.4.2 Dating backstop re-added after the Snapchat block
        if (db >= 0 && de > db) rules.RemoveRange(db, de - db + 1); else if (db >= 0) rules.RemoveAt(db);
        var outp = new List<string>();
        foreach (var r in rules)
        {
            var t = r.Trim();
            if (t.StartsWith("@@")) // 3.4.2: never re-allow Snapchat
            {
                var am = Regex.Match(t.Substring(2), @"^\|{0,2}([a-z0-9.*-]+)\^?", RegexOptions.IgnoreCase);
                if (am.Success && (SnapchatBlock.IsSnapchatHost(am.Groups[1].Value.Replace("*.", "")) || DatingBlock.IsDatingHost(am.Groups[1].Value.Replace("*.", "")))) { Core.Log("snapchat guard: commented out Snapchat allow rule: " + t); outp.Add("! " + t); continue; }
            }
            if (!t.StartsWith("!") && !t.StartsWith("#") && !t.StartsWith("@@"))
            {
                var m = Regex.Match(t, @"^\|{0,2}([a-z0-9.*-]+)\^?", RegexOptions.IgnoreCase);
                if (m.Success && SnapchatBlock.IsSnapchatHost(m.Groups[1].Value.Replace("*.", ""))) continue; /* 3.4.2: lives in the Snapchat block */
                if (m.Success && IsProtectedHost(m.Groups[1].Value.Replace("*.", ""))) { Core.Log("messaging guard: dropped rule that would block messaging: " + t); continue; }
                if (m.Success && InstagramAllow.IsInstagramHost(m.Groups[1].Value.Replace("*.", ""))) { Core.Log("instagram guard: commented out Instagram block rule: " + t); outp.Add("! " + t); continue; }
            }
            outp.Add(r);
        }
        var res = InstagramAllow.Block(); res.AddRange(Block()); res.AddRange(SnapchatBlock.Block()); res.AddRange(DatingBlock.Block()); res.AddRange(outp); return res;
    }

    static readonly string[] PhoneWords = { "phone", "iphone", "pixel", "galaxy", "android", "moto", "oneplus" };
    /// <summary>Phones can never be paused or put on a bedtime schedule (that would cut texts and one-time codes).</summary>
    public static bool IsPhone(string ip, string mac, string name)
    {
        mac = (mac ?? "").ToLowerInvariant();
        if (!string.IsNullOrEmpty(mac) && AppSettings.Current.DeviceTypes.TryGetValue(mac, out var ty) && ty == "Phone") return true;
        if (!string.IsNullOrEmpty(mac) && AppSettings.Current.DeviceTypes.Any(k => string.Equals(k.Key, mac, StringComparison.OrdinalIgnoreCase) && k.Value == "Phone")) return true;
        var n = (name ?? "").ToLowerInvariant(); if (PhoneWords.Any(n.Contains)) return true;
        try
        {
            foreach (var d in Devices.All.Values)
                if ((!string.IsNullOrEmpty(mac) && string.Equals(d.Mac, mac, StringComparison.OrdinalIgnoreCase)) || (!string.IsNullOrEmpty(ip) && d.Ip == ip))
                { var s = ((d.Type ?? "") + " " + (d.Display ?? "")).ToLowerInvariant(); if (PhoneWords.Any(s.Contains)) return true; }
        } catch { }
        foreach (var c in SafeGuard.LastClients ?? new JsonArray())
        {
            if (!((string)c?["name"] ?? "").StartsWith("SG Phone")) continue;
            if (c["ids"]?.AsArray().Any(i => string.Equals((string)i, ip, StringComparison.OrdinalIgnoreCase) || string.Equals((string)i, mac, StringComparison.OrdinalIgnoreCase)) == true) return true;
        }
        return false;
    }

    /// <summary>Locked green badge shown on Safe Guard and Admin pages (no toggle - cannot be switched off).</summary>
    public static UIElement Badge() => new Border { Background = new SolidColorBrush(Color.FromArgb(38, 48, 209, 88)), BorderBrush = new SolidColorBrush(Color.FromRgb(48, 209, 88)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(8), Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 4, 0, 8),
        Child = UI.Col(UI.T("\uD83D\uDD12  Messaging protected (locked)", 13.5, FontWeights.SemiBold, new SolidColorBrush(Color.FromRgb(48, 209, 88))), UI.T(Explain, 11.5, null, UI.Sub, true)) };
    public const string Explain = "Messaging protected (locked): texts, one-time codes, RCS chats, iMessage/FaceTime, Wi-Fi Calling, WhatsApp/Signal/Telegram/Messenger and voicemail are never blocked for any phone on WALLACE or WALLACE Admin. Safe Guard lists, categories, pause, bedtime schedules and device toggles cannot override this.";
}
