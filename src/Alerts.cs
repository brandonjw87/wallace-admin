using System.Collections.ObjectModel;
using System.Windows;
using Microsoft.Toolkit.Uwp.Notifications;

namespace WNH;

public record AlertItem(DateTime Time, string Kind, string Title, string Body)
{
    public string TimeText => Time.ToString("MMM d  h:mm:ss tt");
    public string Color => Kind switch { "red" => "#FF453A", "yellow" => "#FFD60A", "green" => "#30D158", _ => "#0A84FF" };
}

/// <summary>Toast + in-app alert feed with per-key cooldown so nothing spams.</summary>
public static class Alerts
{
    public static readonly ObservableCollection<AlertItem> Feed = new();
    static readonly Dictionary<string, DateTime> last = new();
    static readonly object gate = new();
    public static bool ToastsWork { get; private set; } = true;

    public static void Raise(string key, string kind, string title, string body, int cooldownMinutes = 10)
    {
        lock (gate)
        {
            if (last.TryGetValue(key, out var t) && DateTime.Now - t < TimeSpan.FromMinutes(cooldownMinutes)) return;
            last[key] = DateTime.Now;
        }
        Core.Log($"ALERT [{kind}] {title}: {body}");
        var item = new AlertItem(DateTime.Now, kind, title, body);
        Application.Current?.Dispatcher.BeginInvoke(() => { Feed.Insert(0, item); while (Feed.Count > 500) Feed.RemoveAt(Feed.Count - 1); });
        Toast(title, body);
    }

    public static void Toast(string title, string body)
    {
        if (!ToastsWork) return;
        try { new ToastContentBuilder().AddText(title).AddText(body).AddAttributionText("WALLACE Admin").Show(); }
        catch (Exception ex) { ToastsWork = false; Core.Log("toast unavailable: " + ex.Message); }
    }
}
