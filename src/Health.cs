using System.IO;
using System.Text.Json;

namespace WNH;

/// <summary>Shared state for the v1 health checks (Dashboard tiles, mini monitor, map, alerts).</summary>
public static class Health
{
    public static List<Check> Checks = new();
    public static DateTime LastRun; public static bool Busy; public static string Error;
    public static event Action Changed;
    static Timer auto;

    public static int Red => Checks.Count(c => c.Status == "Red");
    public static int Yellow => Checks.Count(c => c.Status == "Yellow");
    public static int GreenCount => Checks.Count(c => c.Status == "Green");
    public static string Overall => Checks.Count == 0 ? "Gray" : Red > 0 ? "Red" : Yellow > 0 ? "Yellow" : "Green";
    public static string Summary => Busy && Checks.Count == 0 ? "Checking every layer… (10–40 s)" : Checks.Count == 0 ? "No check yet" :
        Red > 0 ? $"{Red} problem(s), {Yellow} warning(s), {GreenCount} OK" : Yellow > 0 ? $"Mostly healthy — {GreenCount} OK, {Yellow} warning(s)" : $"Everything healthy — {GreenCount} checks OK";

    public static void StartAuto()
    {
        auto?.Dispose(); auto = null;
        var s = AppSettings.Current; if (!s.AutoRecheck) return;
        var period = TimeSpan.FromMinutes(Math.Max(1, s.RecheckMinutes));
        auto = new Timer(_ => _ = Recheck(), null, period, period);
    }

    public static async Task Recheck()
    {
        if (Busy) return; Busy = true; Changed?.Invoke();
        try
        {
            var prev = Checks.ToDictionary(c => c.Layer + "/" + c.Name, c => c.Status);
            var res = await Task.Run(Core.RunAllChecks).WaitAsync(TimeSpan.FromMinutes(4));
            if (AppSettings.Current.AlertHealthRed && prev.Count > 0)
                foreach (var c in res.Where(c => c.Status == "Red" && prev.TryGetValue(c.Layer + "/" + c.Name, out var p) && p != "Red"))
                    Alerts.Raise("health-" + c.Name, "red", $"{c.Name} turned red", $"{c.Layer}: {c.Detail}", 30);
            Checks = res; LastRun = DateTime.Now; Error = null; SaveLast();
        }
        catch (Exception ex) { Error = ex.Message; Core.Log("recheck: " + ex); }
        finally { Busy = false; Changed?.Invoke(); }
    }

    public static void SaveLast() { try { if (Checks.Count > 0) File.WriteAllText(Path.Combine(Core.DataDir, "last-check.json"), JsonSerializer.Serialize(Checks)); } catch { } }
}
