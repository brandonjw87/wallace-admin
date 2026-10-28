using System.IO;
using System.Text.Json;

namespace WNH;

/// <summary>Bedtime / schedule: pause a device (by MAC, or "*" = whole hotspot) between From and To on the chosen days.</summary>
public class ScheduleRule { public string Name { get; set; } public string Mac { get; set; } public string From { get; set; } = "22:00"; public string To { get; set; } = "06:00"; public string Days { get; set; } = "0123456"; public bool Enabled { get; set; } = true; }

public class MonitorDef { public string Name { get; set; } public string Type { get; set; } public string Target { get; set; } }

public class AppSettings
{
    public bool AutoRecheck { get; set; } = true;
    public int RecheckMinutes { get; set; } = 5;
    public bool Translucent { get; set; } = true;
    public bool AlertNewDevice { get; set; } = true;
    public bool AlertDeviceOffline { get; set; } = true;
    public bool AlertHealthRed { get; set; } = true;
    public bool AlertBandwidth { get; set; } = true;
    public double BandwidthMbps { get; set; } = 80;
    public int BandwidthSeconds { get; set; } = 10;
    public bool AlertNewHost { get; set; } = false;
    public bool AlertBlacklist { get; set; } = true;
    public bool AlertMonitorDown { get; set; } = true;
    public int OfflineMinutes { get; set; } = 3;
    public int ScanSeconds { get; set; } = 60;
    public bool AutoRefresh { get; set; } = true;
    public int QuickRefreshSeconds { get; set; } = 30;
    public int FullScanMinutes { get; set; } = 5;
    public int MonitorSeconds { get; set; } = 30;
    public bool CaptureEthernetToo { get; set; } = false;
    public List<string> Blacklist { get; set; } = new() { "# One IP, CIDR (1.2.3.0/24) or host-name fragment per line", "doubleclick.net" };
    public Dictionary<string, string> DeviceNames { get; set; } = new();
    /// <summary>Owner toggle (Admin page). true = 'SG Roku -' clients skip Safe Guard extras; false = Rokus fully filtered.</summary>
    public bool ExemptRokus { get; set; } = true;
    public Dictionary<string, string> DeviceTypes { get; set; } = new();
    public bool PruneStale { get; set; } = false;
    public int PruneDays { get; set; } = 30;
    public string AutoReport { get; set; } = "off";   // off | daily | weekly
    public DateTime LastAutoReport { get; set; }
    public List<ScheduleRule> Schedules { get; set; } = new();
    public List<MonitorDef> Monitors { get; set; } = new()
    {
        new() { Name = "Internet (Cloudflare)", Type = "ping", Target = "1.1.1.1" },
        new() { Name = "Internet (HTTPS)", Type = "http", Target = "https://www.google.com/generate_204" },
        new() { Name = "Spectrum router", Type = "ping", Target = "192.0.2.15" },
        new() { Name = "Hotspot gateway", Type = "ping", Target = "192.0.2.11" },
        new() { Name = "AdGuard DNS", Type = "tcp", Target = "127.0.0.1:53" },
        new() { Name = "AdGuard web", Type = "http", Target = "http://127.0.0.1:3000" },
        new() { Name = "Uptime Kuma", Type = "http", Target = "http://127.0.0.1:3001" },
        new() { Name = "LG TV", Type = "ping", Target = "mac:00:00:5E:00:53:41" },
    };

    static string FilePath => Path.Combine(Core.DataDir, "settings.json");
    public static AppSettings Current { get; private set; } = Load();
    static AppSettings Load()
    {
        try { if (File.Exists(FilePath)) return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new(); }
        catch (Exception ex) { Core.Log("settings load failed: " + ex.Message); try { File.Copy(FilePath, FilePath + ".bad", true); } catch { } }
        return new();
    }
    public static void Save() { try { File.WriteAllText(FilePath, JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true })); } catch (Exception ex) { Core.Log("settings save failed: " + ex.Message); } }
    public static event Action Changed;
    public static void RaiseChanged() { Save(); Changed?.Invoke(); }
}

public static class JsonStore
{
    public static T Load<T>(string name) where T : new()
    {
        try { var p = Path.Combine(Core.DataDir, name); if (File.Exists(p)) return JsonSerializer.Deserialize<T>(File.ReadAllText(p)) ?? new T(); } catch (Exception ex) { Core.Log($"load {name}: {ex.Message}"); }
        return new T();
    }
    public static void Save<T>(string name, T value)
    {
        try { var p = Path.Combine(Core.DataDir, name); var tmp = p + ".tmp"; File.WriteAllText(tmp, JsonSerializer.Serialize(value)); File.Move(tmp, p, true); } catch (Exception ex) { Core.Log($"save {name}: {ex.Message}"); }
    }
}
