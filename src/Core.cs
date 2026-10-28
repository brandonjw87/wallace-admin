using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WNH;

public record Check(string Layer, string Name, string Status, string Detail, string Explain);

/// <summary>v1 health engine (probe.ps1 + update checks), unchanged behaviour, plus shared helpers.</summary>
public static class Core
{
    public const string Version = "3.4.2";
    public const string Tools = @"C:\Users\YOU\Tools";
    public static string V2 => Path.Combine(Tools, "wallace-roku-v2");
    public static string BackupRoot => Path.Combine(Tools, "dev-config-backup");
    public static string DataDir { get { var d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WALLACE Admin"); Directory.CreateDirectory(d); return d; } }
    public static string OldDataDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WallaceNetworkHealth");
    /// <summary>One-time copy of v2 (Wallace Network Health) data into the WALLACE Admin folder; the old folder is left untouched. Also clears stale probe temp files.</summary>
    public static void Migrate()
    {
        try
        {
            var nd = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WALLACE Admin");
            var marker = Path.Combine(nd, "migrated-from-v2.txt");
            if (Directory.Exists(OldDataDir) && !File.Exists(marker))
            {
                Directory.CreateDirectory(nd); int n = 0;
                foreach (var f in Directory.GetFiles(OldDataDir))
                {
                    var name = Path.GetFileName(f);
                    if (name.StartsWith("probe-") || name.EndsWith(".tmp")) continue;
                    var dst = Path.Combine(nd, name); if (!File.Exists(dst)) { File.Copy(f, dst); n++; }
                }
                File.WriteAllText(marker, $"{DateTime.Now:s} copied {n} files from {OldDataDir} (old folder kept)");
                Log($"migrated {n} settings/data files from {OldDataDir}");
            }
            foreach (var f in Directory.GetFiles(DataDir, "probe-*.ps1")) if (File.GetLastWriteTime(f) < DateTime.Now.AddMinutes(-10)) try { File.Delete(f); } catch { }
        }
        catch (Exception ex) { Log("migrate: " + ex.Message); }
    }
    public static string LogDir { get { var d = Path.Combine(DataDir, "logs"); Directory.CreateDirectory(d); return d; } }
    public static string ReportDir { get { var d = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WALLACE Admin Reports"); Directory.CreateDirectory(d); return d; } }

    static readonly Regex Secret = new(@"(?i)(pass\w*|secret\w*|private_key|token|psk|api[_-]?key)(\s*[:=]\s*)\S+", RegexOptions.Compiled);
    public static string Redact(string s) => s == null ? "" : Secret.Replace(s, "$1$2<redacted>");
    static readonly string[] Forbidden = { "HOTSPOT-PASSWORD", "ADMIN-LOGIN", ".webui_secret_key", "client-key", "AdGuardHome.yaml", "EverydayOfEvey" };
    public static bool IsForbidden(string path) => Forbidden.Any(f => path.Contains(f, StringComparison.OrdinalIgnoreCase));

    static readonly object logLock = new();
    public static void Log(string msg)
    {
        try { lock (logLock) File.AppendAllText(Path.Combine(LogDir, $"app-{DateTime.Now:yyyyMMdd}.log"), $"{DateTime.Now:HH:mm:ss.fff} {Redact(msg)}\r\n"); } catch { }
    }

    public static readonly HttpClient Http = MakeHttp();
    static HttpClient MakeHttp() { var h = new HttpClient { Timeout = TimeSpan.FromSeconds(20) }; h.DefaultRequestHeaders.UserAgent.ParseAdd("WALLACEAdmin/" + Version); h.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json"); return h; }

    public static (int code, string output) RunPs(string script, int timeoutMs = 120000)
    {
        var file = Path.Combine(DataDir, "probe-" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(file, script, new UTF8Encoding(true));
        try
        {
            var psi = new ProcessStartInfo("powershell.exe", $"-NoProfile -ExecutionPolicy Bypass -File \"{file}\"")
            { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true, StandardOutputEncoding = Encoding.UTF8 };
            using var p = Process.Start(psi);
            var so = p.StandardOutput.ReadToEndAsync(); var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(true); } catch { } return (-1, "timeout"); }
            p.WaitForExit();
            return (p.ExitCode, so.Result + (string.IsNullOrWhiteSpace(se.Result) ? "" : "\nERR:" + se.Result));
        }
        finally { try { File.Delete(file); } catch { } }
    }

    public static Stream Res(string name) => typeof(Core).Assembly.GetManifestResourceStream(name);
    public static string ResText(string name) { using var s = Res(name); if (s == null) return ""; using var r = new StreamReader(s); return r.ReadToEnd(); }

    public static List<Check> RunAllChecks()
    {
        var (code, output) = RunPs(ResText("probe.ps1"), 180000);
        var list = new List<Check>();
        var jl = output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None).LastOrDefault(l => l.TrimStart().StartsWith("[")) ?? "";
        if (jl.Length > 0) output = jl;
        int start = output.IndexOf('['), end = output.LastIndexOf(']');
        if (start < 0 || end < start) { list.Add(new Check("Engine", "Probe", "Red", Redact(output.Length > 400 ? output[..400] : output), "The checking script did not return results.")); return list; }
        try
        {
            using var doc = JsonDocument.Parse(output.Substring(start, end - start + 1));
            foreach (var e in doc.RootElement.EnumerateArray())
                list.Add(new Check(S(e, "Layer"), S(e, "Name"), S(e, "Status"), Redact(S(e, "Detail")), S(e, "Explain")));
        }
        catch (Exception ex) { list.Add(new Check("Engine", "Probe", "Red", "bad JSON: " + ex.Message, "The checking script returned unreadable results.")); }
        return list;
    }
    static string S(JsonElement e, string n) => e.TryGetProperty(n, out var v) && v.ValueKind != JsonValueKind.Null ? v.ToString() : "";

    // 30-min cache: GitHub allows only 60 unauthenticated API calls/hour, so repeated "Check now" clicks no longer burn the quota.
    static readonly System.Collections.Concurrent.ConcurrentDictionary<string, (DateTime at, string tag)> relCache = new();
    public static async Task<string> LatestRelease(string repo)
    {
        if (relCache.TryGetValue(repo, out var c) && DateTime.UtcNow - c.at < TimeSpan.FromMinutes(30)) return c.tag;
        try
        {
            using var resp = await Http.GetAsync($"https://api.github.com/repos/{repo}/releases/latest");
            if ((int)resp.StatusCode == 403 || (int)resp.StatusCode == 429)
            {
                var reset = resp.Headers.TryGetValues("X-RateLimit-Reset", out var rv) && long.TryParse(rv.FirstOrDefault(), out var rs) ? DateTimeOffset.FromUnixTimeSeconds(rs).LocalDateTime.ToString("t") : "later";
                return c.tag ?? $"check failed: GitHub rate limit (retry after {reset})";
            }
            resp.EnsureSuccessStatusCode();
            using var d = JsonDocument.Parse(await resp.Content.ReadAsStringAsync()); var tag = d.RootElement.GetProperty("tag_name").GetString();
            relCache[repo] = (DateTime.UtcNow, tag); return tag;
        }
        catch (Exception ex) { return c.tag ?? "check failed: " + ex.Message; }
    }

    public static string FileVer(string path) { try { if (!File.Exists(path)) return "not found"; var v = FileVersionInfo.GetVersionInfo(path); return string.IsNullOrEmpty(v.ProductVersion) ? File.GetLastWriteTime(path).ToString("yyyy-MM-dd") + " build" : v.ProductVersion; } catch { return "?"; } }

    public static string RunExe(string exe, string args, int timeoutMs = 15000)
    {
        try
        {
            if (!File.Exists(exe)) return "not found";
            var psi = new ProcessStartInfo(exe, args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
            using var p = Process.Start(psi); var so = p.StandardOutput.ReadToEndAsync(); var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs)) { try { p.Kill(true); } catch { } return "timeout"; }
            return (so.Result + se.Result).Trim();
        }
        catch (Exception ex) { return "error: " + ex.Message; }
    }

    public record UpdateRow(string Item, string Installed, string Latest, string Verdict);
    public static async Task<List<UpdateRow>> CheckUpdates(bool includeWindowsUpdate)
    {
        var r = new List<UpdateRow>();
        string agh = await Task.Run(() => RunExe(Path.Combine(Tools, @"AdGuardHome\AdGuardHome.exe"), "--version"));
        var m = Regex.Match(agh, @"v\d+\.\d+\.\d+"); string aghV = m.Success ? m.Value : Redact(agh);
        if (!m.Success) { var av = await SafeGuard.Version(); if (av != null) { aghV = av; m = Regex.Match(av, @"v\d+\.\d+\.\d+"); } } // real version via the AdGuard API
        // AdGuardHome folder is admin-only (secrets inside), so a per-user app can't run the exe: say so instead of "not found".
        if (!m.Success && (agh == "not found" || agh.Contains("denied", StringComparison.OrdinalIgnoreCase)))
        { bool locked = false; try { Directory.GetFiles(Path.Combine(Tools, "AdGuardHome")); } catch (UnauthorizedAccessException) { locked = true; } catch { }
          if (locked) aghV = "installed (folder admin-only; see version in AdGuard dashboard footer)"; }
        var t1 = LatestRelease("AdguardTeam/AdGuardHome"); var t2 = LatestRelease("dmunozv04/iSponsorBlockTV"); var t3 = LatestRelease("louislam/uptime-kuma"); var t4 = LatestRelease("GyulyVGC/sniffnet");
        await Task.WhenAll(t1, t2, t3, t4);
        r.Add(new("AdGuard Home", aghV, t1.Result, Verdict(aghV, t1.Result)));
        string sbV = FileVer(Path.Combine(Tools, @"isponsorblocktv\iSponsorBlockTV.exe"));
        r.Add(new("iSponsorBlockTV", sbV, t2.Result, Verdict(sbV, t2.Result)));
        string kV = "?"; try { using var d = JsonDocument.Parse(File.ReadAllText(Path.Combine(Tools, @"uptime-kuma\package.json"))); kV = d.RootElement.GetProperty("version").GetString(); } catch { }
        r.Add(new("Uptime Kuma", kV, t3.Result, Verdict(kV, t3.Result)));
        string snV = FileVer(@"C:\Program Files\Sniffnet\sniffnet.exe");
        r.Add(new("Sniffnet", snV, t4.Result, Verdict(snV, t4.Result)));
        r.Add(new("Npcap (capture driver)", NpcapInfo.Version ?? "NOT INSTALLED", "npcap.com", NpcapInfo.Installed ? "installed" : "install from your Desktop (npcap-1.90.exe)"));
        try
        {
            var j = await Http.GetStringAsync("https://api.github.com/repos/hagezi/dns-blocklists/commits?per_page=1");
            using var d = JsonDocument.Parse(j); var date = d.RootElement[0].GetProperty("commit").GetProperty("committer").GetProperty("date").GetDateTime();
            var fdir = Path.Combine(Tools, @"AdGuardHome\data\filters"); string local = "?";
            if (Directory.Exists(fdir)) { var newest = new DirectoryInfo(fdir).GetFiles().OrderByDescending(f => f.LastWriteTime).FirstOrDefault(); if (newest != null) local = newest.LastWriteTime.ToString("yyyy-MM-dd HH:mm"); }
            r.Add(new("HaGeZi blocklists", "AdGuard filters refreshed " + local, "upstream updated " + date.ToLocalTime().ToString("yyyy-MM-dd HH:mm"), "AdGuard refreshes lists itself (every 24h by default)"));
        }
        catch (Exception ex) { r.Add(new("HaGeZi blocklists", "?", "check failed: " + ex.Message, "")); }
        if (includeWindowsUpdate)
        {
            var (c, o) = await Task.Run(() => RunPs("$s=New-Object -ComObject Microsoft.Update.Session; $x=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0'); $x.Updates.Count; foreach($u in $x.Updates){ '- ' + $u.Title }", 240000));
            var lines = o.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            if (lines.Skip(1).Any(l => Regex.IsMatch(l, @"- (\d{1,2}/\d{1,2}/)?20(0\d|1\d)"))) lines = lines.Select(l => Regex.IsMatch(l, @"/20(0\d|1\d) ") ? l.Trim() + " [old driver, likely older than installed - skip]" : l).ToArray();
            r.Add(new("Windows Update", "pending: " + (lines.Length > 0 ? lines[0].Trim() : "?"), string.Join("; ", lines.Skip(1).Take(6).Select(l => l.Trim())), "Read-only. Install from Settings > Windows Update."));
        }
        return r;
    }
    static string Verdict(string inst, string latest)
    {
        if (latest == null || latest.StartsWith("check failed")) return "couldn't check";
        string a = Regex.Match(inst ?? "", @"\d+(\.\d+)+").Value, b = Regex.Match(latest, @"\d+(\.\d+)+").Value;
        if (a == "" || b == "") return "compare manually";
        try { return new Version(a) >= new Version(b) ? "up to date" : "UPDATE AVAILABLE (not auto-installed)"; } catch { return "compare manually"; }
    }

    public static void Launch(string file, string args = "", bool window = false, bool shell = false)
    {
        try { Process.Start(new ProcessStartInfo(file, args) { UseShellExecute = shell || window, CreateNoWindow = !window, WindowStyle = window ? ProcessWindowStyle.Normal : ProcessWindowStyle.Hidden }); }
        catch (Exception ex) { Log("Launch failed " + file + ": " + ex.Message); UI.Toast("Could not start", ex.Message); }
    }

    public static string Esc(string s) => System.Net.WebUtility.HtmlEncode(s ?? "");
    public static string Csv(string s) { s ??= ""; return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s; }
    public static string Bytes(double b) => b < 1024 ? $"{b:0} B" : b < 1048576 ? $"{b / 1024:0.0} KB" : b < 1073741824 ? $"{b / 1048576:0.0} MB" : $"{b / 1073741824:0.00} GB";
    public static string Rate(double bytesPerSec) { var bits = bytesPerSec * 8; return bits < 1e3 ? $"{bits:0} bps" : bits < 1e6 ? $"{bits / 1e3:0.0} Kbps" : $"{bits / 1e6:0.0} Mbps"; }
}

public static class NpcapInfo
{
    public static string Dir => Path.Combine(Environment.SystemDirectory, "Npcap");
    public static bool Installed => File.Exists(Path.Combine(Dir, "wpcap.dll"));
    public static string Version { get { try { var f = Path.Combine(Dir, "wpcap.dll"); return File.Exists(f) ? FileVersionInfo.GetVersionInfo(f).ProductVersion : null; } catch { return null; } } }
    public static bool AdminOnly
    {
        get
        {
            try { using var k = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\npcap\Parameters"); return k != null && Convert.ToInt32(k.GetValue("AdminOnly", 0)) != 0; }
            catch { return false; }
        }
    }
    public static string DesktopInstaller => Directory.GetFiles(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "npcap-*.exe").OrderByDescending(f => f).FirstOrDefault();
}
