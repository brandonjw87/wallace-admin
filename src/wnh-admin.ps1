# WALLACE Admin elevated helper (runs only when Brandon clicks the UAC prompt).
# Actions: pause|unpause <ip>, pause-mac|unpause-mac <mac>, restart-adguard, backup-yaml <dir>, selftest-wfp, install-schedules <json>, reboot-schedule '<Day> <HH:mm>'|off, hotspot-off
# Device pause = Windows Filtering Platform block filter on the IP FORWARD layer (the layer ICS/hotspot traffic actually
# passes through; normal Windows Firewall rules do NOT apply to forwarded hotspot traffic). Filters are persistent and keyed
# by a deterministic GUID per IP so they can always be removed. Never prints secrets.
param([string]$Action = 'list', [string]$Arg = '', [string]$Log = "$env:LOCALAPPDATA\WALLACE Admin\logs\admin-helper.log")
$ErrorActionPreference = 'Stop'
function L($m) { $l = "$(Get-Date -f s) [$Action] $m"; Add-Content -Path $Log -Value $l; $l }
$src = @'
using System; using System.Runtime.InteropServices; using System.Security.Cryptography; using System.Text; using System.Collections.Generic;
public static class WallaceWfp {
  [StructLayout(LayoutKind.Explicit, Size=200)] struct FILTER {
    [FieldOffset(0)] public Guid filterKey; [FieldOffset(16)] public IntPtr name; [FieldOffset(24)] public IntPtr desc; [FieldOffset(32)] public uint flags;
    [FieldOffset(40)] public IntPtr providerKey; [FieldOffset(48)] public uint pdSize; [FieldOffset(56)] public IntPtr pdData;
    [FieldOffset(64)] public Guid layerKey; [FieldOffset(80)] public Guid subLayerKey; [FieldOffset(96)] public uint weightType; [FieldOffset(104)] public ulong weightVal;
    [FieldOffset(112)] public uint numConds; [FieldOffset(120)] public IntPtr conds; [FieldOffset(128)] public uint actionType; [FieldOffset(132)] public Guid actionGuid;
    [FieldOffset(152)] public ulong rawContext; [FieldOffset(168)] public IntPtr reserved; [FieldOffset(176)] public ulong filterId; }
  [StructLayout(LayoutKind.Explicit, Size=40)] struct COND { [FieldOffset(0)] public Guid fieldKey; [FieldOffset(16)] public uint matchType; [FieldOffset(24)] public uint valType; [FieldOffset(32)] public ulong val; }
  [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineOpen0(string server, uint authn, IntPtr auth, IntPtr session, out IntPtr h);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmEngineClose0(IntPtr h);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterAdd0(IntPtr h, ref FILTER f, IntPtr sd, out ulong id);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterDeleteByKey0(IntPtr h, ref Guid key);
  [DllImport("fwpuclnt.dll")] static extern uint FwpmFilterGetByKey0(IntPtr h, ref Guid key, out IntPtr f);
  [DllImport("fwpuclnt.dll")] static extern void FwpmFreeMemory0(ref IntPtr p);
  static readonly Guid FWD4 = new Guid("a82acc24-4ee1-4ee1-b465-fd1d25cb10a4");
  static readonly Guid SRC = new Guid("ae96897e-2e94-4bc9-b313-b27ee80e574d"), DST = new Guid("2d79133b-b390-45c6-8699-acaceaafed33");
  public static Guid Key(string ip, string dir) { using (var m = MD5.Create()) return new Guid(m.ComputeHash(Encoding.UTF8.GetBytes("wallace-pause|" + dir + "|" + ip))); }
  static uint Ip(string ip) { var b = System.Net.IPAddress.Parse(ip).GetAddressBytes(); return ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3]; }
  static IntPtr Open() { IntPtr h; uint r = FwpmEngineOpen0(null, 10, IntPtr.Zero, IntPtr.Zero, out h); if (r != 0) throw new Exception("FwpmEngineOpen0 0x" + r.ToString("X")); return h; }
  public static string Pause(string ip) {
    var h = Open(); var sb = new StringBuilder();
    try { foreach (var dir in new[] { "src", "dst" }) {
      var key = Key(ip, dir); IntPtr ex; if (FwpmFilterGetByKey0(h, ref key, out ex) == 0) { FwpmFreeMemory0(ref ex); sb.Append(dir + ":exists "); continue; }
      var c = new COND { fieldKey = dir == "src" ? SRC : DST, matchType = 0, valType = 3, val = Ip(ip) };
      IntPtr pc = Marshal.AllocHGlobal(40); Marshal.StructureToPtr(c, pc, false);
      IntPtr nm = Marshal.StringToHGlobalUni("WALLACE Admin pause " + ip + " (" + dir + ")"), ds = Marshal.StringToHGlobalUni("Blocks forwarded hotspot traffic for a paused device. Remove from WALLACE Admin.");
      try { var f = new FILTER { filterKey = key, name = nm, desc = ds, flags = 1, layerKey = FWD4, weightType = 0, numConds = 1, conds = pc, actionType = 0x1001 };
        ulong id; uint r = FwpmFilterAdd0(h, ref f, IntPtr.Zero, out id); if (r != 0) throw new Exception("FwpmFilterAdd0 0x" + r.ToString("X")); sb.Append(dir + ":added id=" + id + " "); }
      finally { Marshal.FreeHGlobal(pc); Marshal.FreeHGlobal(nm); Marshal.FreeHGlobal(ds); } } }
    finally { FwpmEngineClose0(h); }
    return sb.ToString(); }
  public static string Unpause(string ip) { var h = Open(); var sb = new StringBuilder();
    try { foreach (var dir in new[] { "src", "dst" }) { var key = Key(ip, dir); uint r = FwpmFilterDeleteByKey0(h, ref key); sb.Append(dir + (r == 0 ? ":removed " : r == 0x80320003 ? ":absent " : ":err0x" + r.ToString("X") + " ")); } }
    finally { FwpmEngineClose0(h); } return sb.ToString(); }
  public static bool Exists(string ip) { var h = Open(); try { var key = Key(ip, "src"); IntPtr ex; if (FwpmFilterGetByKey0(h, ref key, out ex) == 0) { FwpmFreeMemory0(ref ex); return true; } return false; } finally { FwpmEngineClose0(h); } }
}
'@
try {
  if ($Action -in 'pause','unpause','selftest-wfp') { Add-Type -TypeDefinition $src -Language CSharp }
  $state = "$env:LOCALAPPDATA\WALLACE Admin\paused.json"
  switch ($Action) {
    'pause'   { [void][Net.IPAddress]::Parse($Arg); L ("pause $Arg -> " + [WallaceWfp]::Pause($Arg)) }
    'unpause' { [void][Net.IPAddress]::Parse($Arg); L ("unpause $Arg -> " + [WallaceWfp]::Unpause($Arg)) }
    'selftest-wfp' { $t = '192.0.2.12'; L ("test add " + [WallaceWfp]::Pause($t)); L ("exists=" + [WallaceWfp]::Exists($t)); L ("test remove " + [WallaceWfp]::Unpause($t)); L ("exists-after=" + [WallaceWfp]::Exists($t)) }
    'restart-adguard' { Restart-Service AdGuardHome; Start-Sleep 3; L ("AdGuardHome " + (Get-Service AdGuardHome).Status) }
    'backup-yaml' { $y = 'C:\Users\YOU\Tools\AdGuardHome\AdGuardHome.yaml'; if (-not (Test-Path $Arg)) { throw "no dir" }; Copy-Item $y (Join-Path $Arg 'AdGuardHome.yaml'); icacls (Join-Path $Arg 'AdGuardHome.yaml') /inheritance:r /grant:r "*S-1-5-32-544:F" "SYSTEM:F" | Out-Null; L "yaml copied to backup (admin-only ACL, not printed)" }
    'pause-mac' { $m = $Arg.ToUpper().Replace(':','-'); $ips = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | ?{ $_.LinkLayerAddress -eq $m -and $_.IPAddress -like '192.168.137.*' } | select -Expand IPAddress -Unique)
      $pd = 'C:\ProgramData\WALLACE Admin'; New-Item -ItemType Directory -Force $pd | Out-Null; Set-Content "$pd\paused-$($m).txt" ($ips -join ',')
      if ($ips.Count -eq 0) { L "pause-mac $m : device not on hotspot now" } else { Add-Type -TypeDefinition $src -Language CSharp; foreach ($i in $ips) { L ("pause-mac $m $i -> " + [WallaceWfp]::Pause($i)) } } }
    'unpause-mac' { $m = $Arg.ToUpper().Replace(':','-'); $f = "C:\ProgramData\WALLACE Admin\paused-$($m).txt"; Add-Type -TypeDefinition $src -Language CSharp
      $ips = @(); if (Test-Path $f) { $ips = (Get-Content $f -Raw).Trim().Split(',') | ?{ $_ } }; foreach ($i in $ips) { L ("unpause-mac $m $i -> " + [WallaceWfp]::Unpause($i)) }; Remove-Item $f -ea 0; if (-not $ips) { L "unpause-mac $m : nothing paused" } }
    'hotspot-off' { $p=[Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetInternetConnectionProfile()
      $t=[Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager,Windows.Networking.NetworkOperators,ContentType=WindowsRuntime]::CreateFromConnectionProfile($p); [void]$t.StopTetheringAsync(); Start-Sleep 3; L "hotspot stop requested (schedule)" }
    'install-schedules' {
      $pd = 'C:\ProgramData\WALLACE Admin'; New-Item -ItemType Directory -Force $pd | Out-Null
      Copy-Item $PSCommandPath "$pd\wnh-admin.ps1" -Force; icacls $pd /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "SYSTEM:(OI)(CI)F" "*S-1-5-32-545:(OI)(CI)RX" | Out-Null
      Get-ScheduledTask -TaskPath '\WALLACE\' -ErrorAction SilentlyContinue | ?{ $_.TaskName -like 'Bedtime*' } | Unregister-ScheduledTask -Confirm:$false
      $rules = Get-Content $Arg -Raw | ConvertFrom-Json; $n = 0
      $dn = 'Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'
      foreach ($r in @($rules)) { if (-not $r.Enabled) { continue }; $days = @($r.Days.ToCharArray() | %{ $dn[[int][string]$_] }); $safe = ($r.Name -replace '[^\w -]','').Trim()
        foreach ($edge in @(@{t=$r.From; a= if ($r.Mac -eq '*') {'hotspot-off'} else {'pause-mac'}; s='start'}, @{t=$r.To; a= if ($r.Mac -eq '*') {'hotspot-on'} else {'unpause-mac'}; s='end'})) {
          if ($edge.a -eq 'hotspot-on') { $act = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"C:\Users\YOU\Tools\wallace-roku-v2\start-hotspot.ps1`"" }
          else { $act = New-ScheduledTaskAction -Execute powershell.exe -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$pd\wnh-admin.ps1`" -Action $($edge.a) -Arg $($r.Mac) -Log `"$pd\schedule.log`"" }
          $tr = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $days -At $edge.t
          $pr = if ($edge.a -like 'hotspot*') { New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\Brandon" -LogonType Interactive -RunLevel Highest } else { New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest }
          Register-ScheduledTask -TaskPath '\WALLACE\' -TaskName "Bedtime $safe $($edge.s)" -Action $act -Trigger $tr -Principal $pr -Settings (New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries) -Force | Out-Null; $n++ } }
      L "installed $n bedtime/schedule tasks" }
    'reboot-schedule' { Get-ScheduledTask -TaskPath '\WALLACE\' -TaskName 'Scheduled reboot' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
      if ($Arg -ne 'off') { $d, $t = $Arg.Split(' '); $act = New-ScheduledTaskAction -Execute shutdown.exe -Argument '/r /t 120 /c "WALLACE Admin scheduled reboot"'
        Register-ScheduledTask -TaskPath '\WALLACE\' -TaskName 'Scheduled reboot' -Action $act -Trigger (New-ScheduledTaskTrigger -Weekly -DaysOfWeek $d -At $t) -User SYSTEM -RunLevel Highest -Force | Out-Null; L "reboot scheduled weekly $Arg" } else { L "scheduled reboot removed" } }
    default { throw "unknown action" }
  }
  exit 0
} catch { L ("ERROR " + $_.Exception.Message); exit 1 }
