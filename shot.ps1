param([string]$out, [string]$nav)
Add-Type -AssemblyName System.Windows.Forms,System.Drawing; Add-Type -Name D -Namespace X -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'; [X.D]::SetProcessDPIAware() | Out-Null
Add-Type @"
using System; using System.Runtime.InteropServices;
public class W { [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out R r); [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h); [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int c);
 public struct R { public int L,T,Rt,B; } }
"@
$p = Get-Process WallaceNetworkHealth | ? { $_.MainWindowTitle -eq 'Wallace Network Health' -and $_.Path -like '*Programs*' } | select -First 1
if (-not $p) { "no window" | Out-File "$out.txt"; exit }
[W]::ShowWindow($p.MainWindowHandle, 9) | Out-Null; [W]::SetForegroundWindow($p.MainWindowHandle) | Out-Null; Start-Sleep -Milliseconds 800
$r = New-Object W+R; [W]::GetWindowRect($p.MainWindowHandle, [ref]$r) | Out-Null
$w=$r.Rt-$r.L; $h=$r.B-$r.T; $bmp = New-Object Drawing.Bitmap $w,$h; $g=[Drawing.Graphics]::FromImage($bmp); $g.CopyFromScreen($r.L,$r.T,0,0,$bmp.Size); $bmp.Save($out); "ok $w x $h responding=$($p.Responding)" | Out-File "$out.txt"

