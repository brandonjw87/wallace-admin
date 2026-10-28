using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace WNH;

public static class Native
{
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int cmd);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern int GetWindowLong(IntPtr h, int i);
    [DllImport("user32.dll")] static extern int SetWindowLong(IntPtr h, int i, int v);
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int val, int size);
    [DllImport("dwmapi.dll")] static extern int DwmExtendFrameIntoClientArea(IntPtr h, ref Margins m);
    [StructLayout(LayoutKind.Sequential)] struct Margins { public int L, R, T, B; }

    public static bool IsWin11 => Environment.OSVersion.Version.Build >= 22000;
    public static bool BackdropSupported => Environment.OSVersion.Version.Build >= 22621;

    /// <summary>Dark title, rounded corners, and Mica/Acrylic backdrop on Windows 11 22H2+. Returns true when translucency is active.</summary>
    public static bool ApplyDwm(Window w, bool translucent, int backdrop = 2)
    {
        try
        {
            var h = new WindowInteropHelper(w).EnsureHandle();
            int on = 1; DwmSetWindowAttribute(h, 20, ref on, 4);          // immersive dark mode
            int round = 2; DwmSetWindowAttribute(h, 33, ref round, 4);    // rounded corners
            if (!translucent || !BackdropSupported) return false;
            var src = HwndSource.FromHwnd(h); if (src?.CompositionTarget != null) src.CompositionTarget.BackgroundColor = System.Windows.Media.Colors.Transparent;
            SetWindowLong(h, -16, GetWindowLong(h, -16) & ~0x80000); // drop WS_SYSMENU so DWM doesn't paint its own caption buttons over our traffic lights
            var m = new Margins { L = -1, R = -1, T = -1, B = -1 }; DwmExtendFrameIntoClientArea(h, ref m);
            int type = backdrop; return DwmSetWindowAttribute(h, 38, ref type, 4) == 0;   // 2 = Mica, 3 = Acrylic
        }
        catch (Exception ex) { Core.Log("dwm: " + ex.Message); return false; }
    }
}
