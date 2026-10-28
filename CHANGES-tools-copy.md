
## 2026-10-26 20:33 Flash fix
- Culprit: 'Wallace-Roku Watchdog' task (every 3 min) launched powershell.exe directly -> console flash. Added wallace-roku-v2\run-hidden.vbs; Tools\fix-flash-admin.ps1 (UAC) switches task action to wscript. Backup: dev-config-backup\pre-flashfix-*. AI-Watchdog already hidden via VBS.


## 2026-10-26 20:38 WNH v2 fast scan
- Devices.cs: ARP-first; quick refresh (pings known/ARP IPs only) vs full rescan; ping 256-way/600ms, wake 512-way (ping 700ms, tcp 350ms) in parallel with ping and SSDP; profiling 48-way, only new devices (Ports==null) or full-scan re-profile after 6h (cached per MAC in devices.json); incremental Updated events.
- Built-in auto-refresh loop (Settings: AutoRefresh, QuickRefreshSeconds=30, FullScanMinutes=5); Devices page: Rescan now button, interval dropdown, last-scan kind/time/age + scanning indicator.
- Discovery.cs: NetBIOS/mDNS lookups parallel with port profile, 400ms port timeout.
- Full scan 24.1s -> 3.8s (selftest PASS). Backup: dev-config-backup\pre-fastscan-20261026-203345.


## 2026-10-26 21:25 Safe Guard (adult/Instagram blocking)
- Backup: dev-config-backup\pre-safeguard-20261026-211638 (AdGuardHome.yaml via one UAC RunAs copy + API JSON snapshots).
- AdGuard: added lists HaGeZi NSFW, OISD NSFW, StevenBlack porn-only (on), Block List Project porn (added, OFF); parental control ON; SafeSearch ON (Google/Bing/DDG/Ecosia/Yandex/Pixabay, YouTube OFF for Rokus); blocked_services=instagram; user rules: SafeGuard bypass block (mask.icloud.com, mask-h2.icloud.com, use-application-dns.net); paused '@@|google.com^' and '@@|www.google.com^' as '! SG-paused ...' (they defeated Google SafeSearch).
- Persistent clients: 4x 'SG Roku - *' (custom settings: no parental/safesearch/blocked services), 4x 'SG Phone - *' candidates (global settings, not exempt).
- App: new SafeGuard.cs + 'Safe Guard' nav tab (MainWindow.cs), selftest safeGuard check (App.xaml.cs). Rebuilt, reinstalled per-user, selftest PASS.

## 2026-10-26 21:46 Owner phone exempt
- AdGuard client 'SG Phone - Pixel-10-Pro-XL (hotspot)' renamed to 'SG Phone - Brandon Pixel 10 Pro XL (owner)' (ids 192.0.2.10 + private MAC); custom settings, filtering OFF, parental/SafeSearch/blocked services OFF (same as the Safe Guard Exempt checkbox). Other phones left filtered. Hotspot DNS proxy/icssvc untouched, so the exemption only applies to queries AdGuard sees with the phone's own IP.


## 2026-10-27 00:35 WALLACE hotspot switch-over + Safe Guard+ (WNH 2.1.0)
- Backup: dev-config-backup\pre-wallace-20261027-002106 (wallace-roku-v2, roku-dhcp, watchdog, isponsorblocktv, WNH-v2 source, AdGuardHome.yaml via UAC copy, kuma.db+wal+shm, old task XML, Wi-Fi profiles, CHANGES.md).
- Hotspot: SSID now 'WALLACE' (config.json Ssid), 5 GHz, passphrase unchanged (still read from roku-dhcp\HOTSPOT-PASSWORD.txt, never printed). Same virtual adapter 'Local Area Connection* 2', same 192.0.2.11, uplink Ethernet.
- TP-Link 'Wi-Fi 2' test: disabled the Intel Wi-Fi Direct virtual adapters only (wallace-roku-v2\move-to-tplink-admin.ps1); Windows created no Wi-Fi Direct adapter on the TP-Link (Realtek driver 5001.19.128.4, hosted network = No) and StartTethering returned WiFiDeviceOff. Restored Intel WFD (restore-intel-wfd-admin.ps1) -> WALLACE hosted on Intel AX9462. The only remaining way to use the TP-Link is disabling the Intel adapter itself: NOT done, awaiting Brandon.
- Task: new 'WALLACE Watchdog' (same XML/action run-hidden.vbs), old 'Wallace-Roku Watchdog' disabled (not deleted). config.json Watchdog.TaskName updated.
- MAC-based tracking: config.json DeviceMacs + KumaMacMonitors; new wallace-roku-v2\kuma-mac-sync.ps1 (ARP + 1.5 s async ping sweep, updates only monitor.hostname for Kuma ids 9/10/11, restarts Kuma only when an IP changed); called from watchdog finally{} every run. WNH monitors accept 'mac:AA:BB:..' targets (Devices.ResolveTarget); LG TV monitor/name now by MAC.
- Text: all 'Wallace-Roku' user-facing strings in v2 scripts, legacy hotspot-watchdog and WNH app -> 'WALLACE'. Folder names, firewall group 'Wallace-Roku v2' and legacy roku-dhcp\start-hotspot.ps1 (= rollback script, sets old SSID) left as-is on purpose.
- WNH 2.1.0: Blocking.cs (Safe Guard+ categories: ads [AdGuard DNS filter, HaGeZi Pro, HaGeZi pop-up ads] ON; malware/phishing/scam [HaGeZi TIF medium, URLhaus, Phishing Army, phishing-filter, HaGeZi Fake + AdGuard browsing security] ON; crypto-mining [NoCoin] ON; extra-strict [HaGeZi Pro++, OISD Big, 1Hosts Lite] off; telemetry [HaGeZi Windows/Office, TikTok] off; gambling [HaGeZi] off). Always-first allow block for googlevideo, youtubei.googleapis, s.youtube, youtube, ytimg, ggpht, sponsor.ajay.app, Roku api/image/channels/captive/time, LG store. Per-category toggles, rules + 24h block counts, 'Update all lists now' (filtering/refresh), 'Test an address' (check_host), plain-English limits help. Fixed SafeGuard.Send content-type (AdGuard 415 on charset). Selftest now applies defaults once and checks 12 lookups. Selftest PASS; installed per-user.
- Verified: Resolve-DnsName via 127.0.0.1 and 192.0.2.11: doubleclick/pornhub/instagram -> 0.0.0.0, google -> forcesafesearch, googlevideo/youtube/sponsor.ajay.app resolve. Kuma 8/11 green; LG/Hisense/Stick down until moved to WALLACE (auto re-pointed by MAC).

## 2026-10-27 00:50 - WALLACE Admin 3.0.0 (rename of Wallace Network Health 2.1.0)
- Backup first: Tools\dev-config-backup\pre-admin-20261027-004300 (src, installer, scripts, appdata, adapter-advanced-before.csv; HOTSPOT-PASSWORD.txt excluded).
- Renamed app: exe WALLACEAdmin.exe, window/sidebar/toasts/reports 'WALLACE Admin', installer WALLACE-Admin-Setup-3.0.0.exe (installer-admin.iss, new AppId, side-by-side), Start menu 'WALLACE Admin' (+ mini monitor), Desktop + Startup shortcuts.
- Data path %LOCALAPPDATA%\WALLACE Admin; one-time copy of old %LOCALAPPDATA%\WallaceNetworkHealth (old folder kept). Reports go to Documents\WALLACE Admin Reports.
- Old install %LOCALAPPDATA%\Programs\WallaceNetworkHealth KEPT (not deleted); only its launch shortcuts (Start menu app/mini, Startup) retired. Its uninstall shortcut is kept.
- New 'WALLACE Secure' page + Dashboard card: hosting adapter (via Wi-Fi Direct parent device), band, clients, uplink, live rate, Wi-Fi adapter settings, watchdog task + log tail, new devices 24h, Safe Guard status/blocks; alerts when hotspot goes Off/back On; plain-English TP-Link note.
- Bug fixes: Core.Version said 2.0.0 while build was 2.1.0; stale probe-*.ps1 temp files now cleaned; Devices reverse-DNS could read Result of a faulted task; SafeGuard HttpClient lazy init race (lock).
- AdGuard check_host now supports ?client= (AdGuard v0.107.58+). Self-test adds WALLACE host/band, SafeSearch DNS (google -> 216.239.38.120) and YouTube resolve checks.
- Wi-Fi performance script Tools\wifi-perf-admin.ps1 (Set-NetAdapterAdvancedProperty only, -NoRestart; rollback CSV dev-config-backup\wifi-perf-rollback.csv): Intel Preferred Band -> Prefer 5GHz, Throughput Booster -> Enabled, MIMO PS -> No SMPS, Roaming -> Lowest, Mixed Mode -> CTS-to-self; power mgmt off on Wi-Fi/Wi-Fi 2; wireless power plan Max Performance. Result: see wifi-perf-admin.log.

## 2026-10-27 - Removed old Wallace Network Health versions (approved by Brandon)
- Silently uninstalled Wallace Network Health 2.1.0 (unins000.exe /VERYSILENT); HKCU uninstall entry {6B1E5F2A-7C9D-4E1B-9A55-57A11ACE0002}_is1 removed by uninstaller.
- Deleted leftover %LOCALAPPDATA%\Programs\WallaceNetworkHealth (contained WallaceNetworkHealth.v1-running.old).
- Deleted Start Menu folder 'Wallace Network Health' (incl. 'Uninstall Wallace Network Health.lnk').
- Deleted old data %LOCALAPPDATA%\WallaceNetworkHealth (5 files already migrated to %LOCALAPPDATA%\WALLACE Admin; backup in Tools\dev-config-backup\pre-admin-20261027-004300).
- Deleted Desktop\WallaceNetworkHealth-Setup-2.0.0.exe.
- Kept: WALLACE Admin 3.0.0, WALLACE-Admin-Setup-3.0.0.exe, Tools\WallaceNetworkHealth-v2 source, backups, scripts. WALLACE Admin --selftest re-run after removal.

## 2026-10-27 01:15 Windows Update + Updates tab
- Windows Update (log Tools\winupdate-20261027-011054.log): installed Realtek SoftwareComponent Driver 1.0.1050.0 (success, no reboot). Defender definitions updated to 1.461.217.0. SKIPPED 4 Intel 2018 display/extension drivers (24.20.x, older than installed 31.0.101.2145). No reboot pending. winget upgrades listed only (11), none installed.
- App (Core.cs): GitHub release check cached 30 min + rate-limit message; AdGuard row says folder is admin-only instead of 'not found'; Ollama row when installed; Windows Update row flags pre-2020 drivers as skip. App.xaml.cs: selftest records update-check rows (informational). Backup: dev-config-backup\pre-updates-20261027-011345. Rebuilt, reinstalled per-user, selftest PASS.

## 2026-10-27 01:35-01:55 - Removed all local AI; AdGuard 401 fix; app updates (approved by Brandon)
- Backup first: Tools\dev-config-backup\pre-noai-20261027-013537 (startup items, AI-Watchdog task XML + scripts, local-ai-pwa source, wallace-roku-v2 scripts/config, WALLACE Admin src, kuma.db, start-open-webui.cmd; no model files, no secrets).
- Ollama: already uninstalled earlier (no exe, no .ollama, no OLLAMA_* env vars). Removed leftover Defender exclusions (C:\Users\YOU\.ollama, .ollama\models, process ollama.exe) and Tools\ollama-tune-log.txt.
- Open WebUI: stopped (uvx/open-webui/python on 8080); deleted Startup\OpenWebUI.vbs, Tools\start-open-webui.cmd(+.bak), Tools\open-webui.log, Tools\open-webui-data (incl. .webui_secret_key, not printed); 'uv cache clean open-webui' (12,025 files, 473.7 MiB). Firewall 'WR2 Open WebUI 8080' removed.
- AI-Watchdog: scheduled task removed, Tools\watchdog folder deleted.
- Phone app (8088, AndroidProjects\local-ai-pwa): was only a static page + /api proxy to Ollama 11434 -> removed (process stopped, Startup\LocalAI-PWA.vbs, folder, firewall 'WR2 Local AI PWA 8088').
- Uptime Kuma: deleted monitors 'Open WebUI' (id 4) and 'Phone App' (id 5) via bundled @louislam/sqlite3 (user table untouched); Kuma restarted, HTTP 200. 9 monitors remain.
- wallace-roku-v2: config.json Ports.OpenWebUI/Pwa + AiWatchdogTask removed; lib.ps1 app checks now AdGuardWeb only (no AI-Watchdog check); apply-admin.ps1 no longer recreates 8080/8088 rules.
- WALLACE Admin 3.0.1: removed Open WebUI/Phone PWA monitors, AI-Watchdog log/probe checks, Ollama update row. FIX: Safe Guard 401 - the running app kept a cached AdGuard HttpClient after AdGuard restarted/updated (~00:58); now on 401 it reloads ADMIN-LOGIN.txt and retries once. Updates tab shows real AdGuard version from /control/status (v0.107.79). Rebuilt, installed per-user, selftest PASS.
- Windows Update: hid 4 Intel 2018 drivers (24.20.100.6287/6292).
- winget: Git, ODBC 17, Teams (personal), VS Code, Outlook, Visual Studio 2026, Windows Terminal OK. Edge: winget refuses (different install technology; Edge self-updates). Node.js LTS: winget 'no applicable upgrade' (portable 24.20.0 kept; Kuma launcher unchanged). Android Studio: 'cannot be upgraded using WinGet' (use Help > Check for Updates). AdGuard Home already v0.107.79.
- Verified DNS (127.0.0.1 and 192.0.2.11): doubleclick/pornhub/instagram -> 0.0.0.0; youtube, sponsor.ajay.app, api.roku.com resolve; google -> 216.239.38.120. WALLACE hotspot On, 5 GHz. Log: Tools\noai-admin-log.txt.


## 2026-10-27 03:40 WALLACE Admin 3.1.0 (admin controls, Roku filtering, reports, Flint features)
- Backup first: dev-config-backup\pre-admin-ctrl-20261027-030945 (src, iss, app data incl. devices.json, roku-dhcp, CHANGES.md, AdGuardHome.yaml via one UAC copy with admin-only ACL).
- Rokus: new owner toggle 'Exempt Rokus from Safe Guard' (Admin page; also `WALLACEAdmin.exe --roku-exempt=on|off`). Tested ON->OFF->ON->OFF; per Brandon (t190u) left OFF: all 4 'SG Roku -' clients now use global settings + global blocked services = every block (ads, porn, Instagram, malware, trackers, SafeSearch, parental, all categories).
- Roku allow list cut to the minimum: api/image/channels/captive/ntp/time/cloudservices/sr/wwwimg/my/firmware.roku.com + YouTube/googlevideo/ytimg/ggpht/youtubei/s.youtube/youtube-nocookie + SponsorBlock (sponsor.ajay.app, sponsorblock.hankmccord.dev) + LG TV (lgtvsdp/lgappstv). BUG FIXED: '@@||cooper.logs.roku.com^' was in the allow block and overrode the logs block; removed (cooper/ads/logs/events.roku.com, ravm.tv now blocked for Rokus). Exact-duplicate user rules removed (same meaning).
- Admin page (new): per-device Exempt / Pause-Resume / Rename / Type (Roku/Phone/TV/PC), custom block/allow rules ('! WALLACE custom' section), Update lists, Restart AdGuard (UAC), Restart hotspot, Run watchdog, View/Clear app logs, Back up / Restore AdGuard settings (API JSON in dev-config-backup\wallace-admin-config). Destructive actions ask to confirm. Rokus, router, this PC and the owner phone cannot be paused.
- Device pause: elevated helper wnh-admin.ps1 adds a persistent Windows Filtering Platform BLOCK filter on FWPM_LAYER_IPFORWARD_V4 (source + destination = device IP) - the layer hotspot/ICS traffic actually traverses (normal firewall rules don't apply to it) - plus AdGuard access/disallowed_clients. Tested on fake IP 192.0.2.12: add -> exists -> remove -> gone. Spectrum devices can't be paused from the PC (traffic doesn't pass it).
- Duplicates fixed at the source: scanner no longer creates devices from dead/static ICS ARP leftovers (randomized-MAC phones left one per reconnect); Devices.Dedupe merges same-IP offline ghosts / randomized-MAC same-hostname entries, optional prune > PruneDays (default off, 30 d), devices.json.bak-<date> first. Safe Guard/Admin lists merge AdGuard clients by MAC before IP (Roku with stale lease IP showed twice); SetDevice drops stale IPs for MAC-identified clients. 'Refresh devices' button on Devices + Admin pages.
- Reports: Blocked-content PDF (QuestPDF Community): by category (porn, gambling, Instagram, social, ads, trackers, malware, crypto, SafeSearch, bypass, custom), device, app (domain->app map), list; KPIs, hourly/daily chart, top devices/apps/sites, per-device pages with timestamps. Options: 24 h / 7 d / 14 d / custom, category + device filter, Open folder, auto daily/weekly. Honest ICS attribution note ('WALLACE hotspot / this PC (device unknown)' or 'probably X' when only one hotspot device online). Query log: retention already 90 days, client IPs not anonymized (app enforces >=14 d, anonymize off).
- Router (Flint features) page: 25-feature map (Implemented/Partial/Not possible + why), speed test (Cloudflare), ping/traceroute/DNS lookup, uplink/failover/Wi-Fi/IPv6 status, show/switch AdGuard upstreams to DoH (not switched), bedtime/schedule rules -> \WALLACE\ scheduled tasks (pause by MAC or stop/start hotspot), optional weekly reboot (off).
- Title bar: Mac traffic lights moved to top-right in Windows order (minimize, maximize, close), same colors/hover glyphs; mini monitor close is a red dot on the right. Caption drag, double-click maximize, snap unchanged (WindowChrome).
- Bugs fixed: cooper.logs allow override; IP-only client matching duplicates; ghost ARP devices; UDP receive tasks unobserved after timeout (log spam with full stacks) now observed; unobserved-task log trimmed to one line.
- Self-test (PASS) new checks: Roku setting matches AdGuard clients, owner phone exempt, Roku-client lookups (pornhub/doubleclick/ads.roku/logs.roku/cooper.logs blocked; api.roku/googlevideo/youtube/sponsorblock allowed), custom-rule add/check/remove round-trip, querylog config, helper embedded, no duplicate devices, sample blocked-content PDF.


## 2026-10-27 05:00 EDT - WALLACE Admin 3.2.0: messaging never blocked + real per-device DNS
- Backup: C:\Users\YOU\Tools\dev-config-backup\pre-msgfix-20261027-044809 (AdGuard user_rules/clients/dns_info/access/blocked_services JSON, AdGuardHome.yaml copy with admin-only ACL, SharedAccess.reg, IKEEXT.reg, firewall.wfw).
- Diagnosis (48 h querylog, 24k filtered entries): NO messaging host was DNS-blocked (RCS/instantmessaging-pa, mtalk/FCM, Apple push, ePDG all resolved). Only telemetry blocked (firebaselogging, securemetrics.apple.com, fbcdn netseer). Every hotspot query arrived as ::1/127.0.0.1 (ICS DNS proxy) and all hotspot devices shared one AdGuard rate limit (100 qps).
- Likely root cause: the PC's IKEEXT service was listening on UDP 500/4500 - the exact ports phones use for Wi-Fi Calling IPsec (IKE/NAT-T) to the carrier ePDG, which carries SMS/MMS/OTP when Wi-Fi Calling is on. IKEEXT stopped and set to Manual (was Automatic). Built-in Windows VPNs would start it on demand.
- AdGuard: protected '! Messaging:protected' block of 64 @@||domain^$important rules + googleapis regex placed FIRST in user rules (overrides every list, category, blocked service). Domains in Tools\msgfix\messaging-domains.txt and src\Messaging.cs.
- AdGuard ratelimit 100->300, whitelist kept (+192.0.2.13).
- Per-device fix: AdGuard bind_hosts 0.0.0.0 -> 127.0.0.1, ::1, 192.0.2.13, 192.0.2.11 (specific bind beats the ICS DNS proxy wildcard socket). Hotspot devices now appear with their own IPs (verified 192.0.2.14 Roku stick). Also stops AdGuard answering on public IPv6 addresses.
- New SYSTEM task \WALLACE\DNS bind guard (startup + every 2 min, C:\ProgramData\WALLACE Admin\dns-bind-guard.ps1): keeps binds matching present addresses with auto-fallback to wildcard if AdGuard is unhealthy; re-inserts the messaging block if missing; syncs each MAC-identified AdGuard client's current 192.168.137.x IP from ARP (exempt phone / filtered Rokus follow the device).
- App 3.2.0: Messaging.cs (Enforce() applied to every filtering/set_rules write; drops any rule that would block a messaging host), phones can never be paused (Admin.Pause) or put on a bedtime schedule (Router.InstallSched), locked 'Messaging protected' badge on Safe Guard + Admin pages, Spectrum network labelled 'WALLACE Admin (Spectrum)'; selftest adds messaging (global + Roku profile), hotspot DNS listener = AdGuardHome, per-client IPs. Rebuilt, installed per-user, selftest PASS (0 fails).
- Hotspot SSID verified 'WALLACE' (unchanged). Spectrum router SSID is 'WALLACE Admin'.
