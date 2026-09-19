# phone_sync.ps1 - push latest GH Actions clash config to the S24U phone and trigger Meta import
# Run manually:  powershell -ExecutionPolicy Bypass -File C:\Users\ThinkPad\clash-free-auto\phone_sync.ps1
# Scheduled:      see "schedule_sync.ps1" for the Windows Task Scheduler entry.

$ErrorActionPreference = "Stop"

$adb   = "C:\Users\ThinkPad\platform-tools\platform-tools\adb.exe"
$raw   = "https://raw.githubusercontent.com/bruce0madao/clash-free-auto/master/output/clash.yaml"
$tmp   = Join-Path $env:TEMP "cfa-phone-clash.yaml"
$metaPkg = "com.github.metacubex.clash.meta"
$metaFile = "/sdcard/Android/data/$metaPkg/files/clash-free-auto.yaml"
$dlFile   = "/sdcard/Download/clash-free-auto.yaml"

function Log($m) { Write-Host ("[" + (Get-Date -f HH:mm:ss) + "] " + $m) }

Log "phone_sync start"

# 0) ADB server
& $adb start-server | Out-Null

# 1) Is the phone connected?
$dev = & $adb devices | Select-String "device" | Select-String -NotMatch "List of devices|^$"
if (-not $dev) {
    Log "NO phone connected (USB debugging off / cable unplugged) - exit 2"
    exit 2
}
Log ("device: " + ($dev -join "; ").Trim())

# 2) Download latest config from GitHub (fixed generator: gstatic url-test)
try {
    Invoke-WebRequest -Uri $raw -OutFile $tmp -TimeoutSec 30 | Out-Null
} catch {
    Log ("download failed: " + $_.Exception.Message + " - exit 3")
    exit 3
}
$bytes = (Get-Item $tmp).Length
if ($bytes -lt 1000) { Log "downloaded file too small ($bytes bytes) - exit 3"; exit 3 }
Log ("downloaded $bytes bytes")

# 3) Push to Meta's app-external storage + shared Download
& $adb push $tmp $metaFile | Out-Null
& $adb push $tmp $dlFile  | Out-Null
Log "pushed to phone"

# 4) Make Meta's external dir readable (shell-owned copy keeps perms sane)
& $adb shell "chmod 644 $metaFile 2>/dev/null; chmod 644 $dlFile 2>/dev/null" | Out-Null

# 5) Ensure Meta is running, then trigger local-file import deep link
& $adb shell "pidof $metaPkg" | Out-Null
& $adb shell "am start -n $metaPkg/com.github.kr328.clash.MainActivity" | Out-Null
Start-Sleep -Seconds 2
$enc = "自动免费节点(GH)"
$encUrl = "clash://install-config?url=local%3A%2F%2F%2Fsdcard%2FAndroid%2Fdata%2F$metaPkg%2Ffiles%2Fclash-free-auto.yaml&name=" + ([uri]::EscapeDataString($enc))
& $adb shell "am start -a android.intent.action.VIEW -d '$encUrl' $metaPkg" | Out-Null
Start-Sleep -Seconds 3
Log "import deep link triggered"

# 6) Verify: Meta's external file is now the fixed version (gstatic present)
$probe = & $adb shell "grep -ac gstatic $metaFile 2>/dev/null; grep -ac 'name:' $metaFile 2>/dev/null"
Log ("phone file check: gstatic=$(($probe -join '|').Split('|')[0]) proxies=$(($probe -join '|').Split('|')[1])")

Log "phone_sync OK"
exit 0
