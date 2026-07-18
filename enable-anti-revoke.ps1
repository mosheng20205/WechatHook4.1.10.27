param(
    [string]$BaseUrl = "http://127.0.0.1:30001"
)

$ErrorActionPreference = "Stop"

function Enable-Feature {
    param(
        [string]$Name,
        [string]$Path
    )

    $result = Invoke-RestMethod `
        -Uri "$BaseUrl$Path" `
        -Method Post `
        -ContentType "application/json; charset=utf-8" `
        -Body '{"enabled":true}' `
        -TimeoutSec 10

    if ($result.ret -ne 0 -or $result.enabled -ne $true) {
        throw "The API did not confirm that $Name is enabled: $($result | ConvertTo-Json -Compress)"
    }

    Write-Host "$Name enabled successfully." -ForegroundColor Green
    $result | ConvertTo-Json -Depth 8
}

try {
    # 1) Keep recalled messages (text AND image) visible.
    Enable-Feature -Name "Anti-revoke" -Path "/AntiRevoke/config"

    # 2) Also inject the "<name> 撤回了一条消息" gray tip.  This only has a
    #    visible effect while anti-revoke is on, so it is enabled second.
    Enable-Feature -Name "Revoke tip" -Path "/RevokeTip/config"

    Write-Host "Anti-revoke + revoke tip are both enabled." -ForegroundColor Green
}
catch {
    Write-Error "Failed to enable anti-revoke + revoke tip. Make sure WeChat was started with the hook and port 30001 is available. $($_.Exception.Message)"
    exit 1
}
