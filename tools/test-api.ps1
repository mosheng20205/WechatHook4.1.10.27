param(
    [string]$BaseUrl = "http://127.0.0.1:30001",
    [switch]$RequireLogin,
    [string]$ContactWxid = "",
    [string]$SendTextTo = "",
    [string]$SendText = ""
)

$ErrorActionPreference = "Stop"

function Get-Json($Uri) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method GET -TimeoutSec 10
    if ($response.StatusCode -ne 200) { throw "GET $Uri returned HTTP $($response.StatusCode)" }
    return [pscustomobject]@{ Headers = $response.Headers; Body = ($response.Content | ConvertFrom-Json) }
}

function Post-Json($Uri, $Body) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method POST `
        -Body ($Body | ConvertTo-Json -Compress) `
        -ContentType "application/json; charset=utf-8" -TimeoutSec 15
    if ($response.StatusCode -ne 200) { throw "POST $Uri returned HTTP $($response.StatusCode)" }
    return [pscustomobject]@{ Headers = $response.Headers; Body = ($response.Content | ConvertFrom-Json) }
}

$status = Get-Json "$BaseUrl/QueryDB/status"
if ($status.Body.PSObject.Properties.Name -notcontains "IsLogin") { throw "status response has no IsLogin" }

$profileResponse = Post-Json "$BaseUrl/GetSelfProfile" @{}
$profile = $profileResponse.Body
if ($profileResponse.Headers["Content-Type"] -notmatch "charset=utf-8") {
    throw "GetSelfProfile must return UTF-8 Content-Type"
}

if ($RequireLogin -and $status.Body.IsLogin -ne 1) { throw "WeChat is not logged in" }
if ($status.Body.IsLogin -eq 1 -and $profile.profile_read_ok -ne $true) {
    throw "Profile read failed while logged in"
}
if ($status.Body.IsLogin -eq 0 -and $profile.profile_read_ok -eq $true) {
    throw "Profile data leaked while logged out"
}

if ($ContactWxid) {
    if ($status.Body.IsLogin -ne 1) { throw "Contact test requires WeChat to be logged in" }
    $contactResponse = Post-Json "$BaseUrl/GetContact" @{ wxid = $ContactWxid }
    if ($contactResponse.Body.status -ne 0 -or $contactResponse.Body.contact_found -ne $true) {
        throw "Contact lookup failed for $ContactWxid"
    }
}

if ($SendTextTo -or $SendText) {
    if (-not $SendTextTo -or -not $SendText) {
        throw "SendTextTo and SendText must be supplied together"
    }
    if ($status.Body.IsLogin -ne 1) { throw "Text send test requires WeChat to be logged in" }
    $sendResponse = Post-Json "$BaseUrl/SendTextMsg" @{
        wxidorgid = $SendTextTo
        msg = $SendText
    }
    if ($sendResponse.Body.ret -ne 0 -or $sendResponse.Body.queued -ne $true) {
        throw "Text message was not queued"
    }
}

[pscustomobject]@{
    Status = "PASS"
    IsLogin = $status.Body.IsLogin
    ProfileReadOk = $profile.profile_read_ok
    LoginStateSource = $status.Body.LoginStateSource
    ContactTested = [bool]$ContactWxid
    TextSendTested = [bool]$SendTextTo
    ContentType = $profileResponse.Headers["Content-Type"]
}
