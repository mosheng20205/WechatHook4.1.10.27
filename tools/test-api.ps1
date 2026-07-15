param(
    [string]$BaseUrl = "http://127.0.0.1:30001",
    [switch]$RequireLogin
)

$ErrorActionPreference = "Stop"

function Get-Json($Uri) {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $Uri -Method GET -TimeoutSec 10
    if ($response.StatusCode -ne 200) { throw "GET $Uri returned HTTP $($response.StatusCode)" }
    return [pscustomobject]@{ Headers = $response.Headers; Body = ($response.Content | ConvertFrom-Json) }
}

$status = Get-Json "$BaseUrl/QueryDB/status"
if ($status.Body.PSObject.Properties.Name -notcontains "IsLogin") { throw "status response has no IsLogin" }

$profileResponse = Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/GetSelfProfile" -Method POST `
    -Body "{}" -ContentType "application/json; charset=utf-8" -TimeoutSec 10
if ($profileResponse.StatusCode -ne 200) { throw "POST /GetSelfProfile returned HTTP $($profileResponse.StatusCode)" }
$profile = $profileResponse.Content | ConvertFrom-Json
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

[pscustomobject]@{
    Status = "PASS"
    IsLogin = $status.Body.IsLogin
    ProfileReadOk = $profile.profile_read_ok
    LoginStateSource = $status.Body.LoginStateSource
    ContentType = $profileResponse.Headers["Content-Type"]
}
