param(
    [string]$Item = "PCWeixinHook",
    [string]$DefaultPageId = "11559060626558382",
    [string]$OutputDir = "docs/showdoc/PC_Weixin_Hook"
)

$ErrorActionPreference = "Stop"
$ApiBase = "https://showdoc-server.cdn.dfyun.com.cn/server/index.php"

function Invoke-ShowDocApi {
    param(
        [Parameter(Mandatory = $true)][string]$Route,
        [Parameter(Mandatory = $true)][hashtable]$Body
    )

    $client = [System.Net.WebClient]::new()
    $client.Headers[[System.Net.HttpRequestHeader]::Referer] = "https://www.showdoc.com.cn/"
    $form = [System.Collections.Specialized.NameValueCollection]::new()
    foreach ($key in $Body.Keys) {
        $form.Add([string]$key, [string]$Body[$key])
    }
    try {
        $responseBytes = $client.UploadValues("${ApiBase}?s=$Route", "POST", $form)
        $response = ([System.Text.Encoding]::UTF8.GetString($responseBytes) | ConvertFrom-Json)
    }
    finally {
        $client.Dispose()
    }

    if ($response.error_code -ne 0) {
        throw "ShowDoc API $Route failed: $($response.error_message)"
    }
    return $response.data
}

function Get-SafeName {
    param([Parameter(Mandatory = $true)][string]$Name)

    $safe = $Name -replace '[\\/:*?"<>|]', '_'
    $safe = $safe.Trim().TrimEnd('.')
    if ([string]::IsNullOrWhiteSpace($safe)) {
        return "untitled"
    }
    if ($safe.Length -gt 100) {
        $safe = $safe.Substring(0, 100).TrimEnd()
    }
    return $safe
}

function Get-OrderedEntries {
    param([object[]]$Entries)
    return @($Entries | Sort-Object { [int]$_.s_number }, { $_.page_title }, { $_.cat_name })
}

$itemInfo = Invoke-ShowDocApi -Route "/api/item/info" -Body @{
    item_id         = $Item
    keyword         = ""
    default_page_id = $DefaultPageId
    _item_pwd       = "null"
}

$root = Join-Path (Get-Location) $OutputDir
New-Item -ItemType Directory -Force -Path $root | Out-Null

$script:pageCount = 0
$script:indexLines = [System.Collections.Generic.List[string]]::new()
$script:indexLines.Add("# $($itemInfo.item_name)")
$script:indexLines.Add("")
$script:indexLines.Add("Automatically exported from [ShowDoc](https://www.showdoc.com.cn/$Item/$DefaultPageId).")
$script:indexLines.Add("")

function Export-Page {
    param(
        [Parameter(Mandatory = $true)]$Page,
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$RelativeDirectory,
        [Parameter(Mandatory = $true)][int]$Depth
    )

    $pageInfo = Invoke-ShowDocApi -Route "/api/page/info" -Body @{
        page_id  = [string]$Page.page_id
        _item_pwd = "null"
    }

    $fileName = "$(Get-SafeName -Name ([string]$Page.page_title)).md"
    $filePath = Join-Path $Directory $fileName
    $sourceUrl = "https://www.showdoc.com.cn/$Item/$($Page.page_id)"
    $content = [System.Net.WebUtility]::HtmlDecode([string]$pageInfo.page_content).Trim()
    $markdown = @(
        "# $($pageInfo.page_title)",
        "",
        "> Source: [$sourceUrl]($sourceUrl)  ",
        "> ShowDoc page_id: $($Page.page_id)",
        "",
        $content,
        ""
    ) -join [Environment]::NewLine

    [System.IO.File]::WriteAllText($filePath, $markdown, [System.Text.UTF8Encoding]::new($false))
    $script:pageCount++

    $relativePath = if ([string]::IsNullOrEmpty($RelativeDirectory)) {
        $fileName
    } else {
        "$($RelativeDirectory.Replace('\', '/'))/$fileName"
    }
    $indent = "  " * $Depth
    $script:indexLines.Add("$indent- [$($Page.page_title)]($relativePath)")
}

function Export-Catalog {
    param(
        [Parameter(Mandatory = $true)]$Catalog,
        [Parameter(Mandatory = $true)][string]$ParentDirectory,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$ParentRelativeDirectory,
        [Parameter(Mandatory = $true)][int]$Depth
    )

    $prefix = ([int]$Catalog.s_number).ToString("00")
    $directoryName = "$prefix-$(Get-SafeName -Name ([string]$Catalog.cat_name))"
    $directory = Join-Path $ParentDirectory $directoryName
    $relativeDirectory = if ([string]::IsNullOrEmpty($ParentRelativeDirectory)) {
        $directoryName
    } else {
        Join-Path $ParentRelativeDirectory $directoryName
    }
    New-Item -ItemType Directory -Force -Path $directory | Out-Null

    $indent = "  " * $Depth
    $script:indexLines.Add("$indent- **$($Catalog.cat_name)**")

    foreach ($page in (Get-OrderedEntries -Entries @($Catalog.pages))) {
        Export-Page -Page $page -Directory $directory -RelativeDirectory $relativeDirectory -Depth ($Depth + 1)
    }
    foreach ($child in (Get-OrderedEntries -Entries @($Catalog.catalogs))) {
        Export-Catalog -Catalog $child -ParentDirectory $directory -ParentRelativeDirectory $relativeDirectory -Depth ($Depth + 1)
    }
}

foreach ($page in (Get-OrderedEntries -Entries @($itemInfo.menu.pages))) {
    Export-Page -Page $page -Directory $root -RelativeDirectory "" -Depth 0
}
foreach ($catalog in (Get-OrderedEntries -Entries @($itemInfo.menu.catalogs))) {
    Export-Catalog -Catalog $catalog -ParentDirectory $root -ParentRelativeDirectory "" -Depth 0
}

$indexPath = Join-Path $root "README.md"
[System.IO.File]::WriteAllLines($indexPath, $script:indexLines, [System.Text.UTF8Encoding]::new($false))

Write-Output "Exported $script:pageCount Markdown pages to $root"
