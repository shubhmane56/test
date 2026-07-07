<#
.SYNOPSIS
    Tests which AI-related domains are BLOCKED or ALLOWED on the current network.

.DESCRIPTION
    Performs read-only checks against a broad list of AI-related domains
    (chatbots, coding assistants, image/video/voice generators, writing
    tools, etc.) to help identify "shadow AI" - unapproved AI tools that
    employees may be using outside of sanctioned/company-approved services.

    For each domain, this script:
      1. Attempts DNS resolution.
      2. Attempts an HTTPS request (HEAD, falling back to GET) to the domain.

    It does NOT attempt to bypass, tunnel through, or circumvent any
    security control - it simply reports what the network currently allows.

.PARAMETER InputFile
    Path to a text file containing one domain per line. Lines starting with
    '#' are treated as comments. If omitted, a built-in default list is used.

.PARAMETER OutputFile
    Path to write a CSV file of detailed results. Defaults to
    ai_domain_check_results.csv in the current directory.

.PARAMETER TimeoutSeconds
    Timeout in seconds for each DNS/HTTPS check. Defaults to 5.

.EXAMPLE
    .\ai_domain_checker.ps1

.EXAMPLE
    .\ai_domain_checker.ps1 -InputFile .\domains.txt -OutputFile results.csv -TimeoutSeconds 8

.NOTES
    If script execution is blocked by policy, run it with:
        powershell -ExecutionPolicy Bypass -File .\ai_domain_checker.ps1
#>

[CmdletBinding()]
param(
    [string]$InputFile,
    [string]$OutputFile = "ai_domain_check_results.csv",
    [int]$TimeoutSeconds = 5
)

# Default list of AI-related domains, grouped by category for readability.
# Edit this list, or supply your own with -InputFile domains.txt
$DefaultDomains = @(
    # --- OpenAI ---
    "openai.com",
    "chat.openai.com",
    "chatgpt.com",
    "platform.openai.com",
    # --- Anthropic (Claude) ---
    "claude.ai",
    "anthropic.com",
    "console.anthropic.com",
    # --- Google ---
    "bard.google.com",
    "gemini.google.com",
    "aistudio.google.com",
    "labs.google",
    # --- Microsoft ---
    "copilot.microsoft.com",
    "copilot.cloud.microsoft",
    # --- xAI ---
    "x.ai",
    "grok.com",
    # --- Meta ---
    "meta.ai",
    # --- Perplexity ---
    "perplexity.ai",
    # --- Mistral ---
    "mistral.ai",
    "chat.mistral.ai",
    "lechat.mistral.ai",
    # --- DeepSeek ---
    "deepseek.com",
    "chat.deepseek.com",
    # --- Alibaba Qwen ---
    "qwen.ai",
    "chat.qwen.ai",
    "tongyi.aliyun.com",
    # --- Baidu ---
    "yiyan.baidu.com",
    "ernie.baidu.com",
    # --- Zhipu / Moonshot (Chinese AI assistants) ---
    "chatglm.cn",
    "moonshot.cn",
    "moonshot.ai",
    "kimi.moonshot.cn",
    "kimi.ai",
    # --- Inflection ---
    "pi.ai",
    "inflection.ai",
    # --- Character / general chat ---
    "character.ai",
    "poe.com",
    "you.com",
    # --- Model providers / infra ---
    "groq.com",
    "together.ai",
    "cohere.com",
    "cohere.ai",
    "ai21.com",
    "huggingface.co",
    # --- AI coding assistants ---
    "cursor.sh",
    "cursor.com",
    "tabnine.com",
    "codeium.com",
    "windsurf.com",
    "sourcegraph.com",
    "replit.com",
    "v0.dev",
    "bolt.new",
    "lovable.dev",
    # --- Image / video / voice generation ---
    "midjourney.com",
    "stability.ai",
    "dreamstudio.ai",
    "runwayml.com",
    "pika.art",
    "lumalabs.ai",
    "firefly.adobe.com",
    "leonardo.ai",
    "elevenlabs.io",
    "synthesia.io",
    "suno.ai",
    "udio.com",
    "descript.com",
    # --- Writing / productivity ---
    "notion.ai",
    "jasper.ai",
    "writesonic.com",
    "copy.ai",
    "rytr.me",
    "grammarly.com",
    "quillbot.com",
    "gamma.app",
    "otter.ai",
    "fireflies.ai",
    # --- Translation ---
    "deepl.com",
    # --- Misc / aggregators ---
    "phind.com",
    "replicate.com",
    "abacus.ai"
)

function Test-DomainDns {
    param(
        [string]$Domain,
        [int]$Timeout
    )
    try {
        $task = [System.Net.Dns]::GetHostAddressesAsync($Domain)
        if ($task.Wait([TimeSpan]::FromSeconds($Timeout))) {
            if ($task.Result -and $task.Result.Count -gt 0) {
                return @{ Ok = $true; Error = $null }
            }
            return @{ Ok = $false; Error = "No addresses returned" }
        }
        else {
            return @{ Ok = $false; Error = "DNS resolution timed out" }
        }
    }
    catch {
        $msg = $_.Exception.InnerException.Message
        if (-not $msg) { $msg = $_.Exception.Message }
        return @{ Ok = $false; Error = "DNS resolution failed: $msg" }
    }
}

function Test-DomainHttps {
    param(
        [string]$Domain,
        [int]$Timeout
    )
    $url = "https://$Domain"
    try {
        $response = Invoke-WebRequest -Uri $url -Method Head -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
        return @{ Ok = $true; Info = [int]$response.StatusCode }
    }
    catch {
        # Some servers reject HEAD or throw on non-2xx - inspect the response if we have one
        if ($_.Exception.Response) {
            try {
                $statusCode = [int]$_.Exception.Response.StatusCode
                return @{ Ok = $true; Info = $statusCode }
            }
            catch { }
        }
        # Retry once with GET before giving up
        try {
            $response = Invoke-WebRequest -Uri $url -Method Get -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
            return @{ Ok = $true; Info = [int]$response.StatusCode }
        }
        catch {
            return @{ Ok = $false; Info = "Connection failed: $($_.Exception.Message)" }
        }
    }
}

function Test-Domain {
    param(
        [string]$Domain,
        [int]$Timeout
    )

    $result = [ordered]@{
        Domain             = $Domain
        DnsResolved        = $false
        DnsError           = $null
        HttpsReachable     = $false
        HttpsStatusOrError = $null
        Verdict            = "BLOCKED"
        CheckedAt          = (Get-Date).ToString("s")
    }

    $dns = Test-DomainDns -Domain $Domain -Timeout $Timeout
    $result.DnsResolved = $dns.Ok
    $result.DnsError = $dns.Error

    if (-not $dns.Ok) {
        $result.Verdict = "BLOCKED (DNS)"
        return [pscustomobject]$result
    }

    $https = Test-DomainHttps -Domain $Domain -Timeout $Timeout
    $result.HttpsReachable = $https.Ok
    $result.HttpsStatusOrError = $https.Info
    $result.Verdict = if ($https.Ok) { "ALLOWED" } else { "BLOCKED (Connection)" }

    return [pscustomobject]$result
}

# --- Load domain list ---
if ($InputFile) {
    if (-not (Test-Path $InputFile)) {
        Write-Error "Input file not found: $InputFile"
        exit 1
    }
    $Domains = Get-Content -Path $InputFile |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -and -not $_.StartsWith("#") }
}
else {
    $Domains = $DefaultDomains
}

Write-Host "Testing $($Domains.Count) domain(s) with a $TimeoutSeconds second timeout...`n"
Write-Host ("{0,-28} {1,-22} {2}" -f "DOMAIN", "VERDICT", "DETAILS")
Write-Host ("-" * 80)

$Results = @()
foreach ($domain in $Domains) {
    $r = Test-Domain -Domain $domain -Timeout $TimeoutSeconds
    $detail = if ($r.DnsError) { $r.DnsError } elseif ($r.HttpsStatusOrError) { $r.HttpsStatusOrError } else { "OK" }
    Write-Host ("{0,-28} {1,-22} {2}" -f $r.Domain, $r.Verdict, $detail)
    $Results += $r
}

$Allowed = $Results | Where-Object { $_.Verdict -eq "ALLOWED" }
$Blocked = $Results | Where-Object { $_.Verdict -ne "ALLOWED" }

Write-Host "`nSummary"
Write-Host ("-" * 80)
Write-Host "Total tested : $($Results.Count)"
Write-Host "Allowed      : $($Allowed.Count)"
Write-Host "Blocked      : $($Blocked.Count)"

$Results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8

Write-Host "`nDetailed results written to: $OutputFile"
