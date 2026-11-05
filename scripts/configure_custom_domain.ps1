param(
    [ValidateSet('us-east-1', 'us-west-2')]
    [string]$Region = 'us-east-1',
    [string]$StackName = 'cloud-data-governance',
    [Parameter(Mandatory = $true)]
    [string]$DomainName,
    [Parameter(Mandatory = $true)]
    [string]$HostedZoneId,
    [Parameter(Mandatory = $true)]
    [string]$CertificateArn,
    [string]$CredentialsFile = ''
)

$ErrorActionPreference = 'Stop'
$env:AWS_PAGER = ''
$ProjectDir = Split-Path -Parent $PSScriptRoot

function Import-LearnerLabCredentials([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) {
        foreach ($Candidate in @((Join-Path $ProjectDir 'aws'), (Join-Path $ProjectDir 'aws.env'))) {
            if (Test-Path -LiteralPath $Candidate) { $Path = $Candidate; break }
        }
    }
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if (-not (Test-Path -LiteralPath $Path)) { throw "Credentials file was not found: $Path" }

    $Allowed = @{
        'aws_access_key_id' = 'AWS_ACCESS_KEY_ID'
        'aws_secret_access_key' = 'AWS_SECRET_ACCESS_KEY'
        'aws_session_token' = 'AWS_SESSION_TOKEN'
    }
    foreach ($Line in Get-Content -LiteralPath $Path) {
        if ($Line -notmatch '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') { continue }
        $Key = $Matches[1].Trim().ToLowerInvariant()
        if ($Allowed.ContainsKey($Key)) {
            [Environment]::SetEnvironmentVariable($Allowed[$Key], $Matches[2].Trim(), 'Process')
        }
    }
}

function Invoke-AwsText([string[]]$Arguments) {
    $Result = & aws @Arguments
    if ($LASTEXITCODE -ne 0) { throw "AWS CLI failed: aws $($Arguments -join ' ')" }
    return ($Result | Out-String).Trim()
}

function Test-CertificateCoversDomain([string]$CertificateName, [string]$RequestedDomain) {
    if ($CertificateName -eq $RequestedDomain) { return $true }
    if (-not $CertificateName.StartsWith('*.')) { return $false }
    $Suffix = $CertificateName.Substring(1)
    if (-not $RequestedDomain.EndsWith($Suffix)) { return $false }
    $Prefix = $RequestedDomain.Substring(0, $RequestedDomain.Length - $Suffix.Length)
    return $Prefix.Length -gt 0 -and -not $Prefix.Contains('.')
}

Import-LearnerLabCredentials $CredentialsFile
Invoke-AwsText @('sts', 'get-caller-identity', '--query', 'Account', '--output', 'text') | Out-Null

$ApiUrl = Invoke-AwsText @(
    'cloudformation', 'describe-stacks', '--region', $Region, '--stack-name', $StackName,
    '--query', "Stacks[0].Outputs[?OutputKey=='ApiUrl'].OutputValue | [0]", '--output', 'text'
)
if ($ApiUrl -notmatch '^https://([a-z0-9]+)\.execute-api\.') {
    throw "Could not derive the API id from stack output ApiUrl: $ApiUrl"
}
$ApiId = $Matches[1]

$Certificate = Invoke-AwsText @(
    'acm', 'describe-certificate', '--region', $Region, '--certificate-arn', $CertificateArn,
    '--query', 'Certificate.{Status:Status,Names:SubjectAlternativeNames}', '--output', 'json'
) | ConvertFrom-Json
if ($Certificate.Status -ne 'ISSUED') { throw "Certificate is not ISSUED: $($Certificate.Status)" }
$Covered = @($Certificate.Names | Where-Object { Test-CertificateCoversDomain $_ $DomainName })
if ($Covered.Count -eq 0) { throw "Certificate does not cover $DomainName" }

$DomainJson = & aws apigatewayv2 get-domain-name --region $Region --domain-name $DomainName --output json 2>$null
if ($LASTEXITCODE -ne 0) {
    Invoke-AwsText @(
        'apigatewayv2', 'create-domain-name', '--region', $Region, '--domain-name', $DomainName,
        '--domain-name-configurations', "CertificateArn=$CertificateArn,EndpointType=REGIONAL,SecurityPolicy=TLS_1_2",
        '--output', 'json'
    ) | Out-Null
}
else {
    $ExistingDomain = ($DomainJson | Out-String) | ConvertFrom-Json
    $ExistingCertificate = $ExistingDomain.DomainNameConfigurations[0].CertificateArn
    if ($ExistingCertificate -ne $CertificateArn) {
        throw "Custom domain already uses a different certificate: $ExistingCertificate"
    }
}

$DomainStatus = ''
for ($Attempt = 1; $Attempt -le 30; $Attempt++) {
    $DomainStatus = Invoke-AwsText @(
        'apigatewayv2', 'get-domain-name', '--region', $Region, '--domain-name', $DomainName,
        '--query', 'DomainNameConfigurations[0].DomainNameStatus', '--output', 'text'
    )
    if ($DomainStatus -eq 'AVAILABLE') { break }
    if ($DomainStatus -eq 'FAILED') { throw "API Gateway custom domain failed: $DomainName" }
    Start-Sleep -Seconds 10
}
if ($DomainStatus -ne 'AVAILABLE') { throw "Custom domain did not become AVAILABLE: $DomainStatus" }

$Mappings = Invoke-AwsText @(
    'apigatewayv2', 'get-api-mappings', '--region', $Region, '--domain-name', $DomainName, '--output', 'json'
) | ConvertFrom-Json
$RootMapping = @($Mappings.Items | Where-Object { [string]::IsNullOrWhiteSpace($_.ApiMappingKey) }) | Select-Object -First 1
if ($null -eq $RootMapping) {
    Invoke-AwsText @(
        'apigatewayv2', 'create-api-mapping', '--region', $Region, '--domain-name', $DomainName,
        '--api-id', $ApiId, '--stage', '$default', '--output', 'json'
    ) | Out-Null
}
elseif ($RootMapping.ApiId -ne $ApiId -or $RootMapping.Stage -ne '$default') {
    Invoke-AwsText @(
        'apigatewayv2', 'update-api-mapping', '--region', $Region, '--domain-name', $DomainName,
        '--api-mapping-id', $RootMapping.ApiMappingId, '--api-id', $ApiId, '--stage', '$default', '--output', 'json'
    ) | Out-Null
}

$DomainConfig = Invoke-AwsText @(
    'apigatewayv2', 'get-domain-name', '--region', $Region, '--domain-name', $DomainName,
    '--query', 'DomainNameConfigurations[0]', '--output', 'json'
) | ConvertFrom-Json
$ChangeBatch = [ordered]@{
    Changes = @(
        [ordered]@{
            Action = 'UPSERT'
            ResourceRecordSet = [ordered]@{
                Name = $DomainName
                Type = 'A'
                AliasTarget = [ordered]@{
                    HostedZoneId = $DomainConfig.HostedZoneId
                    DNSName = $DomainConfig.ApiGatewayDomainName
                    EvaluateTargetHealth = $false
                }
            }
        }
    )
} | ConvertTo-Json -Depth 8 -Compress
$ChangeId = Invoke-AwsText @(
    'route53', 'change-resource-record-sets', '--hosted-zone-id', $HostedZoneId,
    "--change-batch=$ChangeBatch", '--query', 'ChangeInfo.Id', '--output', 'text'
)
Invoke-AwsText @('route53', 'wait', 'resource-record-sets-changed', '--id', $ChangeId) | Out-Null

$TargetIp = Resolve-DnsName -Name $DomainConfig.ApiGatewayDomainName -Type A -Server 8.8.8.8 -DnsOnly |
    Where-Object { $_.IPAddress } | Select-Object -First 1 -ExpandProperty IPAddress
if ([string]::IsNullOrWhiteSpace($TargetIp)) { throw 'Could not resolve the API Gateway custom-domain target.' }
$Health = & curl.exe --silent --show-error --fail `
    --resolve "$DomainName`:443`:$TargetIp" "https://$DomainName/health"
if ($LASTEXITCODE -ne 0) { throw "Strict HTTPS health verification failed for $DomainName" }
$HealthObject = $Health | ConvertFrom-Json
if ($HealthObject.status -ne 'healthy') { throw "Unexpected health status: $($HealthObject.status)" }

Write-Host "Custom domain ready: https://$DomainName/"
Write-Host "API mapping: $ApiId / `$default"
Write-Host "HTTPS health: $($HealthObject.status)"
