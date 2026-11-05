param(
    [ValidateSet('us-east-1', 'us-west-2')]
    [string]$Region = 'us-east-1',
    [string]$StackName = 'cloud-data-governance',
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

Import-LearnerLabCredentials $CredentialsFile
$AdminUsername = if ([string]::IsNullOrWhiteSpace($env:ADMIN_USERNAME)) { 'admin' } else { $env:ADMIN_USERNAME }
$AdminPassword = $env:ADMIN_PASSWORD
if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
    $LoginFile = Join-Path $ProjectDir '.learner-lab-login'
    if (Test-Path -LiteralPath $LoginFile) {
        $AdminLine = Get-Content -LiteralPath $LoginFile | Where-Object { $_ -like 'admin=*' } | Select-Object -First 1
        if ($AdminLine) { $AdminPassword = $AdminLine.Substring('admin='.Length) }
    }
}
if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
    throw 'Administrator password is unavailable. Deploy first or set ADMIN_PASSWORD.'
}

function Get-StackOutput([string]$Key) {
    aws cloudformation describe-stacks --region $Region --stack-name $StackName `
        --query "Stacks[0].Outputs[?OutputKey=='$Key'].OutputValue" --output text
}

function Invoke-ApiWithRetry([string]$Uri, [hashtable]$Headers = @{}, [Microsoft.PowerShell.Commands.WebRequestSession]$WebSession = $null) {
    $TransientStatuses = @(429, 502, 503, 504)
    foreach ($Attempt in 1..6) {
        try {
            if ($WebSession) { return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers -WebSession $WebSession }
            return Invoke-RestMethod -Method Get -Uri $Uri -Headers $Headers
        }
        catch {
            $StatusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
            if ($Attempt -eq 6 -or $StatusCode -notin $TransientStatuses) { throw }
            Write-Host "Transient API response $StatusCode; retrying ($Attempt/6)..."
            Start-Sleep -Seconds ([Math]::Min($Attempt, 3))
        }
    }
}

$RawBucket = Get-StackOutput 'RawDataBucketName'
$CleanBucket = Get-StackOutput 'CleanDataBucketName'
$ResultsTable = Get-StackOutput 'ResultsTableName'
$AuditTable = Get-StackOutput 'AuditTableName'
$ApiUrl = Get-StackOutput 'ApiUrl'
$ClassifierFunction = Get-StackOutput 'ClassifierFunctionName'
$ReleaseId = Get-StackOutput 'ReleaseId'
$ManifestPath = Join-Path $ProjectDir 'release-manifest.json'
if (-not (Test-Path -LiteralPath $ManifestPath)) {
    throw 'Local release manifest is missing. Deploy the current release first.'
}
$LocalReleaseId = [string](Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json).source_tree_sha256
if ($ReleaseId -ne $LocalReleaseId) {
    throw 'The deployed release does not match the local release manifest.'
}
$Config = Invoke-ApiWithRetry -Uri "$ApiUrl/config"
if ($Config.service_mode -eq 'direct_redaction') {
    Write-Host 'Verifying direct, no-inventory processing...'
    $Health = Invoke-ApiWithRetry -Uri "$ApiUrl/health"
    if ($Health.release_id -ne $ReleaseId) { throw 'Health release identity does not match the stack.' }
    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $Page = Invoke-WebRequest -Method Get -Uri "$ApiUrl/" -WebSession $WebSession
    if ($Page.Content -notmatch 'Protect and download' -or $Page.Content -match 'Data inventory') {
        throw 'The direct-processing page is not active.'
    }
    $Headers = @{ 'X-Filename' = 'synthetic.txt' }
    if (-not $Config.public_free_api) {
        $LoginResponse = Invoke-WebRequest -Method Post -Uri "$ApiUrl/auth/login" -ContentType 'application/json' `
            -Body (@{ username = $AdminUsername; password = $AdminPassword } | ConvertTo-Json -Compress) -WebSession $WebSession
        $Login = $LoginResponse.Content | ConvertFrom-Json
        if ($Login.access_role -ne 'ADMIN') { throw 'Administrator sign-in failed.' }
        $Csrf = $WebSession.Cookies.GetCookies($ApiUrl)['ds_csrf'].Value
        if (-not $Csrf) { throw 'CSRF cookie is missing.' }
        $Headers['X-CSRF-Token'] = $Csrf
    }
    $Synthetic = [Text.Encoding]::UTF8.GetBytes("NRIC: 900101-14-5555`nEmail: learner@example.com")
    $Protected = Invoke-WebRequest -Method Post -Uri "$ApiUrl/api/v1/protect" `
        -ContentType 'text/plain' -Body $Synthetic -WebSession $WebSession `
        -Headers $Headers
    if ($Protected.StatusCode -ne 200 -or $Protected.Content -match '900101-14-5555|learner@example\.com' `
        -or $Protected.Content -notmatch 'REDACTED') {
        throw 'Direct protected output failed the sensitive-value check.'
    }
    Write-Host 'Direct download returned a redacted file. The public mode keeps only an aggregate daily usage count; document storage must be checked separately.'
    Write-Host "Release $ReleaseId verified."
    return
}
$TestKey = 'evidence/learner-lab-sensitive-' + [guid]::NewGuid().ToString('N') + '.txt'
$TestFile = Join-Path ([System.IO.Path]::GetTempPath()) ("cdg-evidence-" + [guid]::NewGuid() + '.txt')

try {
    @(
        'Classification evidence sample for the academic Learner Lab.'
        'NRIC: 900101-14-5555'
        'Email: learner@example.com'
    ) | Set-Content -LiteralPath $TestFile -Encoding utf8

    Write-Host 'Uploading controlled synthetic test data...'
    aws s3api put-object --region $Region --bucket $RawBucket --key $TestKey `
        --body $TestFile --content-type text/plain `
        --tagging 'DataOwner=LearnerLab&Sensitivity=Unknown&CostCenter=Academic' | Out-Null

    $ResourceId = "s3://$RawBucket/$TestKey"
    Write-Host 'Waiting up to 60 seconds for asynchronous classification...'
    $Found = $null
    foreach ($Attempt in 1..12) {
        $Found = aws dynamodb query --region $Region --table-name $ResultsTable `
            --key-condition-expression 'resource_id = :resource' `
            --expression-attribute-values ":resource={S=$ResourceId}" --no-scan-index-forward `
            --query 'sort_by(Items,&timestamp.S)[-1].sensitivity_level.S' --output text 2>$null
        if ($Found -eq 'RESTRICTED') { break }
        Start-Sleep -Seconds 5
    }

    if ($Found -ne 'RESTRICTED') {
        throw "Expected RESTRICTED but received '$Found'. Inspect: aws logs tail /aws/lambda/$ClassifierFunction --since 10m --region $Region"
    }

    Write-Host 'Classification result: RESTRICTED'
    $ProtectedText = aws s3 cp "s3://$CleanBucket/$TestKey" - --region $Region
    if ($LASTEXITCODE -ne 0) { throw 'Protected output could not be downloaded.' }
    $ProtectedText = $ProtectedText -join "`n"
    if ($ProtectedText -match '900101-14-5555|learner@example\.com') {
        throw 'Protected output still contains a test sensitive value.'
    }
    if ($ProtectedText -notmatch 'REDACTED') { throw 'Expected redaction marker is missing.' }
    Write-Host 'Protected output downloaded; test NRIC and email removed.'

    $AuditCount = 0
    foreach ($Attempt in 1..6) {
        $AuditCount = aws dynamodb scan --region $Region --table-name $AuditTable `
            --select COUNT --query Count --output text
        if ([int]$AuditCount -gt 0) { break }
        Start-Sleep -Seconds 2
    }
    if ([int]$AuditCount -lt 1) { throw 'No audit record was created.' }
    Write-Host "Audit records present: $AuditCount"
    Write-Host 'Public health endpoint:'
    $Health = Invoke-ApiWithRetry -Uri "$ApiUrl/health"
    if ($Health.release_id -ne $ReleaseId) {
        throw 'The health endpoint release identity does not match the stack output.'
    }
    $Health | ConvertTo-Json -Compress
    Write-Host 'Administrator sign-in and authenticated dashboard API:'
    $WebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $LoginResponse = Invoke-WebRequest -Method Post -Uri "$ApiUrl/auth/login" -ContentType 'application/json' `
        -Body (@{ username = $AdminUsername; password = $AdminPassword } | ConvertTo-Json -Compress) -WebSession $WebSession
    $Login = $LoginResponse.Content | ConvertFrom-Json
    if ($Login.access_role -ne 'ADMIN' -or -not $WebSession.Cookies.GetCookies($ApiUrl)['dashboard_session']) {
        throw 'Administrator sign-in did not return a valid session cookie.'
    }
    Invoke-ApiWithRetry -Uri "$ApiUrl/dashboard/summary" -WebSession $WebSession | ConvertTo-Json -Depth 8 -Compress
    Write-Host "`nCore Learner Lab verification passed."
}
finally {
    if (Test-Path -LiteralPath $TestFile) {
        Remove-Item -LiteralPath $TestFile -Force
    }
}
