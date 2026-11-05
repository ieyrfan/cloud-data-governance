param(
    [ValidateSet('us-east-1', 'us-west-2')]
    [string]$Region = 'us-east-1',
    [string]$StackName = 'cloud-data-governance',
    [string]$CredentialsFile = '',
    [string]$BaseUrl = 'https://datasentinel.ifhx.my'
)

$ErrorActionPreference = 'Stop'
$ProjectDir = Split-Path -Parent $PSScriptRoot

if ([string]::IsNullOrWhiteSpace($CredentialsFile)) {
    foreach ($Candidate in @((Join-Path $ProjectDir 'aws'), (Join-Path $ProjectDir 'aws.env'))) {
        if (Test-Path -LiteralPath $Candidate) { $CredentialsFile = $Candidate; break }
    }
}
if (-not [string]::IsNullOrWhiteSpace($CredentialsFile)) {
    $Allowed = @{
        'aws_access_key_id' = 'AWS_ACCESS_KEY_ID'
        'aws_secret_access_key' = 'AWS_SECRET_ACCESS_KEY'
        'aws_session_token' = 'AWS_SESSION_TOKEN'
    }
    foreach ($Line in Get-Content -LiteralPath $CredentialsFile) {
        if ($Line -notmatch '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') { continue }
        $Key = $Matches[1].Trim().ToLowerInvariant()
        if ($Allowed.ContainsKey($Key)) {
            [Environment]::SetEnvironmentVariable($Allowed[$Key], $Matches[2].Trim(), 'Process')
        }
    }
}

$Python = Join-Path $ProjectDir '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $Python)) { $Python = 'python' }

Write-Host 'Gate 1/3: core AWS, classification, audit, release identity, and administrator API...'
& (Join-Path $PSScriptRoot 'verify_learner_lab.ps1') `
    -Region $Region -StackName $StackName -CredentialsFile $CredentialsFile
if ($LASTEXITCODE -ne 0) { throw 'Core Learner Lab verification failed.' }

Write-Host 'Gate 2/3: format-preserving PDF protection and human role boundary...'
& $Python (Join-Path $PSScriptRoot 'live_pdf_acceptance.py') `
    --region $Region --stack-name $StackName `
    --login-file (Join-Path $ProjectDir '.learner-lab-login')
if ($LASTEXITCODE -ne 0) { throw 'Live PDF acceptance failed.' }

Write-Host 'Gate 3/3: Integration API isolation, idempotency, and protected retrieval...'
& $Python (Join-Path $PSScriptRoot 'verify_integration_api.py') `
    --base-url $BaseUrl `
    --client-file (Join-Path $ProjectDir '.datasentinel-integration-client')
if ($LASTEXITCODE -ne 0) { throw 'Integration API acceptance failed.' }

Write-Host "`nDataSentinel release verification passed all three gates."
