param(
    [ValidateSet('us-east-1', 'us-west-2')]
    [string]$Region = 'us-east-1',
    [string]$StackName = 'cloud-data-governance',
    [string]$ProjectName = 'cloud-data-governance',
    [ValidateSet('dev', 'test')]
    [string]$Environment = 'dev',
    [string]$CredentialsFile = '',
    [string]$CustomDomainName = '',
    [string]$HostedZoneId = '',
    [string]$CertificateArn = '',
    [string]$DashboardCustomOrigin = 'https://datasentinel.ifhx.my',
    [ValidateSet('true', 'false')]
    [string]$EphemeralProcessingMode = 'true'
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
if (-not [string]::IsNullOrWhiteSpace($DashboardCustomOrigin)) {
    $ParsedDashboardOrigin = $null
    if (-not [Uri]::TryCreate($DashboardCustomOrigin, [UriKind]::Absolute, [ref]$ParsedDashboardOrigin) `
        -or $ParsedDashboardOrigin.Scheme -ne 'https' `
        -or $ParsedDashboardOrigin.AbsolutePath -ne '/' `
        -or -not [string]::IsNullOrEmpty($ParsedDashboardOrigin.Query) `
        -or -not [string]::IsNullOrEmpty($ParsedDashboardOrigin.Fragment)) {
        throw 'DashboardCustomOrigin must be an HTTPS origin without a path, query, or fragment.'
    }
    $DashboardCustomOrigin = $DashboardCustomOrigin.TrimEnd('/')
}
function Get-SessionDerivedToken([string]$Purpose) {
    $Sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [Text.Encoding]::UTF8.GetBytes("$Purpose`:$($env:AWS_SESSION_TOKEN)")
        return ([BitConverter]::ToString($Sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant().Substring(0, 32)
    }
    finally { $Sha256.Dispose() }
}

$DashboardToken = $env:DASHBOARD_TOKEN
$AdminDashboardToken = $env:ADMIN_DASHBOARD_TOKEN
$AdminUsername = if ([string]::IsNullOrWhiteSpace($env:ADMIN_USERNAME)) { 'admin' } else { $env:ADMIN_USERNAME }
$AdminPassword = $env:ADMIN_PASSWORD
if (-not [string]::IsNullOrWhiteSpace($env:AWS_SESSION_TOKEN)) {
    if ([string]::IsNullOrWhiteSpace($DashboardToken)) { $DashboardToken = Get-SessionDerivedToken 'reviewer' }
    if ([string]::IsNullOrWhiteSpace($AdminDashboardToken)) { $AdminDashboardToken = Get-SessionDerivedToken 'administrator' }
    if ([string]::IsNullOrWhiteSpace($AdminPassword)) { $AdminPassword = Get-SessionDerivedToken 'console-admin-password' }
}
if ([string]::IsNullOrWhiteSpace($DashboardToken) -or $DashboardToken.Length -lt 16) {
    throw 'Set DASHBOARD_TOKEN to at least 16 characters, or provide valid Learner Lab credentials with a session token.'
}
if ([string]::IsNullOrWhiteSpace($AdminDashboardToken) -or $AdminDashboardToken.Length -lt 16) {
    throw 'Set ADMIN_DASHBOARD_TOKEN to at least 16 characters, or provide valid Learner Lab credentials with a session token.'
}
if ($DashboardToken -eq $AdminDashboardToken) { throw 'Reviewer and administrator tokens must be different.' }
if ([string]::IsNullOrWhiteSpace($AdminPassword) -or $AdminPassword.Length -lt 12) {
    throw 'Set ADMIN_PASSWORD to at least 12 characters, or provide a valid Learner Lab session token.'
}
$IntegrationApiKey = Get-SessionDerivedToken 'integration-api-key'
$IntegrationKeyHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $IntegrationApiKeyHash = ([BitConverter]::ToString(
        $IntegrationKeyHasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($IntegrationApiKey))
    )).Replace('-', '').ToLowerInvariant()
}
finally { $IntegrationKeyHasher.Dispose() }
$RolePassword = @{}
foreach ($RoleName in @('owner', 'reviewer', 'auditor')) {
    $Sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Bytes = [Text.Encoding]::UTF8.GetBytes("$RoleName`:$AdminDashboardToken")
        $RolePassword[$RoleName] = ([BitConverter]::ToString($Sha256.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant().Substring(0, 24)
    }
    finally { $Sha256.Dispose() }
}
$AccountId = aws sts get-caller-identity --query Account --output text
if ($LASTEXITCODE -ne 0) { throw 'AWS credentials are unavailable. Start the Learner Lab session first.' }
aws cloudformation list-stacks --region $Region --max-items 1 2>$null | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'The Learner Lab credentials are recognised but deployment access is denied. Start or resume the lab, replace aws.env with the new session credentials, and run this script again.'
}

$LabRoleArn = "arn:aws:iam::$AccountId`:role/LabRole"
$ReleasePython = Join-Path $ProjectDir '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $ReleasePython)) { $ReleasePython = 'python' }
& $ReleasePython (Join-Path $ProjectDir 'scripts\generate_release_manifest.py') `
    --release 'datasentinel-booth-2026.10' | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Release manifest generation failed.' }
$ReleaseManifest = Get-Content -LiteralPath (Join-Path $ProjectDir 'release-manifest.json') -Raw | ConvertFrom-Json
$ReleaseId = [string]$ReleaseManifest.source_tree_sha256
if ($ReleaseId -notmatch '^[a-f0-9]{64}$') { throw 'Release identity is invalid.' }
$ArtifactBucket = "$ProjectName-artifacts-$AccountId-$Region"
$BuildDir = Join-Path ([System.IO.Path]::GetTempPath()) ("cdg-" + [guid]::NewGuid())
$PackageDir = Join-Path $BuildDir 'package'
$ZipPath = Join-Path $BuildDir 'cloud-data-governance.zip'

try {
    Write-Host 'Checking access to the pre-created LabRole...'
    aws iam get-role --role-name LabRole --region $Region | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'LabRole cannot be read in this Learner Lab account.' }

    Write-Host 'Building Lambda package...'
    New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null
    python -m pip install --quiet --disable-pip-version-check `
        --platform manylinux_2_28_x86_64 `
        --platform manylinux2014_x86_64 `
        --implementation cp `
        --python-version 3.12 `
        --only-binary ':all:' `
        -r (Join-Path $ProjectDir 'deployment/lambda-requirements.txt') -t $PackageDir
    if ($LASTEXITCODE -ne 0) { throw 'Python dependency packaging failed.' }
    Copy-Item -Recurse -Force (Join-Path $ProjectDir 'src') (Join-Path $PackageDir 'src')
    Copy-Item -Recurse -Force (Join-Path $ProjectDir 'frontend') (Join-Path $PackageDir 'frontend')
    Compress-Archive -Path (Join-Path $PackageDir '*') -DestinationPath $ZipPath -CompressionLevel Optimal
    $CodeHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ZipPath).Hash.Substring(0, 16).ToLowerInvariant()
    $CodeKey = "lambda/cloud-data-governance-$CodeHash.zip"

    Write-Host 'Preparing encrypted deployment artifact bucket...'
    aws s3api head-bucket --bucket $ArtifactBucket 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        if ($Region -eq 'us-east-1') {
            aws s3api create-bucket --bucket $ArtifactBucket --region $Region | Out-Null
        } else {
            aws s3api create-bucket --bucket $ArtifactBucket --region $Region `
                --create-bucket-configuration "LocationConstraint=$Region" | Out-Null
        }
        if ($LASTEXITCODE -ne 0) { throw 'The encrypted deployment artifact bucket could not be created.' }
    }
    aws s3api put-public-access-block --bucket $ArtifactBucket `
        --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
    if ($LASTEXITCODE -ne 0) { throw 'The deployment artifact bucket public-access block could not be applied.' }
    $EncryptionConfigPath = Join-Path $BuildDir 's3-encryption.json'
    [IO.File]::WriteAllText($EncryptionConfigPath, '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}', [Text.UTF8Encoding]::new($false))
    aws s3api put-bucket-encryption --bucket $ArtifactBucket `
        --server-side-encryption-configuration "file://$EncryptionConfigPath"
    if ($LASTEXITCODE -ne 0) { throw 'The deployment artifact bucket encryption could not be applied.' }
    # Lambda packages in this project are well below S3's single-request
    # limit. A single PutObject is more reliable in Learner Lab networks than
    # the AWS CLI multipart upload used by `s3 cp`.
    aws s3api put-object --bucket $ArtifactBucket --key $CodeKey --body $ZipPath `
        --region $Region --server-side-encryption AES256 --no-cli-pager | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'The Lambda deployment artifact could not be uploaded.' }

    Write-Host "Deploying CloudFormation stack $StackName in $Region..."
    aws cloudformation deploy `
        --region $Region `
        --stack-name $StackName `
        --template-file (Join-Path $ProjectDir 'cloudformation/learner-lab.yml') `
        --no-fail-on-empty-changeset `
        --parameter-overrides `
            "ProjectName=$ProjectName" `
            "Environment=$Environment" `
            "LabRoleArn=$LabRoleArn" `
            "LambdaCodeBucket=$ArtifactBucket" `
            "LambdaCodeKey=$CodeKey" `
            "ReleaseId=$ReleaseId" `
            "DashboardToken=$DashboardToken" `
            "AdminDashboardToken=$AdminDashboardToken" `
            "AdminUsername=$AdminUsername" `
            "AdminPassword=$AdminPassword" `
            "IntegrationApiKeyHash=$IntegrationApiKeyHash" `
            "IntegrationTenantId=ifhx-demo" `
            "IntegrationClientId=booth-client" `
            "DashboardCustomOrigin=$DashboardCustomOrigin" `
            "EphemeralProcessingMode=$EphemeralProcessingMode"
    if ($LASTEXITCODE -ne 0) { throw 'CloudFormation deployment failed.' }

    Write-Host 'Backfilling sparse query indexes for existing evidence...'
    $MigrationPython = Join-Path $ProjectDir '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $MigrationPython)) { $MigrationPython = 'python' }
    & $MigrationPython (Join-Path $ProjectDir 'scripts\backfill_query_indexes.py') `
        --region $Region --stack $StackName --project $ProjectName --environment $Environment
    if ($LASTEXITCODE -ne 0) { throw 'DynamoDB query-index migration failed.' }

    Write-Host 'Verifying webhook queue consumption...'
    $WebhookFunctionName = aws cloudformation describe-stacks --region $Region --stack-name $StackName `
        --query "Stacks[0].Outputs[?OutputKey=='WebhookDispatcherFunctionName'].OutputValue | [0]" `
        --output text
    $MappingDetails = aws lambda list-event-source-mappings --region $Region `
        --function-name $WebhookFunctionName --query 'EventSourceMappings[0].[UUID,State]' --output text
    $MappingParts = @($MappingDetails -split '\s+' | Where-Object { $_ })
    if ($MappingParts.Count -lt 2 -or $MappingParts[0] -eq 'None') {
        throw 'Webhook event source mapping was not created.'
    }
    $MappingUuid = $MappingParts[0]
    $MappingState = $MappingParts[1]
    if ($MappingState -notin @('Enabled', 'Enabling')) {
        aws lambda update-event-source-mapping --region $Region --uuid $MappingUuid --enabled | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Webhook event source mapping could not be enabled.' }
    }
    foreach ($Attempt in 1..12) {
        $MappingState = aws lambda get-event-source-mapping --region $Region --uuid $MappingUuid `
            --query State --output text
        if ($MappingState -eq 'Enabled') { break }
        Start-Sleep -Seconds 5
    }
    if ($MappingState -ne 'Enabled') {
        throw "Webhook event source mapping is not healthy: $MappingState"
    }

    function Write-AtomicSecretFile([string]$Path, [string[]]$Lines) {
        $TemporaryPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
        try {
            [IO.File]::WriteAllLines($TemporaryPath, $Lines, [Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $TemporaryPath -Destination $Path -Force
        }
        finally {
            if (Test-Path -LiteralPath $TemporaryPath) {
                Remove-Item -LiteralPath $TemporaryPath -Force
            }
        }
    }

    Write-AtomicSecretFile (Join-Path $ProjectDir '.learner-lab-token') @($DashboardToken)
    Write-AtomicSecretFile (Join-Path $ProjectDir '.learner-lab-admin-token') @($AdminDashboardToken)
    Write-AtomicSecretFile (Join-Path $ProjectDir '.learner-lab-login') @(
        "admin=$AdminPassword"
        "owner=$($RolePassword['owner'])"
        "reviewer=$($RolePassword['reviewer'])"
        "auditor=$($RolePassword['auditor'])"
    )
    Write-AtomicSecretFile (Join-Path $ProjectDir '.datasentinel-integration-client') @(
        'tenant_id=ifhx-demo'
        'client_id=booth-client'
        "api_key=$IntegrationApiKey"
    )

    Write-Host 'Deployment complete. Stack outputs:'
    aws cloudformation describe-stacks --region $Region --stack-name $StackName `
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' --output table
    Write-Host "`nNext: .\scripts\verify_learner_lab.ps1 -Region $Region"
    Write-Host 'Console sign-in and Integration API credentials are ready in ignored local files.'

    $CustomDomainValues = @($CustomDomainName, $HostedZoneId, $CertificateArn)
    $ConfiguredCustomDomainValues = @($CustomDomainValues | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($ConfiguredCustomDomainValues.Count -gt 0 -and $ConfiguredCustomDomainValues.Count -ne 3) {
        throw 'CustomDomainName, HostedZoneId, and CertificateArn must be supplied together.'
    }
    if ($ConfiguredCustomDomainValues.Count -eq 3) {
        Write-Host "Ensuring custom domain $CustomDomainName..."
        & (Join-Path $PSScriptRoot 'configure_custom_domain.ps1') `
            -Region $Region `
            -StackName $StackName `
            -DomainName $CustomDomainName `
            -HostedZoneId $HostedZoneId `
            -CertificateArn $CertificateArn `
            -CredentialsFile $CredentialsFile
        if ($LASTEXITCODE -ne 0) { throw 'Custom-domain configuration failed.' }
    }
}
finally {
    if (Test-Path -LiteralPath $BuildDir) {
        Remove-Item -LiteralPath $BuildDir -Recurse -Force
    }
}
