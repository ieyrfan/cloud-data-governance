param(
    [ValidateSet('us-east-1', 'us-west-2')]
    [string]$Region = 'us-east-1',
    [string]$StackName = 'cloud-data-governance',
    [string]$ProjectName = 'cloud-data-governance',
    [string]$CredentialsFile = ''
)

$ErrorActionPreference = 'Stop'
$env:AWS_PAGER = ''
$ProjectDir = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($CredentialsFile)) {
    foreach ($Candidate in @((Join-Path $ProjectDir 'aws'), (Join-Path $ProjectDir 'aws.env'))) {
        if (Test-Path -LiteralPath $Candidate) { $CredentialsFile = $Candidate; break }
    }
}
if (-not [string]::IsNullOrWhiteSpace($CredentialsFile)) {
    if (-not (Test-Path -LiteralPath $CredentialsFile)) { throw "Credentials file was not found: $CredentialsFile" }
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
$AccountId = aws sts get-caller-identity --query Account --output text
$ArtifactBucket = "$ProjectName-artifacts-$AccountId-$Region"

function Get-StackOutput([string]$Key) {
    aws cloudformation describe-stacks --region $Region --stack-name $StackName `
        --query "Stacks[0].Outputs[?OutputKey=='$Key'].OutputValue" --output text
}

foreach ($Bucket in @((Get-StackOutput 'RawDataBucketName'), (Get-StackOutput 'CleanDataBucketName'))) {
    Write-Host "Emptying versioned bucket $Bucket before stack deletion..."
    do {
        $Response = aws s3api list-object-versions --bucket $Bucket --region $Region `
            --max-items 1000 --output json | ConvertFrom-Json
        $Objects = @()
        foreach ($Version in @($Response.Versions)) {
            if ($null -ne $Version) { $Objects += @{ Key = $Version.Key; VersionId = $Version.VersionId } }
        }
        foreach ($Marker in @($Response.DeleteMarkers)) {
            if ($null -ne $Marker) { $Objects += @{ Key = $Marker.Key; VersionId = $Marker.VersionId } }
        }
        if ($Objects.Count -gt 0) {
            $DeletePayload = @{ Objects = $Objects; Quiet = $true } | ConvertTo-Json -Depth 5 -Compress
            aws s3api delete-objects --bucket $Bucket --region $Region --delete $DeletePayload | Out-Null
        }
    } while ($Objects.Count -gt 0)
}

Write-Host "Deleting stack $StackName..."
aws cloudformation delete-stack --region $Region --stack-name $StackName
aws cloudformation wait stack-delete-complete --region $Region --stack-name $StackName

Write-Host 'Deleting deployment artifacts...'
aws s3 rm "s3://$ArtifactBucket" --recursive --region $Region --only-show-errors
aws s3api delete-bucket --bucket $ArtifactBucket --region $Region 2>$null
Write-Host 'Cleanup complete.'
