$ErrorActionPreference = 'Stop'
$TerraformDirectory = Join-Path $PSScriptRoot '../terraform/environments/dev'
Push-Location $TerraformDirectory
try {
    terraform init
    if ($LASTEXITCODE -ne 0) { throw 'Terraform initialization failed.' }
    terraform apply
    if ($LASTEXITCODE -ne 0) { throw 'Terraform apply failed.' }
}
finally {
    Pop-Location
}
