locals {
  environment     = "dev"
  raw_bucket_name = "data-lake-governance-${local.environment}"
}

module "dynamodb" {
  source      = "../../modules/dynamodb"
  table_name  = "data-governance-results-${local.environment}"
  environment = local.environment
}

module "classifier_lambda" {
  source              = "../../modules/lambda"
  function_name       = "data-classifier-${local.environment}"
  dynamodb_table_name = module.dynamodb.table_name
  dynamodb_table_arn  = module.dynamodb.table_arn
  source_bucket_arn   = "arn:aws:s3:::${local.raw_bucket_name}"
  environment         = local.environment
}

module "data_lake_s3" {
  source              = "../../modules/s3"
  bucket_name         = local.raw_bucket_name
  lambda_function_arn = module.classifier_lambda.function_arn
  environment         = local.environment
}

module "clean_data_lake_s3" {
  source      = "../../modules/s3"
  bucket_name = "data-lake-governance-${local.environment}-clean"
  environment = local.environment
}

module "kms_restricted" {
  source            = "../../modules/kms"
  environment       = local.environment
  sensitivity_level = "RESTRICTED"
  rotation_days     = 90
}

module "kms_confidential" {
  source            = "../../modules/kms"
  environment       = local.environment
  sensitivity_level = "CONFIDENTIAL"
  rotation_days     = 180
}
