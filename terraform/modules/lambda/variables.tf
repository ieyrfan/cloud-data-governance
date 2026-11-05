variable "function_name" {
  description = "Name of the Lambda function"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "dynamodb_table_name" {
  description = "DynamoDB table name to pass as env var"
  type        = string
}

variable "dynamodb_table_arn" {
  description = "ARN of the DynamoDB table the classifier can write"
  type        = string
}

variable "source_bucket_arn" {
  description = "ARN of the S3 bucket the classifier can read"
  type        = string
}
