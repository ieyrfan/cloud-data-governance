# Create IAM Role for Lambda
data "aws_caller_identity" "current" {}

resource "aws_iam_role" "lambda_exec" {
  name = "${var.function_name}_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# Attach basic execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Add policy for DynamoDB and S3 read
resource "aws_iam_role_policy" "lambda_inline_policy" {
  name = "${var.function_name}_policy"
  role = aws_iam_role.lambda_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${var.source_bucket_arn}/*"]
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem"]
        Resource = [var.dynamodb_table_arn]
      },
      {
        Effect   = "Allow"
        Action   = ["comprehend:DetectPiiEntities"]
        Resource = ["*"]
      }
    ]
  })
}

# Package the Lambda code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/../../../src"
  output_path = "${path.module}/function.zip"
}

resource "aws_lambda_function" "classifier" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = var.function_name
  role             = aws_iam_role.lambda_exec.arn
  handler          = "handlers.s3_classifier.lambda_handler"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  runtime          = "python3.11"
  timeout          = 30
  memory_size      = 256

  environment {
    variables = {
      DYNAMODB_TABLE      = var.dynamodb_table_name
      LOCALSTACK_ENDPOINT = "http://host.docker.internal:4566" # Assuming running via localstack
      ENVIRONMENT         = var.environment
    }
  }
}

# Allow S3 to invoke Lambda
resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.classifier.function_name
  principal     = "s3.amazonaws.com"

  source_account = data.aws_caller_identity.current.account_id
  source_arn     = var.source_bucket_arn
}
