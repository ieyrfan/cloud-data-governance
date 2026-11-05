output "table_name" {
  value = aws_dynamodb_table.classification_results.name
}

output "table_arn" {
  value = aws_dynamodb_table.classification_results.arn
}
