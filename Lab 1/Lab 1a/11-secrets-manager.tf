# Secrets Manager
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret
# https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/secretsmanager_secret_version

# Explanation: Secrets Manager is bos’s locked holster—credentials go here, not in code.
resource "aws_secretsmanager_secret" "bos_db_secret01" {
  name = "${local.name_prefix}/rds/mysql"
  recovery_window_in_days = 0
}

# Explanation: Secret payload—students should align this structure with their app (and support rotation later).
resource "aws_secretsmanager_secret_version" "bos_db_secret_version01" {
  secret_id = aws_secretsmanager_secret.bos_db_secret01.id

  secret_string = jsonencode({
    username = var.db_username
    password = var.db_password
    host     = aws_db_instance.bos_rds01.address
    port     = aws_db_instance.bos_rds01.port
    dbname   = var.db_name
  })
}