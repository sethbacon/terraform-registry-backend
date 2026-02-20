terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Uncomment for remote state:
  # backend "s3" {
  #   bucket = "my-terraform-state"
  #   key    = "terraform-registry/terraform.tfstate"
  #   region = "us-east-1"
  # }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project     = "terraform-registry"
      ManagedBy   = "terraform"
      Environment = var.environment
    }
  }
}

# ---------------------------------------------------------------------------
# Data Sources
# ---------------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# VPC
# ---------------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "${var.name}-vpc" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-igw" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "${var.name}-public-${count.index + 1}" }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = { Name = "${var.name}-private-${count.index + 1}" }
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "${var.name}-nat-eip" }
}

resource "aws_nat_gateway" "main" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id
  tags          = { Name = "${var.name}-nat" }

  depends_on = [aws_internet_gateway.main]
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-public-rt" }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${var.name}-private-rt" }

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main.id
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ---------------------------------------------------------------------------
# Security Groups
# ---------------------------------------------------------------------------
resource "aws_security_group" "alb" {
  name_prefix = "${var.name}-alb-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "ecs" {
  name_prefix = "${var.name}-ecs-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 0
    to_port         = 65535
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }

  ingress {
    from_port = 0
    to_port   = 65535
    protocol  = "tcp"
    self      = true
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
}

resource "aws_security_group" "rds" {
  name_prefix = "${var.name}-rds-"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs.id]
  }

  lifecycle { create_before_destroy = true }
}

# ---------------------------------------------------------------------------
# ECR Repositories
# ---------------------------------------------------------------------------
resource "aws_ecr_repository" "backend" {
  name                 = "${var.name}-backend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_repository" "frontend" {
  name                 = "${var.name}-frontend"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }
}

# ---------------------------------------------------------------------------
# Secrets Manager
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${var.name}/database-password"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = var.database_password
}

resource "aws_secretsmanager_secret" "jwt_secret" {
  name                    = "${var.name}/jwt-secret"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "jwt_secret" {
  secret_id     = aws_secretsmanager_secret.jwt_secret.id
  secret_string = var.jwt_secret
}

resource "aws_secretsmanager_secret" "encryption_key" {
  name                    = "${var.name}/encryption-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "encryption_key" {
  secret_id     = aws_secretsmanager_secret.encryption_key.id
  secret_string = var.encryption_key
}

# ---------------------------------------------------------------------------
# RDS PostgreSQL
# ---------------------------------------------------------------------------
resource "aws_db_subnet_group" "main" {
  name       = "${var.name}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_rds_cluster" "main" {
  cluster_identifier     = "${var.name}-db"
  engine                 = "aurora-postgresql"
  engine_version         = "16.1"
  database_name          = "terraform_registry"
  master_username        = "registry"
  master_password        = var.database_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  storage_encrypted      = true
  skip_final_snapshot    = var.environment != "production"

  final_snapshot_identifier = var.environment == "production" ? "${var.name}-final-snapshot" : null
}

resource "aws_rds_cluster_instance" "main" {
  count              = var.db_instance_count
  identifier         = "${var.name}-db-${count.index}"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = var.db_instance_class
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version
}

# ---------------------------------------------------------------------------
# S3 Storage Bucket
# ---------------------------------------------------------------------------
resource "aws_s3_bucket" "storage" {
  bucket = "${var.name}-storage-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "storage" {
  bucket = aws_s3_bucket.storage.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "storage" {
  bucket = aws_s3_bucket.storage.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "storage" {
  bucket                  = aws_s3_bucket.storage.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# Storage Configuration Locals
# ---------------------------------------------------------------------------
locals {
  storage_env = concat(
    [{ name = "TFR_STORAGE_DEFAULT_BACKEND", value = var.storage_backend }],

    # S3 config (native default)
    var.storage_backend == "s3" ? [
      { name = "TFR_STORAGE_S3_BUCKET", value = aws_s3_bucket.storage.id },
      { name = "TFR_STORAGE_S3_REGION", value = var.region },
      { name = "TFR_STORAGE_S3_AUTH_METHOD", value = var.storage_s3_auth_method },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_endpoint != "" ? [
      { name = "TFR_STORAGE_S3_ENDPOINT", value = var.storage_s3_endpoint },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_role_arn != "" ? [
      { name = "TFR_STORAGE_S3_ROLE_ARN", value = var.storage_s3_role_arn },
      { name = "TFR_STORAGE_S3_ROLE_SESSION_NAME", value = var.storage_s3_role_session_name },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_external_id != "" ? [
      { name = "TFR_STORAGE_S3_EXTERNAL_ID", value = var.storage_s3_external_id },
    ] : [],
    var.storage_backend == "s3" && var.storage_s3_web_identity_token_file != "" ? [
      { name = "TFR_STORAGE_S3_WEB_IDENTITY_TOKEN_FILE", value = var.storage_s3_web_identity_token_file },
    ] : [],

    # Azure config
    var.storage_backend == "azure" ? [
      { name = "TFR_STORAGE_AZURE_ACCOUNT_NAME", value = var.storage_azure_account_name },
      { name = "TFR_STORAGE_AZURE_CONTAINER_NAME", value = var.storage_azure_container_name },
    ] : [],
    var.storage_backend == "azure" && var.storage_azure_cdn_url != "" ? [
      { name = "TFR_STORAGE_AZURE_CDN_URL", value = var.storage_azure_cdn_url },
    ] : [],

    # GCS config
    var.storage_backend == "gcs" ? [
      { name = "TFR_STORAGE_GCS_BUCKET", value = var.storage_gcs_bucket },
      { name = "TFR_STORAGE_GCS_PROJECT_ID", value = var.storage_gcs_project_id },
      { name = "TFR_STORAGE_GCS_AUTH_METHOD", value = var.storage_gcs_auth_method },
    ] : [],

    # Local config
    var.storage_backend == "local" ? [
      { name = "TFR_STORAGE_LOCAL_BASE_PATH", value = var.storage_local_base_path },
      { name = "TFR_STORAGE_LOCAL_SERVE_DIRECTLY", value = "true" },
    ] : [],
  )

  storage_secrets = concat(
    var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? [
      { name = "TFR_STORAGE_S3_ACCESS_KEY_ID", valueFrom = aws_secretsmanager_secret.s3_access_key[0].arn },
      { name = "TFR_STORAGE_S3_SECRET_ACCESS_KEY", valueFrom = aws_secretsmanager_secret.s3_secret_key[0].arn },
    ] : [],
    var.storage_backend == "azure" ? [
      { name = "TFR_STORAGE_AZURE_ACCOUNT_KEY", valueFrom = aws_secretsmanager_secret.azure_account_key[0].arn },
    ] : [],
    var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? [
      { name = "TFR_STORAGE_GCS_CREDENTIALS_JSON", valueFrom = aws_secretsmanager_secret.gcs_credentials[0].arn },
    ] : [],
  )

  storage_secret_arns = concat(
    var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? [
      aws_secretsmanager_secret.s3_access_key[0].arn,
      aws_secretsmanager_secret.s3_secret_key[0].arn,
    ] : [],
    var.storage_backend == "azure" ? [
      aws_secretsmanager_secret.azure_account_key[0].arn,
    ] : [],
    var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? [
      aws_secretsmanager_secret.gcs_credentials[0].arn,
    ] : [],
  )
}

# ---------------------------------------------------------------------------
# Conditional Storage Secrets
# ---------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "s3_access_key" {
  count                   = var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? 1 : 0
  name                    = "${var.name}/s3-access-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "s3_access_key" {
  count         = var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.s3_access_key[0].id
  secret_string = var.storage_s3_access_key_id
}

resource "aws_secretsmanager_secret" "s3_secret_key" {
  count                   = var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? 1 : 0
  name                    = "${var.name}/s3-secret-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "s3_secret_key" {
  count         = var.storage_backend == "s3" && var.storage_s3_auth_method == "static" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.s3_secret_key[0].id
  secret_string = var.storage_s3_secret_access_key
}

resource "aws_secretsmanager_secret" "azure_account_key" {
  count                   = var.storage_backend == "azure" ? 1 : 0
  name                    = "${var.name}/azure-account-key"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "azure_account_key" {
  count         = var.storage_backend == "azure" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.azure_account_key[0].id
  secret_string = var.storage_azure_account_key
}

resource "aws_secretsmanager_secret" "gcs_credentials" {
  count                   = var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? 1 : 0
  name                    = "${var.name}/gcs-credentials"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "gcs_credentials" {
  count         = var.storage_backend == "gcs" && var.storage_gcs_credentials_json != "" ? 1 : 0
  secret_id     = aws_secretsmanager_secret.gcs_credentials[0].id
  secret_string = var.storage_gcs_credentials_json
}

# ---------------------------------------------------------------------------
# CloudWatch Log Groups
# ---------------------------------------------------------------------------
resource "aws_cloudwatch_log_group" "backend" {
  name              = "/ecs/${var.name}-backend"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "frontend" {
  name              = "/ecs/${var.name}-frontend"
  retention_in_days = 30
}

# ---------------------------------------------------------------------------
# IAM Roles
# ---------------------------------------------------------------------------
resource "aws_iam_role" "execution" {
  name = "${var.name}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  name = "secrets-access"
  role = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["secretsmanager:GetSecretValue"]
      Resource = concat(
        [
          aws_secretsmanager_secret.db_password.arn,
          aws_secretsmanager_secret.jwt_secret.arn,
          aws_secretsmanager_secret.encryption_key.arn,
        ],
        local.storage_secret_arns,
      )
    }]
  })
}

resource "aws_iam_role" "task" {
  name = "${var.name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "task_s3" {
  name = "s3-storage"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.storage.arn,
        "${aws_s3_bucket.storage.arn}/*",
      ]
    }]
  })
}

# ---------------------------------------------------------------------------
# Application Load Balancer
# ---------------------------------------------------------------------------
resource "aws_lb" "main" {
  name               = var.name
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_lb_target_group" "frontend" {
  name        = "${var.name}-frontend"
  port        = 80
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = var.certificate_arn != "" ? "redirect" : "forward"
    target_group_arn = var.certificate_arn != "" ? null : aws_lb_target_group.frontend.arn

    dynamic "redirect" {
      for_each = var.certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }
  }
}

resource "aws_lb_listener" "https" {
  count             = var.certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.frontend.arn
  }
}

# ---------------------------------------------------------------------------
# ECS Cluster
# ---------------------------------------------------------------------------
resource "aws_ecs_cluster" "main" {
  name = var.name

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ---------------------------------------------------------------------------
# ECS Task Definitions
# ---------------------------------------------------------------------------
resource "aws_ecs_task_definition" "backend" {
  family                   = "${var.name}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 512
  memory                   = 1024
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name      = "backend"
    image     = "${aws_ecr_repository.backend.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [
      { containerPort = 8080 },
      { containerPort = 9090 },
    ]

    environment = concat([
      { name = "TFR_SERVER_HOST", value = "0.0.0.0" },
      { name = "TFR_SERVER_PORT", value = "8080" },
      { name = "TFR_SERVER_BASE_URL", value = var.domain != "" ? "https://${var.domain}" : "http://${aws_lb.main.dns_name}" },
      { name = "TFR_DATABASE_HOST", value = aws_rds_cluster.main.endpoint },
      { name = "TFR_DATABASE_PORT", value = "5432" },
      { name = "TFR_DATABASE_NAME", value = "terraform_registry" },
      { name = "TFR_DATABASE_USER", value = "registry" },
      { name = "TFR_DATABASE_SSL_MODE", value = "require" },
      { name = "TFR_SECURITY_TLS_ENABLED", value = "false" },
      { name = "TFR_AUTH_API_KEYS_ENABLED", value = "true" },
      { name = "TFR_LOGGING_LEVEL", value = "info" },
      { name = "TFR_LOGGING_FORMAT", value = "json" },
      { name = "TFR_TELEMETRY_ENABLED", value = "true" },
      { name = "TFR_TELEMETRY_METRICS_ENABLED", value = "true" },
      { name = "TFR_TELEMETRY_METRICS_PROMETHEUS_PORT", value = "9090" },
      { name = "DEV_MODE", value = "false" },
    ], local.storage_env)

    secrets = concat([
      { name = "TFR_DATABASE_PASSWORD", valueFrom = aws_secretsmanager_secret.db_password.arn },
      { name = "TFR_JWT_SECRET", valueFrom = aws_secretsmanager_secret.jwt_secret.arn },
      { name = "ENCRYPTION_KEY", valueFrom = aws_secretsmanager_secret.encryption_key.arn },
    ], local.storage_secrets)

    healthCheck = {
      command     = ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 10
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.backend.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "backend"
      }
    }
  }])
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${var.name}-frontend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = 256
  memory                   = 512
  execution_role_arn       = aws_iam_role.execution.arn

  container_definitions = jsonencode([{
    name      = "frontend"
    image     = "${aws_ecr_repository.frontend.repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{ containerPort = 80 }]

    healthCheck = {
      command     = ["CMD-SHELL", "wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1"]
      interval    = 30
      timeout     = 3
      retries     = 3
      startPeriod = 5
    }

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.frontend.name
        "awslogs-region"        = var.region
        "awslogs-stream-prefix" = "frontend"
      }
    }
  }])
}

# ---------------------------------------------------------------------------
# ECS Services
# ---------------------------------------------------------------------------
resource "aws_ecs_service" "backend" {
  name            = "${var.name}-backend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = var.backend_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200
}

resource "aws_ecs_service" "frontend" {
  name            = "${var.name}-frontend"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = var.frontend_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.ecs.id]
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.frontend.arn
    container_name   = "frontend"
    container_port   = 80
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  depends_on = [aws_lb_listener.http]
}
