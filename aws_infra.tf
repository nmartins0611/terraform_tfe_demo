# ===================================
# Variables333333
# ===================================

# AWS Credentials (Optional - can use AWS CLI, environment vars, or dynamic credentials)
variable "aws_access_key" {
  description = "AWS Access Key ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_secret_key" {
  description = "AWS Secret Access Key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# EC2 Instance Configuration
variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "rhel_ami" {
  description = "RHEL AMI ID for the specified region"
  type        = string
  default     = "ami-0583d8c7a9c35822c"  # RHEL 9 in us-east-1
}

# SSH Key Configuration
variable "key_name" {
  description = "Name of the AWS key pair for SSH access"
  type        = string
}

variable "ssh_public_key" {
  description = "Public SSH key content (optional - only if creating new key pair)"
  type        = string
  default     = ""
}

variable "create_new_key_pair" {
  description = "Whether to create a new key pair or use existing"
  type        = bool
  default     = false
}

# Machine/Instance Credentials
variable "instance_username" {
  description = "Default username for RHEL instance"
  type        = string
  default     = "ec2-user"
}

# Security Configuration
variable "ssh_allowed_cidr" {
  description = "CIDR blocks allowed to SSH (leave as 0.0.0.0/0 for all, or restrict to your IP)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_name" {
  description = "Name tag for the EC2 instance"
  type        = string
  default     = "rhel-instance"
}

# Webhook/API Configuration
variable "webhook_url" {
  description = "URL of the webhook/API endpoint to notify"
  type        = string
  default     = "http://endpoint:5000/api/notify"
}

variable "webhook_enabled" {
  description = "Enable or disable webhook notifications"
  type        = bool
  default     = true
}

variable "api_token" {
  description = "API token for webhook authentication (if required)"
  type        = string
  default     = ""
  sensitive   = true
}

# ===================================
# Terraform & Provider Configuration
# ===================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region     = var.aws_region
  access_key = var.aws_access_key != "" ? var.aws_access_key : null
  secret_key = var.aws_secret_key != "" ? var.aws_secret_key : null
}

# ===================================
# SSH Key Pair (Optional Creation)
# ===================================

resource "aws_key_pair" "rhel_key" {
  count      = var.create_new_key_pair ? 1 : 0
  key_name   = var.key_name
  public_key = var.ssh_public_key

  tags = {
    Name = "${var.key_name}"
  }
}

# ===================================
# Security Group
# ===================================

resource "aws_security_group" "rhel_sg" {
  name        = "rhel-instance-sg"
  description = "Security group for RHEL instance with SSH, HTTP, and HTTPS"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidr
  }

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "rhel-security-group"
  }
}

# ===================================
# EC2 Instance
# ===================================

resource "aws_instance" "rhel" {
  ami           = var.rhel_ami
  instance_type = var.instance_type
  
  vpc_security_group_ids = [aws_security_group.rhel_sg.id]
  
  key_name = var.key_name

  tags = {
    Name = var.instance_name
  }

  # Send webhook notification after instance is created
  # provisioner "local-exec" {
  #   command = <<-EOT
  #     curl -X POST http://endpoint:5000/api/notify \
  #       -H "Content-Type: application/json" \
  #       -d '{
  #         "event": "instance_created",
  #         "instance_id": "${self.id}",
  #         "instance_ip": "${self.public_ip}",
  #         "instance_name": "${var.instance_name}",
  #         "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  #       }'
  #   EOT
  # }

  # Send webhook notification when instance is destroyed
  # provisioner "local-exec" {
  #   when    = destroy
  #   command = <<-EOT
  #     curl -X POST http://endpoint:5000/api/notify \
  #       -H "Content-Type: application/json" \
  #       -d '{
  #         "event": "instance_destroyed",
  #         "instance_id": "${self.id}",
  #         "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
  #       }'
  #   EOT
  #   on_failure = continue
  # }
}

# ===================================
# Outputs
# ===================================

output "instance_id" {
  description = "The ID of the EC2 instance"
  value       = aws_instance.rhel.id
}

output "instance_public_ip" {
  description = "Public IP address of the instance"
  value       = aws_instance.rhel.public_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the instance"
  value       = aws_instance.rhel.public_dns
}

output "ssh_connection_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i /path/to/${var.key_name}.pem ${var.instance_username}@${aws_instance.rhel.public_ip}"
}

output "instance_username" {
  description = "Default username for SSH connection"
  value       = var.instance_username
}

# ===================================
# Webhook Notification Resource
# ===================================

 resource "null_resource" "webhook_notification" {
   count = var.webhook_enabled ? 1 : 0

   depends_on = [aws_instance.rhel]

   # Trigger on instance changes
   triggers = {
     instance_id = aws_instance.rhel.id
     instance_ip = aws_instance.rhel.public_ip
   }

   # Send notification after instance is ready
   provisioner "local-exec" {
     environment = {
       API_TOKEN = var.api_token
     }
     command = <<-EOT
       curl -X POST ${var.webhook_url} \
         -H "Content-Type: application/json" \
         ${var.api_token != "" ? "-H \"Authorization: Bearer $API_TOKEN\"" : ""} \
         -d '{
           "event": "terraform_apply",
           "resource_type": "aws_instance",
           "instance_id": "${aws_instance.rhel.id}",
           "instance_ip": "${aws_instance.rhel.public_ip}",
           "instance_dns": "${aws_instance.rhel.public_dns}",
           "instance_name": "${var.instance_name}",
           "region": "${var.aws_region}",
           "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'"
         }'
    EOT
   }
 }
