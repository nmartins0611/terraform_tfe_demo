# ===================================
# TERRAFORM WITH OFFICIAL AAP PROVIDER
# ===================================

# Variables
variable "vault_address" {
  description = "URL of the Vault server"
  type        = string
  default     = "https://vault.example.com:8200"
}

variable "vault_role_id" {
  description = "Vault AppRole Role ID"
  type        = string
  sensitive   = true
}

variable "vault_secret_id" {
  description = "Vault AppRole Secret ID"
  type        = string
  sensitive   = true
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "rhel_ami" {
  type    = string
  default = "ami-0583d8c7a9c35822c"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "instance_name" {
  type    = string
  default = "rhel-instance"
}

# AAP Configuration
variable "aap_host" {
  description = "Ansible Automation Platform URL"
  type        = string
  default     = "https://ansible-tower.example.com"
}

variable "aap_username" {
  description = "AAP Username (optional if using token)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "aap_password" {
  description = "AAP Password (optional if using token)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "aap_token" {
  description = "AAP API Token (recommended over username/password)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "aap_organization_id" {
  description = "AAP Organization ID"
  type        = number
  default     = 1
}

variable "aap_job_template_id" {
  description = "AAP Job Template ID to trigger"
  type        = number
}

variable "aap_workflow_template_id" {
  description = "AAP Workflow Template ID (if using workflow instead of job template)"
  type        = number
  default     = null
}

variable "ssh_allowed_cidr" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}

# ===================================
# Providers Configuration
# ===================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
    aap = {
      source  = "ansible/aap"
      version = "~> 1.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

# Vault Provider
provider "vault" {
  address = var.vault_address
  
  auth_login {
    path = "auth/approle/login"
    parameters = {
      role_id   = var.vault_role_id
      secret_id = var.vault_secret_id
    }
  }
}

# Fetch secrets from Vault
data "vault_kv_secret_v2" "aws_creds" {
  mount = "secret"
  name  = "aws/credentials"
}

data "vault_kv_secret_v2" "aap_token" {
  mount = "secret"
  name  = "ansible/tower_token"
}

# AWS Provider
provider "aws" {
  region     = var.aws_region
  access_key = data.vault_kv_secret_v2.aws_creds.data["access_key"]
  secret_key = data.vault_kv_secret_v2.aws_creds.data["secret_key"]
}

# AAP Provider
provider "aap" {
  host                 = var.aap_host
  username             = var.aap_username != "" ? var.aap_username : null
  password             = var.aap_password != "" ? var.aap_password : null
  token                = var.aap_token != "" ? var.aap_token : data.vault_kv_secret_v2.aap_token.data["token"]
  insecure_skip_verify = false  # Set to true for self-signed certificates in dev
}

# ===================================
# Generate Instance Password
# ===================================

resource "random_password" "instance_password" {
  length  = 16
  special = true
}

# Store password in Vault
resource "vault_kv_secret_v2" "instance_password" {
  mount = "secret"
  name  = "instances/${aws_instance.rhel.id}/credentials"
  
  data_json = jsonencode({
    username = "ec2-user"
    password = random_password.instance_password.result
    hostname = aws_instance.rhel.public_ip
    instance_id = aws_instance.rhel.id
  })
}

# ===================================
# Security Group
# ===================================

resource "aws_security_group" "rhel_sg" {
  name        = "${var.instance_name}-sg"
  description = "Security group for RHEL instance"

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
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.instance_name}-sg"
  }
}

# ===================================
# EC2 Instance
# ===================================

resource "aws_instance" "rhel" {
  ami                    = var.rhel_ami
  instance_type          = var.instance_type
  vpc_security_group_ids = [aws_security_group.rhel_sg.id]
  key_name               = var.key_name

  # Set password for ec2-user via user_data
  user_data = <<-EOF
              #!/bin/bash
              echo "ec2-user:${random_password.instance_password.result}" | chpasswd
              sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
              systemctl restart sshd
              EOF

  tags = {
    Name        = var.instance_name
    Environment = "terraform-managed"
    ManagedBy   = "terraform"
  }
}

# ===================================
# AAP Integration - Create Inventory
# ===================================

# Create a dedicated inventory in AAP for this infrastructure
resource "aap_inventory" "terraform_inventory" {
  name         = "Terraform-Managed-${var.instance_name}"
  description  = "Dynamically managed inventory from Terraform"
  organization = var.aap_organization_id
  
  variables = jsonencode({
    terraform_workspace = terraform.workspace
    created_at         = timestamp()
  })
}

# Add the EC2 instance to AAP inventory
resource "aap_host" "rhel_host" {
  name         = aws_instance.rhel.public_ip
  inventory_id = aap_inventory.terraform_inventory.id
  
  variables = jsonencode({
    ansible_host     = aws_instance.rhel.public_ip
    instance_id      = aws_instance.rhel.id
    instance_name    = var.instance_name
    vault_path       = "secret/data/instances/${aws_instance.rhel.id}/credentials"
    aws_region       = var.aws_region
    private_ip       = aws_instance.rhel.private_ip
  })

  depends_on = [vault_kv_secret_v2.instance_password]
}

# Optional: Create a group for organizing hosts
resource "aap_group" "rhel_group" {
  name         = "rhel-servers"
  inventory_id = aap_inventory.terraform_inventory.id
  
  variables = jsonencode({
    os_family = "RedHat"
    managed_by = "terraform"
  })
}

# ===================================
# AAP Integration - Launch Job Template
# ===================================

# Launch an AAP Job Template to configure the instance
resource "aap_job" "configure_instance" {
  job_template_id = var.aap_job_template_id
  inventory_id    = aap_inventory.terraform_inventory.id
  
  # Pass extra variables to the Ansible playbook
  extra_vars = jsonencode({
    target_host    = aws_instance.rhel.public_ip
    instance_id    = aws_instance.rhel.id
    vault_path     = "secret/data/instances/${aws_instance.rhel.id}/credentials"
    instance_name  = var.instance_name
  })

  depends_on = [
    aap_host.rhel_host,
    vault_kv_secret_v2.instance_password
  ]
}

# ===================================
# ALTERNATIVE: Launch Workflow Template
# ===================================

# If you want to use a workflow template instead of a job template,
# use this resource (requires AAP provider >= 1.1.0)

# resource "aap_workflow_job" "configure_workflow" {
#   workflow_template_id = var.aap_workflow_template_id
#   inventory_id         = aap_inventory.terraform_inventory.id
#   
#   extra_vars = jsonencode({
#     target_host   = aws_instance.rhel.public_ip
#     instance_id   = aws_instance.rhel.id
#     vault_path    = "secret/data/instances/${aws_instance.rhel.id}/credentials"
#   })
#
#   depends_on = [
#     aap_host.rhel_host,
#     vault_kv_secret_v2.instance_password
#   ]
# }

# ===================================
# Outputs
# ===================================

output "instance_id" {
  description = "EC2 Instance ID"
  value       = aws_instance.rhel.id
}

output "instance_public_ip" {
  description = "Public IP address"
  value       = aws_instance.rhel.public_ip
}

output "instance_private_ip" {
  description = "Private IP address"
  value       = aws_instance.rhel.private_ip
}

output "vault_secret_path" {
  description = "Vault path where credentials are stored"
  value       = "secret/instances/${aws_instance.rhel.id}/credentials"
}

output "aap_inventory_id" {
  description = "AAP Inventory ID"
  value       = aap_inventory.terraform_inventory.id
}

output "aap_host_id" {
  description = "AAP Host ID"
  value       = aap_host.rhel_host.id
}

output "aap_job_id" {
  description = "AAP Job ID that was launched"
  value       = aap_job.configure_instance.id
}

output "aap_job_status" {
  description = "AAP Job execution status"
  value       = aap_job.configure_instance.status
}

output "ssh_connection_command" {
  description = "SSH command to connect"
  value       = "ssh -i /path/to/${var.key_name}.pem ec2-user@${aws_instance.rhel.public_ip}"
}
