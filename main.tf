################################################################################
# main.tf - Main Terraform Configuration HELOTEST T
################################################################################

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
    ansible = {
      source  = "ansible/ansible"
      version = "~> 1.3.0"
    }
  }
}

################################################################################
# Vault Provider Configuration
################################################################################

provider "vault" {
  # Address and token configured via environment variables:
  # VAULT_ADDR and VAULT_TOKEN in TFE workspace
}

################################################################################
# Data Sources - AWS Static Credentials from Vault
################################################################################

data "vault_kv_secret_v2" "aws_creds" {
  mount = var.vault_kv_mount
  name  = "aws/credentials"
}

################################################################################
# AWS Provider Configuration using Vault Static Credentials
################################################################################

provider "aws" {
  region     = var.aws_region
  access_key = data.vault_kv_secret_v2.aws_creds.data["access_key"]
  secret_key = data.vault_kv_secret_v2.aws_creds.data["secret_key"]
}

################################################################################
# Random Password Generation
################################################################################

resource "random_password" "instance_password" {
  length  = 24
  special = true
  lower   = true
  upper   = true
  numeric = true
}

################################################################################
# Store Password in Vault
################################################################################

resource "vault_kv_secret_v2" "instance_credentials" {
  mount = var.vault_kv_mount
  name  = "rhel-instance-${var.instance_name}"
  
  data_json = jsonencode({
    username    = var.instance_username
    password    = random_password.instance_password.result
    instance_id = aws_instance.rhel.id
    public_ip   = aws_instance.rhel.public_ip
    private_ip  = aws_instance.rhel.private_ip
  })
}

################################################################################
# VPC and Networking
################################################################################

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

################################################################################
# Security Group
################################################################################

resource "aws_security_group" "rhel_sg" {
  name_prefix = "${var.instance_name}-sg-"
  description = "Security group for RHEL instance - SSH, HTTP, HTTPS"
  vpc_id      = data.aws_vpc.default.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.allowed_ssh_cidrs
    description = "SSH access"
  }

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
    description = "HTTP access"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.allowed_web_cidrs
    description = "HTTPS access"
  }

  # Outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name        = "${var.instance_name}-sg"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Find Latest RHEL AMI
################################################################################

data "aws_ami" "rhel" {
  most_recent = true
  owners      = ["309956199498"] # Red Hat's official AWS account

  filter {
    name   = "name"
    values = ["RHEL-${var.rhel_version}*"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

################################################################################
# EC2 Key Pair (optional - for initial access)
################################################################################

resource "aws_key_pair" "rhel_key" {
  count      = var.create_key_pair ? 1 : 0
  key_name   = "${var.instance_name}-key"
  public_key = var.ssh_public_key

  tags = {
    Name        = "${var.instance_name}-key"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

################################################################################
# User Data Script
################################################################################

locals {
  user_data = <<-EOF
    #!/bin/bash
    set -e
    
    # Log all output
    exec > >(tee /var/log/user-data.log)
    exec 2>&1
    
    echo "Starting user-data script at $(date)"
    
    # Set root password
    echo "root:${random_password.instance_password.result}" | chpasswd
    echo "Root password set successfully"
    
    # Create user if not root
    if [ "${var.instance_username}" != "root" ]; then
      # Check if user already exists
      if ! id -u ${var.instance_username} > /dev/null 2>&1; then
        useradd -m -s /bin/bash ${var.instance_username}
        echo "User ${var.instance_username} created"
      fi
      
      # Set password
      echo "${var.instance_username}:${random_password.instance_password.result}" | chpasswd
      echo "Password set for ${var.instance_username}"
      
      # Add to sudoers
      echo "${var.instance_username} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/${var.instance_username}
      chmod 0440 /etc/sudoers.d/${var.instance_username}
      echo "Sudo access granted to ${var.instance_username}"
    fi
    
    # Enable password authentication for SSH
    sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
    
    # Ensure password authentication is enabled
    if ! grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
      echo "PasswordAuthentication yes" >> /etc/ssh/sshd_config
    fi
    
    # Restart SSH
    systemctl restart sshd
    echo "SSH configured and restarted"
    
    # Update system (optional - can be commented out for faster deployment)
    # yum update -y
    
    echo "User-data script completed at $(date)"
  EOF
}

################################################################################
# EC2 Instance
################################################################################

resource "aws_instance" "rhel" {
  ami           = data.aws_ami.rhel.id
  instance_type = var.instance_type
  subnet_id     = data.aws_subnets.default.ids[0]
  
  key_name               = var.create_key_pair ? aws_key_pair.rhel_key[0].key_name : var.existing_key_name
  vpc_security_group_ids = [aws_security_group.rhel_sg.id]
  
  user_data                   = local.user_data
  user_data_replace_on_change = true

  root_block_device {
    volume_type = var.root_volume_type
    volume_size = var.root_volume_size
    encrypted   = true
    tags = {
      Name = "${var.instance_name}-root"
    }
  }

  tags = {
    Name        = var.instance_name
    Environment = var.environment
    ManagedBy   = "Terraform"
    Application = "WebServer"
  }

  # Wait for instance to be ready
  depends_on = [aws_security_group.rhel_sg]
}

################################################################################
# Ansible Provider Configuration for AAP
################################################################################

provider "ansible" {
  # No configuration needed - uses environment variables or resource-level config
}

################################################################################
# Wait for Instance to be Ready
################################################################################

resource "time_sleep" "wait_for_instance" {
  depends_on = [aws_instance.rhel]
  
  create_duration = "90s"  # Wait for user_data to complete
}

################################################################################
# Trigger AAP Workflow using Ansible Provider
################################################################################

resource "ansible_job_template_launch" "apache_install" {
  count = var.trigger_aap_workflow ? 1 : 0

  job_template_id = var.aap_workflow_template_id
  
  inventory_id = var.aap_inventory_id
  
  extra_vars = jsonencode({
    target_host     = aws_instance.rhel.public_ip
    vault_addr      = var.vault_addr
    vault_token     = var.vault_token
    vault_path      = "secret/data/rhel-instance-${var.instance_name}"
    instance_id     = aws_instance.rhel.id
    instance_name   = var.instance_name
    ansible_host    = aws_instance.rhel.public_ip
  })

  # AAP connection details
  controller_url   = var.aap_server_url
  controller_token = var.aap_token
  
  # Allow self-signed certificates
  insecure = var.aap_insecure_tls

  depends_on = [
    vault_kv_secret_v2.instance_credentials,
    time_sleep.wait_for_instance
  ]
}

################################################################################
# variables.tf - Variable Definitions
################################################################################

# Vault Variables
variable "vault_kv_mount" {
  description = "Vault KV v2 mount path where secrets are stored"
  type        = string
  default     = "secret"
}

# AWS Variables
variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "instance_name" {
  description = "Name for the EC2 instance (used in tags and Vault path)"
  type        = string
  default     = "rhel-webserver"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
  
  validation {
    condition     = can(regex("^t[2-3]\\.(nano|micro|small|medium|large|xlarge|2xlarge)$", var.instance_type))
    error_message = "Instance type must be a valid t2 or t3 instance type."
  }
}

variable "rhel_version" {
  description = "RHEL major version to deploy (8 or 9)"
  type        = string
  default     = "9"
  
  validation {
    condition     = contains(["8", "9"], var.rhel_version)
    error_message = "RHEL version must be either 8 or 9."
  }
}

variable "environment" {
  description = "Environment tag (dev, staging, production)"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

# Storage Variables
variable "root_volume_type" {
  description = "Root volume type (gp3, gp2, io1, io2)"
  type        = string
  default     = "gp3"
  
  validation {
    condition     = contains(["gp3", "gp2", "io1", "io2"], var.root_volume_type)
    error_message = "Volume type must be gp3, gp2, io1, or io2."
  }
}

variable "root_volume_size" {
  description = "Root volume size in GB"
  type        = number
  default     = 50
  
  validation {
    condition     = var.root_volume_size >= 10 && var.root_volume_size <= 1000
    error_message = "Volume size must be between 10 and 1000 GB."
  }
}

# Network Security Variables
variable "allowed_ssh_cidrs" {
  description = "List of CIDR blocks allowed to SSH to the instance"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_web_cidrs" {
  description = "List of CIDR blocks allowed to access web ports (80, 443)"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

# SSH Key Variables
variable "create_key_pair" {
  description = "Whether to create a new SSH key pair"
  type        = bool
  default     = true
}

variable "ssh_public_key" {
  description = "SSH public key content (required if create_key_pair is true)"
  type        = string
  default     = ""
}

variable "existing_key_name" {
  description = "Existing AWS key pair name (used if create_key_pair is false)"
  type        = string
  default     = null
}

# Instance Credentials Variables
variable "instance_username" {
  description = "Username for the instance (will be created with sudo access)"
  type        = string
  default     = "ansible"
  
  validation {
    condition     = can(regex("^[a-z][a-z0-9_-]*$", var.instance_username))
    error_message = "Username must start with a letter and contain only lowercase letters, numbers, hyphens, and underscores."
  }
}

# AAP Variables
variable "trigger_aap_workflow" {
  description = "Whether to trigger AAP workflow after instance creation"
  type        = bool
  default     = true
}

variable "aap_server_url" {
  description = "Ansible Automation Platform server URL (e.g., https://aap.example.com)"
  type        = string
}

variable "aap_token" {
  description = "AAP authentication token (Bearer token)"
  type        = string
  sensitive   = true
}

variable "aap_workflow_template_id" {
  description = "AAP Workflow Job Template ID (numeric ID, not name)"
  type        = string
  default     = "7"
  
  validation {
    condition     = can(regex("^[0-9]+$", var.aap_workflow_template_id))
    error_message = "Workflow template ID must be numeric (e.g., '7', not 'Apache Installation Workflow')."
  }
}

variable "aap_inventory_id" {
  description = "AAP Inventory ID to use for the job (numeric ID)"
  type        = string
  default     = "1"
  
  validation {
    condition     = can(regex("^[0-9]+$", var.aap_inventory_id))
    error_message = "Inventory ID must be numeric (e.g., '1')."
  }
}

variable "aap_insecure_tls" {
  description = "Allow insecure TLS connections to AAP (self-signed certificates)"
  type        = bool
  default     = true
}

variable "vault_addr" {
  description = "Vault address for AAP to access (e.g., https://vault.example.com:8200)"
  type        = string
}

variable "vault_token" {
  description = "Vault token for AAP to access instance credentials"
  type        = string
  sensitive   = true
}

################################################################################
# outputs.tf - Output Definitions
################################################################################

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.rhel.id
}

output "instance_public_ip" {
  description = "Public IP address of the instance"
  value       = aws_instance.rhel.public_ip
}

output "instance_private_ip" {
  description = "Private IP address of the instance"
  value       = aws_instance.rhel.private_ip
}

output "instance_public_dns" {
  description = "Public DNS name of the instance"
  value       = aws_instance.rhel.public_dns
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.rhel_sg.id
}

output "vault_secret_path" {
  description = "Path to instance credentials in Vault"
  value       = "${var.vault_kv_mount}/rhel-instance-${var.instance_name}"
}

output "ssh_connection" {
  description = "SSH connection string"
  value       = "ssh ${var.instance_username}@${aws_instance.rhel.public_ip}"
}

output "web_urls" {
  description = "Web access URLs"
  value = {
    http  = "http://${aws_instance.rhel.public_ip}"
    https = "https://${aws_instance.rhel.public_ip}"
  }
}

output "ami_id" {
  description = "AMI ID used for the instance"
  value       = data.aws_ami.rhel.id
}

output "ami_name" {
  description = "AMI name used for the instance"
  value       = data.aws_ami.rhel.name
}

output "instance_username" {
  description = "Username for SSH access"
  value       = var.instance_username
}

output "vault_credentials_command" {
  description = "Command to retrieve credentials from Vault"
  value       = "vault kv get ${var.vault_kv_mount}/rhel-instance-${var.instance_name}"
}
