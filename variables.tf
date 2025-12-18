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
