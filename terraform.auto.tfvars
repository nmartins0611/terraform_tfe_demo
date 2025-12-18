################################################################################
# terraform.auto.tfvars - Auto-loaded Variables File for VCS Workspace
################################################################################

# This file is automatically loaded by Terraform
# Commit this to Git - DO NOT include sensitive values here
# Use TFE workspace variables for sensitive data

# Vault Configuration
vault_kv_mount = "secret"

# AWS Configuration
aws_region    = "us-east-1"
instance_name = "rhel-webserver-01"
instance_type = "t3.medium"
rhel_version  = "9"
environment   = "production"

# Storage Configuration
root_volume_type = "gp3"
root_volume_size = 50

# Security Configuration
# IMPORTANT: Restrict these CIDR blocks to your actual network ranges
allowed_ssh_cidrs = ["0.0.0.0/0"]  # TODO: Change to your IP/network
allowed_web_cidrs = ["0.0.0.0/0"]

# SSH Key Configuration
create_key_pair = true
# ssh_public_key is set in TFE workspace variables (not here)

# Instance User Configuration
instance_username = "ansible"

# AAP Configuration
trigger_aap_workflow = true
# aap_server_url is set in TFE workspace variables
# aap_workflow_template_id is set in TFE workspace variables (must be numeric ID)
# aap_inventory_id is set in TFE workspace variables (must be numeric ID)
# aap_token is set in TFE workspace variables (sensitive)
# vault_addr is set in TFE workspace variables
# vault_token is set in TFE workspace variables (sensitive)
aap_insecure_tls = true  # Set to false if using valid TLS certificates
