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
