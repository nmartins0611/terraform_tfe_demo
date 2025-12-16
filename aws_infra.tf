terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"  # Change to your preferred region
}

# Security Group
resource "aws_security_group" "rhel_sg" {
  name        = "rhel-instance-sg"
  description = "Security group for RHEL instance with SSH, HTTP, and HTTPS"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Consider restricting to your IP
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

# EC2 Instance
resource "aws_instance" "rhel" {
  ami           = "ami-0583d8c7a9c35822c"  # RHEL 9 in us-east-1 - Update for your region
  instance_type = "t3.micro"
  
  vpc_security_group_ids = [aws_security_group.rhel_sg.id]
  
  key_name = "your-key-pair"  # Replace with your SSH key pair name

  tags = {
    Name = "rhel-instance"
  }
}

# Outputs
output "instance_id" {
  value = aws_instance.rhel.id
}

output "instance_public_ip" {
  value = aws_instance.rhel.public_ip
}

output "instance_public_dns" {
  value = aws_instance.rhel.public_dns
}
