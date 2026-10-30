variable "admin_cidr" {
  description = "Who may SSH to the bastion"
  type        = string
  default     = "10.20.0.0/16"
}

variable "partner_cidr" {
  description = "The partner's network, given at apply time"
  type        = string
}

resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
}

resource "aws_security_group" "web" {
  name   = "web"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_vpc_security_group_ingress_rule" "partner_ssh" {
  security_group_id = aws_security_group.bastion.id
  cidr_ipv4         = var.partner_cidr
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
}
