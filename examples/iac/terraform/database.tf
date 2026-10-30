resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t4g.micro"
  allocated_storage   = 20
  storage_encrypted   = true
  publicly_accessible = true
  username            = "app"
  manage_master_user_password = true
}

resource "aws_ebs_encryption_by_default" "on" {
  enabled = true
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "eu-west-1a"
  size              = 50
}
