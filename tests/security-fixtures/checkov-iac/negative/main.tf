resource "aws_security_group" "fixture" {
  name        = "vibesec-negative"
  description = "Inert Checkov fixture; never applied"

  ingress {
    description = "Private SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
