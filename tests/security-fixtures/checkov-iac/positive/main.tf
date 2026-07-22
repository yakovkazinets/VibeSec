resource "aws_security_group" "fixture" {
  name        = "vibesec-positive"
  description = "Inert Checkov fixture; never applied"

  ingress {
    description = "Intentionally public SSH for CKV_AWS_24"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
