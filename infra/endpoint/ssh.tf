resource "aws_key_pair" "measurement" {
  key_name   = "icpr-measurement"
  public_key = file(pathexpand(var.ssh_public_key_path))

  tags = merge(local.common_tags, {
    Name = "icpr-measurement"
  })
}
