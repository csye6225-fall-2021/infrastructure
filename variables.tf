variable "vpc_cider" {
  description = "VPC Cider Block"
  type        = string
}

variable "vpc_name" {
  description = "VPC Cider Block"
  type        = string
}
variable "subnet_cidrs" {
  type        = list(string)
  description = "Public Subnet Cider Blocks"
}

variable "subnet_az" {
  type        = list(string)
  description = "Public Subnet Availability Zones"
}

variable "subnet_names" {
  type        = list(string)
  description = "Public Subnet Name Tags"
}

variable "aws_profile" {
  type        = string
  description = ""
}


