variable "vpc_cider" {
  type        = string
  description = "CIDR Block for VPC"
}

variable "vpc_name" {
  type        = string
  description = "CIDR Block name for VPC"
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

variable "password" {
  type        = string
  description = "RDS Password"
}

variable "ec2_key" {
  type        = string
  description = "ec2 key pair for instances"
}

variable "aws_profile" {
  type        = string
  description = "AWS Profile"
}

variable "s3_domain" {
  type = string
}

variable "s3_name" {
  type = string
}

variable "aws_profile_name" {
  type = string
}


variable "domain_Name" {
  type = string
}

variable "region" {
  type = string
}

variable "dynamo_read_capacity" {
  type = number
}

variable "dynamo_write_capacity" {
  type = number
}
variable "dynamo_dbname" {
  type = string
}