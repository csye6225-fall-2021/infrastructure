output "vpc_id" {
  value = aws_vpc.vpc.id
}

output "aws_internet_gateway_id" {
  value = aws_internet_gateway.internet-gateway.id
}

output "aws_subnet_id" {
  value = { for k, v in aws_subnet.public-subnet : k => v.id }
}

output "public-route-table_id" {
  value = aws_route_table.public-route-table.id
}

