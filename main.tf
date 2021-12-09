locals {
  //vpc options
  enable_dns_support               = true
  enable_dns_hostnames             = true
  enable_classiclink_dns_support   = true
  assign_generated_ipv6_cidr_block = false
}

resource "aws_vpc" "vpc_01" {
  cidr_block                       = var.vpc_cider
  instance_tenancy                 = "default"
  enable_dns_support               = local.enable_dns_support
  enable_dns_hostnames             = local.enable_dns_hostnames
  enable_classiclink_dns_support   = local.enable_classiclink_dns_support
  assign_generated_ipv6_cidr_block = local.assign_generated_ipv6_cidr_block

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "vpc_01_subnet" {
  depends_on              = [aws_vpc.vpc_01]
  count                   = length(var.subnet_cidrs)
  vpc_id                  = aws_vpc.vpc_01.id
  cidr_block              = var.subnet_cidrs[count.index]
  availability_zone       = var.subnet_az[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = var.subnet_names[count.index]
  }
}

resource "aws_internet_gateway" "vpc_01_internet-gateway" {
  depends_on = [aws_vpc.vpc_01]
  vpc_id     = aws_vpc.vpc_01.id

  tags = {
    Name = "Internet gateway for vpc_01"
  }
}

resource "aws_route_table" "vpc_01_route-table" {
  depends_on = [aws_vpc.vpc_01, aws_internet_gateway.vpc_01_internet-gateway]
  vpc_id     = aws_vpc.vpc_01.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.vpc_01_internet-gateway.id
  }

  tags = {
    Name = "vpc_01 Route Table"
  }
}

resource "aws_route_table_association" "vpc_01_subnet-route-table-association" {
  count          = length(var.subnet_cidrs)
  subnet_id      = aws_subnet.vpc_01_subnet[count.index].id
  route_table_id = aws_route_table.vpc_01_route-table.id
}

data "aws_ami" "csye_6225_custom_ami" {
  most_recent = true

  //change to using variables
  owners = ["570209734344", "484705939173"]

  filter {
    name   = "name"
    values = ["csye6225_fall_2021_*"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

resource "aws_security_group" "application" {
  name        = "application"
  description = "Security group for EC2"
  vpc_id      = aws_vpc.vpc_01.id

  ingress = [
    {
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      description      = "TLS from VPC"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 22
      to_port          = 22
      protocol         = "tcp"
      description      = "SSH from VPC"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      description      = "HTTP from VPC"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    }
  ]
  egress = [
    {
      description      = "HTTP"
      from_port        = 80
      to_port          = 80
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "HTTPS"
      from_port        = 443
      to_port          = 443
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
    {
      description      = "SQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
      security_groups  = []
      self             = false
    },
  ]
  tags = {
    Name = "application"
  }
}

resource "aws_security_group" "database" {

  depends_on  = [aws_vpc.vpc_01, aws_security_group.application]
  name        = "database"
  description = "Security group for RDS-MYSQL"
  vpc_id      = aws_vpc.vpc_01.id

  ingress = [
    {
      description      = "MYSQL"
      from_port        = 3306
      to_port          = 3306
      protocol         = "tcp"
      cidr_blocks      = [aws_vpc.vpc_01.cidr_block]
      security_groups  = [aws_security_group.application.id]
      self             = false
      ipv6_cidr_blocks = []
      prefix_list_ids  = []
    }
  ]
  tags = {
    Name = "database"
  }
}

#db_subnet_group
resource "aws_db_subnet_group" "rds-subnet" {
  name       = "rds-subnet"
  subnet_ids = [aws_subnet.vpc_01_subnet[0].id, aws_subnet.vpc_01_subnet[1].id, aws_subnet.vpc_01_subnet[2].id]

  tags = {
    Name = "rds-subnet"
  }
}

#db parameter group
resource "aws_db_parameter_group" "rds-pg" {
  name   = "rds-pg"
  family = "mysql5.7"
  parameter {
    name = "performance_schema"
    value = 1
    apply_method = "pending-reboot"
  }
}

resource "aws_kms_key" "rdsKey" {
  description              = "Custom Managed Key for EBS"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${local.aws_user_account_id}:root",
                    "arn:aws:iam::${local.aws_user_account_id}:user/prod"
                ]
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow service-linked role use of the customer managed key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": "kms:CreateGrant",
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        }
    ]
}
EOF
}

#db instance
resource "aws_db_instance" "csye6225" {

  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  name                   = "csye6225"
  username               = "csye6225"
  password               = var.password
  db_subnet_group_name   = aws_db_subnet_group.rds-subnet.name
  vpc_security_group_ids = [aws_security_group.database.id]

  multi_az                  = false
  identifier                = "csye6225"
  publicly_accessible       = false
  allocated_storage         = 10
  apply_immediately         = true
  backup_retention_period   = 5
  final_snapshot_identifier = true
  skip_final_snapshot       = true
  availability_zone         = "us-east-1a"
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.rdsKey.arn
  parameter_group_name      = aws_db_parameter_group.rds-pg.name
}

resource "aws_s3_bucket" "s3" {
  bucket        = "${var.s3_name}.${var.aws_profile}.${var.s3_domain}"
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "long-term"
    enabled = true

    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
}

data "template_file" "config_data" {
  template = <<-EOF
		#! /bin/bash
        cd home/ubuntu
        mkdir server
        cd server
        echo "{\"db_host\":\"${aws_db_instance.csye6225.endpoint}\",
        \"db_user\":\"csye6225\",\"db_password\":\"${var.password}\",
        \"default_database\":\"csye6225\",\"db_port\":3306,
        \"bucketName\":\"${aws_s3_bucket.s3.bucket}\",
        \"replicaDb\":\"${aws_db_instance.csye6225.endpoint}"\",
        \"SNS_TOPIC_ARN\":\"${aws_sns_topic.sns_email.arn}\"}" > config.json
        cd ..
        sudo chmod -R 777 server
    EOF
}

resource "aws_iam_role" "ec2_s3_access_role" {
  name = "EC2-CSYE6225"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
}

resource "aws_iam_policy" "policy" {
  name        = "WebAppS3"
  description = "ec2 will be able to talk to s3 buckets"
  policy      = <<-EOF
    {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
              "s3:ListAllMyBuckets", 
              "s3:GetBucketLocation",
              "s3:GetObject",
              "s3:PutObject",
              "s3:DeleteObject"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:s3:::${aws_s3_bucket.s3.id}",
                "arn:aws:s3:::${aws_s3_bucket.s3.id}/*"
            ]
        }
    ]
    }
    EOF

}

resource "aws_iam_role_policy_attachment" "test-attach" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = "s3_profile_3"
  role = aws_iam_role.ec2_s3_access_role.name
}

resource "aws_kms_key" "key" {
  description              = "Custom Managed Key for EBS"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Id": "key-default-1",
    "Statement": [
        {
            "Sid": "Enable IAM User Permissions",
            "Effect": "Allow",
            "Principal": {
                "AWS": [
                    "arn:aws:iam::${local.aws_user_account_id}:root",
                    "arn:aws:iam::${local.aws_user_account_id}:user/prod"
                ]
            },
            "Action": "kms:*",
            "Resource": "*"
        },
        {
            "Sid": "Allow service-linked role use of the customer managed key",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:DescribeKey"
            ],
            "Resource": "*"
        },
        {
            "Sid": "Allow attachment of persistent resources",
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            },
            "Action": "kms:CreateGrant",
            "Resource": "*",
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        }
    ]
}
EOF
}

resource "aws_launch_template" "asg_launch_template" {
  depends_on = [aws_s3_bucket.s3, aws_db_instance.csye6225]
  name       = "asg_launch_temp"
  iam_instance_profile {
    name = aws_iam_instance_profile.s3_profile.name
  }
  key_name               = var.ec2_key
  image_id               = data.aws_ami.csye_6225_custom_ami.id
  instance_type          = "t2.micro"
  vpc_security_group_ids = ["${aws_security_group.application.id}"]
  user_data              = base64encode("${data.template_file.config_data.rendered}")
  block_device_mappings {
    device_name = "/dev/sda1"

    ebs {
      volume_size           = 25
      volume_type           = "gp2"
      delete_on_termination = true
      encrypted             = true
      kms_key_id            = aws_kms_key.key.arn
    }
  }
}

# CodeDeploy-EC2-S3 policy allows EC2 instances to read data from S3 buckets. This policy is required for EC2 instances to download latest application revision.
resource "aws_iam_role_policy" "CodeDeploy_EC2_S3" {
  name = "CodeDeploy-EC2-S3"
  role = aws_iam_role.ec2_s3_access_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*",
        "arn:aws:s3:::webapp.${var.aws_profile_name}.${var.domain_Name}/*"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_policy" "gh_upload_s3" {
  name   = "gh_upload_s3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                  "s3:Get*",
                  "s3:List*",
                  "s3:PutObject",
                  "s3:DeleteObject",
                  "s3:DeleteObjectVersion"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}",
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_Name}/*"
              ]
        }
    ]
}
EOF
}

# GH-Code-Deploy Policy for GitHub Actions to Call CodeDeploy

resource "aws_iam_policy" "GH_Code_Deploy" {
  name   = "GH-Code-Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:application:${aws_codedeploy_app.code_deploy_app.name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
         "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentgroup:${aws_codedeploy_app.code_deploy_app.name}/${aws_codedeploy_deployment_group.code_deploy_deployment_group.deployment_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce"
      ]
    }
  ]
}
EOF
}


# IAM Role for CodeDeploy
resource "aws_iam_role" "code_deploy_role" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_policy" "ghactions-app_user_policy" {
  name   = "ghactions-app_user_policy"
  policy = <<-EOF
  {
      "Version": "2012-10-17",
      "Statement": [{
        "Effect": "Allow",
        "Action": [
          "ec2:AttachVolume",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:CreateKeypair",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteKeyPair",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteVolume",
          "ec2:DeregisterImage",
          "ec2:DescribeImageAttribute",
          "ec2:DescribeImages",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeRegions",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSnapshots",
          "ec2:DescribeSubnets",
          "ec2:DescribeTags",
          "ec2:DescribeVolumes",
          "ec2:DetachVolume",
          "ec2:GetPasswordData",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:RegisterImage",
          "ec2:RunInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances"
        ],
        "Resource" : "*"
      }]
  }
  EOF

}



#CodeDeploy App and Group for webapp
resource "aws_codedeploy_app" "code_deploy_app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  app_name               = aws_codedeploy_app.code_deploy_app.name
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.AllAtOnce"
  service_role_arn       = aws_iam_role.code_deploy_role.arn
  autoscaling_groups     = ["${aws_autoscaling_group.autoscaling.name}"]




  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = "myEC2Instance"
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }


  depends_on = [aws_codedeploy_app.code_deploy_app]
}


data "aws_caller_identity" "current" {}

locals {
  aws_user_account_id = data.aws_caller_identity.current.account_id
}

# Attach the policy for CodeDeploy role for webapp
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.code_deploy_role.name
}

resource "aws_iam_user_policy_attachment" "ghactions-app_ec2_policy_attach" {
  user       = "ghactions-app"
  policy_arn = aws_iam_policy.ghactions-app_user_policy.arn
}

resource "aws_iam_user_policy_attachment" "ghactions-app_s3_policy_attach" {
  user       = "ghactions-app"
  policy_arn = aws_iam_policy.gh_upload_s3.arn
}


resource "aws_iam_user_policy_attachment" "ghactions-app_codedeploy_policy_attach" {
  user       = "ghactions-app"
  policy_arn = aws_iam_policy.GH_Code_Deploy.arn
}

data "aws_route53_zone" "selected" {
  name         = var.domain_Name
  private_zone = false
}

resource "aws_iam_role_policy_attachment" "AmazonCloudWatchAgent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.ec2_s3_access_role.name
}


#Autoscaling Group
resource "aws_autoscaling_group" "autoscaling" {
  name                 = "autoscaling-group"
launch_template {
    id      = aws_launch_template.asg_launch_template.id
    version = aws_launch_template.asg_launch_template.latest_version
  }
  min_size             = 3
  max_size             = 5
  default_cooldown     = 60
  desired_capacity     = 3
  vpc_zone_identifier  = ["${aws_subnet.vpc_01_subnet[0].id}"]
  target_group_arns    = ["${aws_lb_target_group.albTargetGroup.arn}"]
  tag {
    key                 = "Name"
    value               = "myEC2Instance"
    propagate_at_launch = true
  }
}
# load balancer target group
resource "aws_lb_target_group" "albTargetGroup" {
  name     = "albTargetGroup"
  port     = "8000"
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc_01.id
  tags = {
    name = "albTargetGroup"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthstatus"
    port                = "8000"
    matcher             = "200"
  }
}

#Autoscalling Policy
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscaling.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscaling.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "scaleDown" {
  alarm_name                = "terraform-scaleDown"
  comparison_operator       = "LessThanOrEqualToThreshold"
  evaluation_periods        = "2"
  metric_name               = "CPUUtilization"
  namespace                 = "AWS/EC2"
  period                    = "120"
  statistic                 = "Average"
  threshold                 = "3"
  alarm_description         = "Scale Down when average cpu is below 3%"
  alarm_actions             = ["${aws_autoscaling_policy.WebServerScaleDownPolicy.arn}"]
  insufficient_data_actions = []
}

resource "aws_cloudwatch_metric_alarm" "scaleUp" {
  alarm_name          = "terraform-scaleUp"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "Scale Up when average cpu is below 5%"
  alarm_actions       = ["${aws_autoscaling_policy.WebServerScaleUpPolicy.arn}"]

  insufficient_data_actions = []
}


#Load Balancer Security Group
resource "aws_security_group" "loadBalancer" {
  name   = "loadBalance_security_group"
  vpc_id = aws_vpc.vpc_01.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "LoadBalancer Security Group"
    Environment = "${var.aws_profile_name}"
  }
}


#Load balancer
resource "aws_lb" "application-Load-Balancer" {
  name               = "application-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = ["${aws_security_group.loadBalancer.id}"]
  subnets            = aws_subnet.vpc_01_subnet.*.id
  ip_address_type    = "ipv4"
  tags = {
    Environment = "${var.aws_profile_name}"
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_lb_listener" "webapp-Listener" {
  load_balancer_arn = aws_lb.application-Load-Balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.albTargetGroup.arn
  }
  certificate_arn = "arn:aws:acm:us-east-1:${local.aws_user_account_id}:certificate/21423e9b-cf2c-4f42-86da-11b765bd2615"
}

# end 

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"

  alias {
    name                   = aws_lb.application-Load-Balancer.dns_name
    zone_id                = aws_lb.application-Load-Balancer.zone_id
    evaluate_target_health = true
  }
}



# dynamo db 

resource "aws_dynamodb_table" "dynamodb-table" {

  name           = var.dynamo_dbname
  read_capacity  = var.dynamo_read_capacity
  write_capacity = var.dynamo_write_capacity
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }
  tags = {
    Name = "${var.dynamo_dbname}"
  }

}

resource "aws_iam_policy" "dynamodb_policy" {
  name        = "DynamoDB-Policy"
  description = "Lambda function to upload data to DynamoDB"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "ListAndDescribe",
        "Effect" : "Allow",
        "Action" : [
          "dynamodb:List*",
          "dynamodb:DescribeReservedCapacity*",
          "dynamodb:DescribeLimits",
          "dynamodb:DescribeTimeToLive",
          "dynamodb:Get*",
          "dynamodb:PutItem*",
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "SpecificTable",
        "Effect" : "Allow",
        "Action" : [
          "dynamodb:BatchGet*",
          "dynamodb:DescribeStream",
          "dynamodb:DescribeTable",
          "dynamodb:Get*",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchWrite*",
          "dynamodb:CreateTable",
          "dynamodb:Delete*",
          "dynamodb:Update*",
          "dynamodb:PutItem"
        ],
        "Resource" : "arn:aws:dynamodb:*:*:table/dynamo"
      }
    ]
  })
}

//EC2 DynamoDB role attachment
resource "aws_iam_policy_attachment" "ec2_dynamoDB_attach" {
  name       = "ec2DynamoDBPolicy"
  roles      = ["${aws_iam_role.ec2_s3_access_role.name}"]
  policy_arn = aws_iam_policy.dynamodb_policy.arn
}

#SNS topic and policies
resource "aws_sns_topic" "sns_email" {
  name = "email_request"
}

resource "aws_sns_topic_policy" "sns_email_policy" {
  arn    = aws_sns_topic.sns_email.arn
  policy = data.aws_iam_policy_document.sns-topic-policy.json
}

data "aws_iam_policy_document" "sns-topic-policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        "${local.aws_user_account_id}",
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      "${aws_sns_topic.sns_email.arn}",
    ]

    sid = "__default_statement_ID"
  }
}

# IAM policy for SNS
resource "aws_iam_policy" "sns_iam_policy" {
  name   = "ec2_iam_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
      "Resource": "${aws_sns_topic.sns_email.arn}"
    }
  ]
}
EOF
}

# Attach the SNS topic policy to the EC2 role
resource "aws_iam_role_policy_attachment" "ec2_instance_sns" {
  policy_arn = aws_iam_policy.sns_iam_policy.arn
  role       = aws_iam_role.ec2_s3_access_role.name
}

#Lambda Function
resource "aws_lambda_function" "sns_lambda_email" {
  s3_bucket = "codedeploy.prod.prod.csye6225.me"
  s3_key    = "userAddLamda.zip"
  function_name = "userAddLamda"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  environment {
    variables = {
      timeToLive = "5"
    }
  }
}

#SNS topic subscription to Lambda
resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.sns_email.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_lambda_email.arn
}

#SNS Lambda permission
resource "aws_lambda_permission" "lambda_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_lambda_email.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.sns_email.arn
}

#Lambda Policy
resource "aws_iam_policy" "aws_lambda_policy" {
  name        = "aws_lambda_policy"
  description = "Lambda Policy for Dynamo Logs"
  policy      = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Effect": "Allow",
           "Action": [
               "logs:CreateLogGroup",
               "logs:CreateLogStream",
               "logs:PutLogEvents"
           ],
           "Resource": "*"
       },
       {
         "Sid": "LambdaDynamoDBAccess",
         "Effect": "Allow",
         "Action": [
             "dynamodb:GetItem",
             "dynamodb:PutItem",
             "dynamodb:UpdateItem"
         ],
         "Resource": "arn:aws:dynamodb:${var.region}:${local.aws_user_account_id}:table/dynamo"
       },
       {
         "Sid": "LambdaSESAccess",
         "Effect": "Allow",
         "Action": [
             "ses:VerifyEmailAddress",
             "ses:SendEmail",
             "ses:SendRawEmail"
         ], 
         "Resource": "*"
       }
   ]
}
 EOF
}

resource "aws_iam_role_policy_attachment" "attachDynamoDbPolicyToRole" {
  role       = aws_iam_role.ec2_s3_access_role.name
  policy_arn = aws_iam_policy.aws_lambda_policy.arn
}

#IAM role for lambda sns
resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

#attach lambda policy with lambda role
## Check 
resource "aws_iam_role_policy_attachment" "attach_lambda_policy_to_lambda_role" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.aws_lambda_policy.arn
}


resource "aws_iam_policy" "lamda_update_policy" {
  name        = "LamdaUpdatePolicy"
  description = "Update Lamda from GH"
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Effect" : "Allow",
        "Action" : "lambda:UpdateFunctionCode",
        "Resource" : [
          "arn:aws:lambda:*:*:function:userAddLamda"
        ]
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "lamda_user_attach" {
  user       = "ghactions-app"
  policy_arn = aws_iam_policy.lamda_update_policy.arn
}

# read replica 

resource "aws_db_instance" "rds-replica" {
  allocated_storage      = 20
  depends_on             = [aws_security_group.database, aws_db_parameter_group.rds-pg, aws_db_subnet_group.rds-subnet, aws_db_instance.csye6225]
  engine                 = "mysql"
  engine_version         = "5.7"
  instance_class         = "db.t3.micro"
  multi_az               = false
  identifier             = "replica"
  replicate_source_db    = aws_db_instance.csye6225.arn
  username               = "csye6225"
  password               = var.password
  db_subnet_group_name   = aws_db_subnet_group.rds-subnet.name
  parameter_group_name   = aws_db_parameter_group.rds-pg.name
  publicly_accessible    = false
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.database.id]
  availability_zone      = "us-east-1b"
}

