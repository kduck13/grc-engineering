variable "region" {
  description = "AWS region to deploy lab resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name prefix applied to all resources in this lab"
  type        = string
  default     = "vpc-seg-lab"
}
