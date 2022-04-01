variable "name_prefix" {
  description = "String to prefix on object names"
  type        = string
}

variable "name_suffix" {
  description = "String to append to object names. This is optional, so start with dash if using"
  type        = string
  default     = ""
}

variable "input_tags" {
  description = "Map of tags to apply to resources"
  type        = map(string)
  default     = {}
}

variable "transition_IA" {
  description = "Number of days before transitioning data to S3 Infrequently Accessed"
  type        = string
  default     = "180"
}

variable "transition_glacier" {
  description = "Number of days before transitioning data to Glacier"
  type        = string
  default     = "366"
}

variable "transition_expiration" {
  description = "Number of days before expiring data completely"
  type        = string
  default     = "2557"
}

variable "versioning_enabled" {
  description = "Enable versioning on the S3 bucket, this is mainly for S3 logging replication"
  type        = bool
  default     = true #There are zero pricing implications assuming this module is used as it should be
}

variable "enable_centralized_logging" {
  description = "Enable support for centralized logging to a centralized logging account"
  type        = bool
  default     = false
}

variable "enable_replication" {
  description = "Enable replication for logging bucket"
  type        = bool
  default     = false
}

variable "enable_server_side_encryption" {
  description = "Enable server-side encryption"
  type        = bool
  default     = false
}

variable "s3_destination_bucket_name" {
  description = "Centralized Logging Bucket Name"
  type        = string
  default     = ""
}

variable "iam_role_s3_replication_arn" {
  description = "IAM Role that enable S3 Role Assumption for Centralized Logging"
  type        = string
  default     = ""
}

variable "logging_account_id" {
  description = "Logging Account Number"
  type        = string
  default     = ""
}

variable "replication_dest_storage_class" {
  description = "The storage class to send replicated objects (https://docs.aws.amazon.com/AmazonS3/latest/API/API_Transition.html#AmazonS3-Type-Transition-StorageClass)"
  type        = string
  default     = "STANDARD_IA"
}