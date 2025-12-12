# CLOUD SECURITY IMPLEMENTATION - AWS IAM Policies, Secure Storage, Data Encryption
# Step 1: Install boto3
!pip install boto3

# Step 2: Import libraries
import boto3
import json
from botocore.exceptions import ClientError

# Step 3: Set AWS credentials (replace with actual keys)
AWS_ACCESS_KEY_ID = "YOUR_AWS_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_AWS_SECRET_ACCESS_KEY"
AWS_REGION = "us-east-1"

session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION
)

s3 = session.client('s3')
iam = session.client('iam')
kms = session.client('kms')

def create_kms_key():
    try:
        response = kms.create_key(
            Description='Security key for S3 encryption and IAM policies',
            KeyUsage='ENCRYPT_DECRYPT',
            KeySpec='SYMMETRIC_DEFAULT'
        )
        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']
        kms.enable_key_rotation(KeyId=key_id)
        kms.create_alias(AliasName='alias/cloud-security-key', TargetKeyId=key_id)
        print(f"✓ KMS Key created: {key_id}")
        return key_id, key_arn
    except ClientError as e:
        print(f"✗ KMS Key creation failed: {e}")
        return None, None

def create_iam_security_role_and_policy(bucket_name, kms_key_arn):
    role_name = f"secure-s3-role-{bucket_name}"
    policy_name = f"s3-security-policy-{bucket_name}"
    
    # IAM Policy Document - Least privilege for S3 + KMS
    policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:ListBucket"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kms:Encrypt",
                    "kms:Decrypt",
                    "kms:ReEncrypt*",
                    "kms:GenerateDataKey*",
                    "kms:DescribeKey"
                ],
                "Resource": kms_key_arn
            }
        ]
    }
    
    try:
        # Create IAM Policy
        policy_response = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(policy_document),
            Description='Least privilege policy for secure S3 access'
        )
        policy_arn = policy_response['Policy']['Arn']
        print(f"✓ IAM Policy created: {policy_arn}")
        
        # Create IAM Role with trust policy
        trust_policy = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        }
        role_response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(trust_policy),
            Description='Role for secure S3 access'
        )
        
        # Attach policy to role
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        print(f"✓ IAM Role '{role_name}' created and policy attached")
        return role_name, policy_arn
        
    except ClientError as e:
        print(f"✗ IAM setup failed: {e}")
        return None, None

def create_secure_bucket(bucket_name, kms_key_arn):
    try:
        s3.create_bucket(Bucket=bucket_name)
        
        # Default KMS encryption
        encryption_config = {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': kms_key_arn
                }
            }]
        }
        s3.put_bucket_encryption(Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)
        
        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'BlockPublicPolicy': True,
                'IgnorePublicAcls': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Strict bucket policy
        bucket_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "EnforceEncryption",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:PutObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "StringNotEquals": {
                            "s3:x-amz-server-side-encryption": "aws:kms"
                        }
                    }
                },
                {
                    "Sid": "EnforceHTTPS",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "s3:*",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {
                        "Bool": {"aws:SecureTransport": "false"}
                    }
                }
            ]
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))
        print(f"✓ Secure bucket '{bucket_name}' created with KMS encryption")
        
    except ClientError as e:
        print(f"✗ Bucket creation failed: {e}")

# EXECUTE COMPLETE SECURITY IMPLEMENTATION
print("🚀 CLOUD SECURITY IMPLEMENTATION STARTING...")
BUCKET_NAME = 'secure-cloud-project-2025'

kms_key_id, kms_key_arn = create_kms_key()
if kms_key_arn:
    create_secure_bucket(BUCKET_NAME, kms_key_arn)
    role_name, policy_arn = create_iam_security_role_and_policy(BUCKET_NAME, kms_key_arn)
    
    print("" + "="*60)
    print("✅ SECURITY IMPLEMENTATION COMPLETE")
    print("="*60)
    print(f"📦 Bucket: s3://{BUCKET_NAME}")
    print(f"🔐 KMS Key: {kms_key_arn}")
    print(f"👤 IAM Role: {role_name}")
    print(f"📜 IAM Policy: {policy_arn}")
    print("="*60)
    print("🔒 Security Features Enabled:")
    print("   • Server-side KMS encryption (default)")
    print("   • Public access BLOCKED")
    print("   • HTTPS enforcement")
    print("   • Least privilege IAM policy")
    print("   • KMS key rotation enabled")