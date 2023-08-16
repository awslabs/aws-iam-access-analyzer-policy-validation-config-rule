## IAM Policy Validation Config Rule

An [AWS Config Custom Lambda Rule](https://docs.aws.amazon.com/config/latest/developerguide/evaluate-config_develop-rules_lambda-functions.html) that uses [IAM Access Analyzer policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html) to validate identity-based and resource-based policies attached to resources in your account. IAM policies are considered noncompliant if there are any validation findings returned from the Access Analyzer [ValidatePolicy](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_ValidatePolicy.html) API.

### Getting Started

[Install the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)


Deploy the CloudFormation template using the AWS CLI:
```
git clone https://github.com/awslabs/aws-iam-access-analyzer-policy-validation-config-rule.git
cd aws-iam-access-analyzer-policy-validation-config-rule
aws cloudformation deploy \
    --stack-name iam-policy-validation-config-rule \
    --template-file templates/template.yaml \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --parameter-overrides RegionToValidateGlobalResources='us-east-1'
```

### Cost of this solution

The primary cost of deploying this solution depends on the number of resources in your account that have IAM policies.  Each time a resource is created or modified, a Lambda function will run and a Config rule will be evaluted.  [See the AWS Config pricing page for more details](https://aws.amazon.com/config/pricing/). 


### Configuring the policy validations exceptions file

You may want to exempt certain resources from specific policy validation checks.  For example, you may need to intentionally deploy a more privileged role to your environment and you do not want that role's policies to have policy validation findings. You can configure this type of exception by placing a file in an S3 bucket that the config rule can read from.

[Here is the schema for the policy validation exceptions file](./function/filters/exceptions-file-schema.json)

#### Deploying the policy validations exception file

- Create a JSON file with the global or account-specific exceptions that follows the schema described above.  Examples can be seen below.
- Upload that file to an S3 bucket that you own.
- Modify the bucket policy so that the bucket is accessible to your Config rule if the Config rule is operating in a different account than the bucket was created in. Below is an example of a bucket policy that allows all accounts in your organization to read the exceptions file.
    ```json
    {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::EXAMPLE-BUCKET/my-exceptions-file.json",
            "Condition": {
                "StringEquals": {
                    "aws:PrincipalOrgId": "<your organization id here>"
                }
            }
        }]
  }
  ```


- Deploy the CloudFormation template using the ExceptionsS3BucketName and ExceptionsS3FilePrefix parameters.  The file prefix should be the full prefix of the S3 object exceptions file.

#### Referencing the policy validation exceptions file when deploying config rule template

```
aws cloudformation deploy \
    --stack-name iam-policy-validation-config-rule \
    --template-file templates/template.yaml \
    --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
    --parameter-overrides RegionToValidateGlobalResources='us-east-1' \
        ExceptionsS3BucketName='EXAMPLE-BUCKET' \
        ExceptionsS3FilePrefix='my-exceptions-file.json'
```

### What does the IAM policy validation config rule do?

The IAM policy validation config rule is designed to detect the deployment of IAM identity-based and resource-based policies in your AWS environment that may have grammatical or syntactical errors and may not follow AWS best practices.

The config rule will mark resources that have IAM policies as noncompliant if the resources have validation findings found using IAM Access Analyzer's ValidatePolicy API.

This can be combined with a preventative mechanism like the [IAM Policy Validator for AWS CloudFormation](https://github.com/awslabs/aws-cloudformation-iam-policy-validator) or the [IAM Policy Validator for Terraform](https://github.com/awslabs/terraform-iam-policy-validator) that run in your CI/CD pipelines prior to deploying IAM policies to your AWS environment.

#### Example policy validation exceptions file contents

One way to maintain this exceptions file is to centrally host it in a Git repo that allows pull requests with approvals for individual account exceptions.

Ignore all security warnings for roles in an "admin" path for all accounts:
```
{
    "global": {
        "ignoreFindingsWith": [{
            "resourceType": "AWS::IAM::Role",
            "resourceName": "admin/*"        
        }]
    }
}
```

Ignore all security warnings for roles in an "admin" path for a specific account:
```
{
    "111111111111": {
        "ignoreFindingsWith": [{
            "resourceType": "AWS::IAM::Role",
            "resourceName": "admin/*"        
        }]
    }
}
```

Disable inheritance of global rules for a specific account.  The outcome of this exception configuration is that IAM roles in the admin role path are not ignored for account 111111111111, but are ignored everywhere else.
```
{
    "global": {
        "ignoreFindingsWith": [{
            "resourceType": "AWS::IAM::Role",
            "resourceName": "admin/*"        
        }]
    },
    "111111111111": {
        "inheritGlobalIgnoreRules": false
    }
}
```

Account specific configuration can be used to override global configuration for individual accounts. When using account configuration with the IgnoreFindingsWith array, the account configuration is appended to the global configuration.
```
{
    "global": {
        "ignoreSecurityWarningFindings": true
    },
    "111111111111": {
        "ignoreSecurityWarningFindings": false
    }
}
```

You can use the following fields within the ignoreFindingsWith array to exclude specific findings:

**resourceType**: The type of resource. In CloudFormation resource format (e.g. AWS::IAM::Role). Exact match, no wildcards, case-insensitive.

**issueCode**: The issue code returned from the Access Analyzer ValidatePolicy API. Exact match, no wildcards, case-insensitive.

**findingType**: The finding type returned from the Access Analyzer ValidatePolicy API. Exact match, no wildcards, case-insensitive.

**resourceName**: The name of the resource. Supports wildcards (*). Includes path for resources that support paths. Case-insensitive.

**policyType**: The type of IAM policy to ignore.  Exact match, no wildcards, case-insensitive.

**region**: Used to ignore resources in a specific region. This is the region that the validation is run in. Exact match, no wildcards, case-insensitive.
