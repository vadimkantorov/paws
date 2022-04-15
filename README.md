# Poehali
A helper script for launching workloads (e.g. reproducing results of deep learning papers) on AWS.

**Does not support EC2-Classic accounts, relies on existence of default VPC/subnet/route table/internet gateway**

```shell
python paws.py setup --hot-bucket --cold-bucket
python paws.py run
```

# Requirements
```
python -m pip install awscli boto3

# note the region in the url
# obtain access keys `Access Key ID` and `Secret Access Key` by creating them at https://console.aws.amazon.com/iam/home?region=eu-east-1#/security_credentials
# update `~/.aws/credentials` and `~/aws/config`

# ~/.aws/credentials
[default]
aws_access_key_id = <access_key_id>
aws_secret_access_key = <secret_access_key>

# ~/.aws/config
[default]
output = json
region = us-east-1
######################
```
