```shell
python3 -m pip install awscli

# obtain access keys `Access Key ID` and `Secret Access Key` by creating them at https://console.aws.amazon.com/iam/home?region=eu-west-3#/security_credentials
# update `~/.aws/credentials` and `~/aws/config`

# ~/.aws/credentials
[default]
aws_access_key_id = <access_key_id>
aws_secret_access_key = <secret_access_key>

# ~/.aws/config
[default]
output = json
region = us-west-3
######################

bash create_key_pair.sh detreg1
bash create_security_group.sh detreg1

AMI=$(bash find_ubuntu_ami.sh)

bash launch_micro.sh detreg1 $AMI
```
