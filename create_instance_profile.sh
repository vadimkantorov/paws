# https://acloudguru.com/hands-on-labs/creating-an-ssm-iam-role-and-configuring-an-ec2-instance-with-aws-systems-manager-via-the-cli

aws iam list-policies --scope AWS --query "Policies[?PolicyName == 'AmazonEC2RoleforSSM']"
# "PolicyName": "AmazonEC2RoleforSSM",
# "PolicyId": "ANPAI6TL3SMY22S4KMMX6",
# "Arn": "arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
# "DefaultVersionId": "v8",
# aws iam get-policy-version --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM --version-id v8

aws iam create-role --role-name MyEC2SSMRole --assume-role-policy-document file://EC2Trust.json

aws iam attach-role-policy --role-name MyEC2SSMRole --policy-arn arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM

aws iam create-instance-profile --instance-profile-name MyEC2InstanceProfile

#{
#    "InstanceProfile": {
#        "Path": "/",
#        "InstanceProfileName": "MyEC2InstanceProfile",
#        "InstanceProfileId": "AIPAYFEHHVEJLLU4N27EI",
#        "Arn": "arn:aws:iam::560776849682:instance-profile/MyEC2InstanceProfile",
#        "CreateDate": "2021-10-22T12:47:47Z",
#        "Roles": []
#    }
#}

aws iam add-role-to-instance-profile --instance-profile-name MyEC2InstanceProfile --role-name MyEC2SSMRole
