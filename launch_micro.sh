# aws ec2 describe-subnets

aws ec2 run-instances  --count 1 --instance-type t2.micro --key-name "$1" --security-group-ids "$1" --image-id $2 --query 'Instances[*].InstanceId' --output text --iam-instance-profile Arn=arn:aws:iam::560776849682:instance-profile/MyEC2InstanceProfile

# aws ec2 attach-volume —-volume-id vol-<VOLUME_ID> —-instance-id i-<INSTANCE_ID> --device /dev/xvdf
