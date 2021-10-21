AVAILABILITYZONENAME=eu-west-3a

#aws ec2 create-volume --volume-type io1  --size 100 --iops 300 --availability-zone $AVAILABILITYZONENAME --region eu-west-3 --multi-attach-enabled

aws ec2 create-volume --volume-type io1  --size 100 --iops 300 --region us-east-1 --availability-zone us-east-1a --multi-attach-enabled --tag-specifications 'ResourceType=volume,Tags=[{Key=Name,Value=datasets}]'

# TODO: query subnet-id
