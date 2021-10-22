aws ec2 describe-instances --query 'Reservations[].Instances[].{IP:PublicIpAddress}' --filters Name=instance-state-name,Values=running --output text

#aws ec2 describe-instances --query 'Reservations[].Instances[].{IP:PublicIpAddress,Name:Tags[0].Value}' --filters Name=instance-state-name,Values=running --output text
