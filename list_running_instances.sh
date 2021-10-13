aws ec2 describe-instances --query 'Reservations[].Instances[].{Name:Tags[0].Value,IP:PublicIpAddress}' --filters Name=instance-state-name,Values=running
