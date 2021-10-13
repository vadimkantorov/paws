aws ec2 run-instances --count 1 --instance-type p3.8xlarge --key-name "$1" --security-group-ids "$1" --image-id $2 > "$1.gpu.json"

