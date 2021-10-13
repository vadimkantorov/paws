aws ec2 run-instances --count 1 --instance-type t2.micro --key-name "$1" --security-group-ids "$1" --image-id $2 > "$1.micro.json"
