aws ec2 create-security-group --group-name "$1" --description "$1" > "$1.sg.json"
