mkdir -p ~/.poehali

aws ec2 create-security-group --group-name "$1" --description "$1" --output text > "~/.poehali/$1.sg.txt"
SGID=$(cat "~/.poehali/$1.sg.txt")
aws ec2 authorize-security-group-ingress --group-id $SGID --protocol tcp --port 22 --cidr 0.0.0.0/0 > "~/.poehali/$1.sg.json"
