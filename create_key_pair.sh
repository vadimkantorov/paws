mkdir -p ~/.poehali

aws ec2 create-key-pair --key-name "$1" --query 'KeyMaterial' --output text > ~/.poehali/$1.pem

chmod 600 ~/.poehali/$1.pem
