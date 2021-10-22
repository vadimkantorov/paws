# https://docs.aws.amazon.com/systems-manager/latest/userguide/walkthrough-cli.html

aws ssm send-command \
    --instance-ids "i-0628b0737c4bdcd6f" \
    --document-name "AWS-RunShellScript" \
    --comment "IP config" \
    --parameters commands=ifconfig \
    --output text


# mkdir ~/datasets
# lsblk
# mkfs -t xfs /dev/nvme2n1
# mount /dev/nvme2n1 ~/datasets
