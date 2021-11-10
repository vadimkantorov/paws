import os
import json
import argparse
import subprocess
import boto3

def write_text(root, name, text):
    with open(os.path.join(root, name), 'w') as f:
        f.write(text)
    print('Written to', os.path.join(root, name))
    

def setup(name, root, region):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)

    ec2 = boto3.client('ec2', region_name = region)

    key_pair = ec2.create_key_pair(KeyName = name) # err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate'
    write_text(root, 'key.pem', key_pair['KeyMaterial'])
    
    security_group = ec2.create_security_group(GroupName = name, Description = name)
    write_text(root, 'security_group.txt', security_group['GroupId'])

    security_group_authorized_ssh = ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpProtocol = 'tcp', FromPort = 22, ToPort = 22, CidrIp = '0.0.0.0/0')
    write_text(root, 'security_group_authorized_ssh.txt', json.dumps(security_group_authorized_ssh, indent = 2))

    # create key pair
    # create security group
    # create instance profile
    # fs partition

def destroy(name):
    pass

def data():
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default = 'eu-west-3')
    parser.add_argument('--name', default = 'poehalitest6')
    parser.add_argument('--root', default = '~')
    parser.add_argument('cmd', choices = ['setup', 'data'])
    args = parser.parse_args()

    if args.cmd == 'setup':
        setup(name = args.name, region = args.region, root = args.root)
