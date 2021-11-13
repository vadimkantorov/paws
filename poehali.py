import os
import datetime
import json
import random
import string
import argparse
import subprocess
import botocore
import boto3

po = 'poehali'

def N(name = '', resource = '', suffix = ''):
    return po + ('_' + name if name else '') + ('_' + resource if resource else '') + ('_' + suffix if suffix else '')

def TagSpecifications(resource, name = '', suffix = ''):
    return [dict(ResourceType = resource, Tags = [dict(Key = 'Name', Value = N(name = name, suffix = suffix)  )])] 

def setup(name, root, region, availability_zone, vpc_id = None, subnet_id = None, cold_disk_size_gb = 200, hot_disk_size_gb = 200, cidr_vpc = '192.168.0.0/16', cidr_public_internet = '0.0.0.0/0', iops = 100):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)

    if not os.path.exists(os.path.join(root, name + '.pem')):
        try:
            key_pair = ec2.create_key_pair(KeyName = name)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
                key_pair = ec2.create_key_pair(KeyName = name + '_' + ''.join(random.choices(string.ascii_uppercase, k = 4)))

        with open(os.path.join(root, name + '.pem'), 'w') as f:
            f.write(key_pair['KeyMaterial'])
        
        os.chmod(os.path.join(root, name + '.pem'), 600)

    if not vpc_id:
        vpc = (ec2.describe_vpcs(Filters = [dict(Name = 'tag:Name', Values = [po + '*'])])['Vpcs'] + [None])[0]
        if not vpc:
            try:
                vpc = ec2.create_default_vpc()['Vpc']
            except botocore.exceptions.ClientError as err:
                print(err)
                #TODO: filter out EC2-Classic not supporting default VPC
                vpc = ec2.create_vpc(CidrBlock = cidr_vpc, InstanceTenancy='default', TagSpecifications = TagSpecifications('vpc'))['Vpc']
        vpc_id = vpc['VpcId']
            
        security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc_id]), dict(Name = 'group-name', Values = [name])])['SecurityGroups'] + [None])[0]
        if not security_group:
            security_group = ec2.create_security_group(GroupName = name, Description = name, VpcId = vpc_id, TagSpecifications = TagSpecifications('security-group'))
            ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpPermissions = [dict(IpProtocol = 'tcp', FromPort = 22, ToPort = 22, IpRanges = [dict(CidrIp = cidr_public_internet)])])

    internet_gateway = (ec2.describe_internet_gateways(Filters = [dict(Name = 'attachment.vpc-id', Values = [vpc_id])])['InternetGateways'] + [None])[0]
    if not internet_gateway:
        internet_gateway = ec2.create_internet_gateway(TagSpecifications = TagSpecifications('internet-gateway'))['InternetGateway']
        ec2.attach_internet_gateway(InternetGatewayId = internet_gateway['InternetGatewayId'], VpcId = vpc_id)

    if not subnet_id:
        subnet = (ec2.describe_subnets(Filters = [dict(Name = 'availability-zone', Values = [availability_zone]), dict(Name = 'tag:Name', Values = [po + '*'])])['Subnets'] + [None])[0]
        if not subnet:
            subnet_id = ec2.create_subnet(VpcId = vpc_id, AvailabilityZone = availability_zone, CidrBlock = cidr_vpc, TagSpecifications = TagSpecifications('subnet'))['Subnet']['SubnetId']
            route_table_id = ec2.describe_route_tables(Filters = [dict(Name = 'association.subnet-id', Values = [subnet_id])])['RouteTables'][0]['Associations'][0]['RouteTableId']
            ec2.create_route(DestinationCidrBlock = cidr_public_internet, GatewayId = internet_gateway_id, RouteTableId = route_table_id)

    cold_disk = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name = name, suffix = 'datasets')])])['Volumes'] + [None])[0]
    if not cold_disk:
        ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = cold_disk_size_gb, Iops = iops, TagSpecifications = TagSpecifications('volume', name = name, suffix = 'datasets'))
    
    hot_disk = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name = name, suffix = 'experiments')])])['Volumes'] + [None])[0]
    if not hot_disk:
        ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = hot_disk_size_gb, Iops = iops, TagSpecifications = TagSpecifications('volume', name = name, suffix = 'experiments'))

    #policy_arn = [p for p in iam.list_policies(Scope = 'AWS', PathPrefix = '/service-role/')['Policies'] if p['PolicyName'] == 'AmazonEC2RoleforSSM'][0]['Arn']
    #policy_document = dict(
    #    Version = '2012-10-17',
    #    Statement = dict(
    #        Effect = 'Allow',
    #        Principal = dict(Service = 'ec2.amazonaws.com'),
    #        Action = 'sts:AssumeRole'
    #    )
    #)
    #role_created = iam.create_role(RoleName = name, AssumeRolePolicyDocument = json.dumps(policy_document))
    #role_attached = iam.attach_role_policy(RoleName = name, PolicyArn = policy_arn)
    #instance_profile_created = iam.create_instance_profile(InstanceProfileName = name)
    #role_added_to_instance_profile = iam.add_role_to_instance_profile(InstanceProfileName = name, RoleName = name)

def micro(region, availability_zone, name, instance_type = 't2.micro', image_name = 'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20210430', shutdown_after_init_script = False):
    ec2 = boto3.client('ec2', region_name = region)

    vpc = (ec2.describe_vpcs(Filters = [dict(Name = 'tag:Name', Values = [po + '*'])])['Vpcs'] + [None])[0]
    subnet = (ec2.describe_subnets(Filters = [dict(Name = 'availability-zone', Values = [availability_zone]), dict(Name = 'tag:Name', Values = [po + '*'])])['Subnets'] + [None])[0]
    security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc['VpcId']]), dict(Name = 'group-name', Values = [name])])['SecurityGroups'] + [None])[0]
    
    image_id = ec2.describe_images(Filters = [dict(Name = 'name', Values = [image_name])])['Images'][0]['ImageId']
    
    volume_id_datasets = ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'datasets')])])['Volumes'][0]['VolumeId']
    
    volume_id_experiments = ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'experiments')])])['Volumes'][0]['VolumeId']

    init_script = '''#!/bin/bash -xe
    INSTANCEID=$(curl -s http://http://169.254.169.254/latest/meta-data/instance-id)
    mkdir ~/datasets ~/experiments

    sudo apt update
    sudo apt install -y awscli

    aws ec2 attach-volume --device /dev/xvdd --instance-id $INSTANCEID --volume-id $VOLUMEID1
    aws ec2 attach-volume --device /dev/xvde --instance-id $INSTANCEID --volume-id $VOLUMEID2
    
    aws ec2 wait volume-in-use --volume-ids $VOLUMEID1 $VOLUMEID2

    [ "$(file -b -s /dev/xvdd)" == "data" ] && mkfs -t xfs /dev/xvdd
    [ "$(file -b -s /dev/xvde)" == "data" ] && mkfs -t xfs /dev/xvde
    
    mount /dev/xvdd ~/datasets
    mount /dev/xvde ~/experiments
    
    '''.replace('$VOLUMEID1', volume_id_datasets).replace('$VOLUMEID2', volume_id_experiments)

    if shutdown_after_init_script:
        init_script += 'shutdown'

    print(ec2.run_instances(
        InstanceType = instance_type, 
        ImageId = image_id, 
        MinCount = 1, 
        MaxCount = 1, 
        KeyName = name, 
        Placement = dict(AvailabilityZone = availability_zone), 
        NetworkInterfaces = [dict(DeviceIndex = 0, Groups = [security_group['GroupId']], SubnetId = subnet['SubnetId'], AssociatePublicIpAddress = True)], 
        TagSpecifications = TagSpecifications('instance', name = name, suffix = 'micro'),
        
        #IamInstanceProfile = dict(Name = name), 
        #UserData = init_script,
    ))

def gpu(name, root, region, availability_zone):
    pass

def datasets(name, root, region, availability_zone):
    micro(region, availability_zone, name, shutdown_after_init_script = True)

def ps(region, name, root):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    ec2 = boto3.client('ec2', region_name = region)
    
    instances = [instance for reservation in ec2.describe_instances()['Reservations'] for instance in reservation['Instances']]
    for instance in instances:
        instance_name = ([tag['Value'] for tag in instance['Tags'] if tag['Key'] == 'Name'] + ['NoName'])[0]
        if not instance_name.startswith('poehali_'):
            continue

        state = instance['State']
        if state['Name'] == 'terminated':
            continue

        availability_zone = instance['Placement']['AvailabilityZone']
        instance_id = instance['InstanceId']
        public_ip = instance.get('PublicIpAddress')
        private_ip = instance.get('PrivateIpAddress')

        print(f'[{instance_name} := {instance_id} @ {availability_zone}]: {state["Name"]}/{state["Code"]}, {public_ip or "no.public.ip.address"} ({private_ip or "no.private.ip.address"})')
        print('ssh -i ' + os.path.join(root, name + '.pem') + f' ubuntu@{public_ip}') if public_ip else print('ssh N/A')
        print()

def kill(region, instance_id):
    ec2 = boto3.client('ec2', region_name = region)
    client.terminate_instances(InstanceIds = [instance_id])
    
def killall(region, name = None):
    ec2 = boto3.client('ec2', region_name = region)
    instances = [instance for reservation in ec2.describe_instances(Filters = [dict(Name = 'tag:Name', Values = [N(name = name) + '_*'])]) ['Reservations'] for instance in reservation['Instances']]
    print(instances)
    #client.terminate_instances(InstanceIds = [instance['InstanceId'] for instance in instances])

def ssh(region, name, root, instance_id, username = 'ubuntu'):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    ec2 = boto3.client('ec2', region_name = region)

    instance = ([instance for reservation in ec2.describe_instances(InstanceIds = [instance_id])['Reservations'] for instance in reservation['Instances']] + [None])[0]
    if not instance:
        print('Instance [', instance_id, '] not found')
        return
    
    print(instance)
    public_ip = instance.get('PublicIpAddress')
    if not public_ip:
        print('Instance [', instance_id, '] does not have public IP')
        return

    cmd = ['ssh', '-i', os.path.join(root, name + '.pem'), f'{username}@{public_ip}']
    print(' '.join(cmd))
    print()

    subprocess.call(cmd)

def help(region):
    print('VPCs @', f'https://console.aws.amazon.com/vpc/home?region={region}#vpcs')
    print('Subnets @', f'https://console.aws.amazon.com/vpc/home?region={region}#subnets')
    print('Keypairs @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#KeyPairs')
    print('Instances @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances')
    print('EBS disks @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Volumes')

def ls(region, name):
    ec2 = boto3.client('ec2', region_name = region)
    
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        name = ([tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Name'] + ['NoName'])[0]
        availability_zone = volume['AvailabilityZone']
        state = volume['State']
        volume_id = volume['VolumeId']
        size = volume['Size']

        print(f'[{name} := {volume_id} @ {availability_zone}]: {size} Gb, {state}')

    if not volumes:
        print(f'No volumes @ {region}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default = 'us-east-1')
    parser.add_argument('--availability-zone', default = 'us-east-1a')
    parser.add_argument('--cold-disk-size-gb', type = int, default = 50)
    parser.add_argument('--hot-disk-size-gb', type = int, default = 50)
    parser.add_argument('--name', default = 'poehalitest43')
    parser.add_argument('--root', default = '~')
    parser.add_argument('--vpc-id')
    parser.add_argument('--subnet-id')
    parser.add_argument('--instance-id')
    parser.add_argument('cmd', choices = ['help', 'ps', 'ls', 'kill', 'killall', 'ssh', 'setup', 'micro', 'datasets'])
    args = parser.parse_args()
    
    if args.cmd == 'help':
        help(region = args.region)
    
    if args.cmd == 'kill':
        kill(region = args.region, instance_id = args.instance_id)
    
    if args.cmd == 'killall':
        killall(region = args.region, name = args.name)
    
    if args.cmd == 'ps':
        ps(region = args.region, name = args.name, root = args.root)
    
    if args.cmd == 'ls':
        ls(region = args.region, name = args.name)
    
    if args.cmd == 'ssh':
        ssh(region = args.region, name = args.name, root = args.root, instance_id = args.instance_id)

    if args.cmd == 'setup':
        setup(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone, vpc_id = args.vpc_id, cold_disk_size_gb = args.cold_disk_size_gb, hot_disk_size_gb = args.hot_disk_size_gb)
    
    if args.cmd == 'micro':
        micro(name = args.name, region = args.region, availability_zone = args.availability_zone)
    
    if args.cmd == 'datasets':
        datasets(name = args.name, region = args.region, availability_zone = args.availability_zone)
