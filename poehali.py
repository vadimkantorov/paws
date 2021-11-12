import os
import datetime
import json
import argparse
import subprocess
import boto3

def N(name, resource = '', suffix = ''):
    return 'poehali_' + name + ('_' + resource if resource else '') + ('_' + suffix if suffix else '')

def T(name, resource, suffix = ''):
    return [dict(ResourceType = resource, Tags = [dict(Key = 'Name', Value = N(name, suffix)  )])] 

def setup(name, root, region, availability_zone, vpc_id = None, subnet_id = None):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)

    key_pair = ec2.create_key_pair(KeyName = name) # err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate'
    write_text(root, name + '.pem', key_pair['KeyMaterial'])
    os.chmod(os.path.join(root, name + '.pem'), 600)
    
    cidr_vpc = '192.168.0.0/16'
    cidr_public_internet = '0.0.0.0/0'
    
    if not vpc_id:
        else:
            try:
                vpc = ec2.create_default_vpc()['Vpc']
            except:
                vpc = ec2.create_vpc(CidrBlock = cidr_vpc, InstanceTenancy='default', TagSpecifications = T('poehali', 'vpc'))['Vpc']
            vpc_id = vpc['VpcId']
        
        internet_gateway_id = ec2.create_internet_gateway()['InternetGateway']['InternetGatewayId']
        ec2.attach_internet_gateway(InternetGatewayId = internet_gateway_id, VpcId = vpc_id)
        
        write_text(root, f'../{region}.txt', vpc_id)

    if not subnet_id:
        if os.path.exists(subnet_id):
        else:
            subnet_id = ec2.create_subnet(VpcId = vpc_id, AvailabilityZone = availability_zone, CidrBlock = cidr_vpc, TagSpecifications = T('poehali', 'subnet'))['Subnet']['SubnetId']

        route_table_id = ec2.describe_route_tables(Filters = [dict(Name = 'association.subnet-id', Values = [subnet_id])])['RouteTables'][0]['Associations'][0]['RouteTableId']
        ec2.create_route(DestinationCidrBlock = cidr_public_internet, GatewayId = internet_gateway_id, RouteTableId = route_table_id)

    security_group = ec2.create_security_group(GroupName = name, Description = name, VpcId = vpc_id, TagSpecifications = T(name, 'security-group'))

    security_group_authorized_ssh = ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpPermissions = [dict(IpProtocol = 'tcp', FromPort = 22, ToPort = 22, IpRanges = [dict(CidrIp = cidr_public_internet)])])

    cold_disk_created = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = cold_disk_size_gb, Iops = iops, TagSpecifications = T(name, 'volume', 'datasets'))
    
    hot_disk_created = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = hot_disk_size_gb, Iops = iops, TagSpecifications = T(name, 'volume', 'experiments'))

def micro(name, root, region, availability_zone, instance_type = 't2.micro', image_name = 'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20210430', shutdown_after_init_script = False):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)

    subnet_id = ec2.describe_subnets(Filters = [dict(name = 'tag:Name', values = [N('subnet')])]) 
    
    security_group_id = ec2.describe_security_groups(GroupNames = [N('security_group')])

    image_id = ec2.describe_images(Filters = [dict(Name = 'name', Values = [image_name])])['Images'][0]['ImageId']
    
    volume_id_datasets = ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'datasets')])])['Volumes'][0]['VolumeId']
    
    volume_id_experiments = ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'experiments')])])['Volumes'][0]['VolumeId']

    launch_script = '''#!/bin/bash -xe
    INSTANCEID=$(curl -s http://instance-data/latest/meta-data/instance-id)
    mkdir ~/datasets ~/experiments

    aws ec2 attach-volume --device /dev/xvdf --instance-id $INSTANCEID --volume-id $VOLUMEID1
    aws ec2 attach-volume --device /dev/xvdh --instance-id $INSTANCEID --volume-id $VOLUMEID2
    
    aws ec2 wait volume-in-use --volume-ids $VOLUMEID1 $VOLUMEID2 # attached

    [ "$(file -b -s /dev/xvdf)" == "data" ] && mkfs -t xfs /dev/xvdf
    [ "$(file -b -s /dev/xvdh)" == "data" ] && mkfs -t xfs /dev/xvdh
    
    mount /dev/xvdf ~/datasets
    mount /dev/xvdh ~/experiments
    
    '''.replace('$VOLUMEID1', volume_id_datasets).replace('$VOLUMEID2', volume_id_checkpoints)

    #VOlUMEID=$(aws ec2 describe-volumes --region $REGION --filters Name=tag:Name,Values=$VOLUMENAME --query Volumes[].VolumeId --output text)

    cold_instance_run = ec2.run_instances(
        InstanceType = instance_type, 
        ImageId = image_id, 
        MinCount = 1, 
        MaxCount = 1, 
        KeyName = name, 
        Placement = dict(AvailabilityZone = availability_zone), 
        NetworkInterfaces = [dict(DeviceIndex = 0, Groups = [security_group_id], SubnetId = subnet_id, AssociatePublicIpAddress = True)], 
        TagSpecifications = T(name, 'instance', 'datasets'),
        
        #IamInstanceProfile = dict(Name = name), 
        #UserData = launch_script,
    )

def gpu(name, root, region, availability_zone):
    pass

def datasets(name, root, region, availability_zone):
    micro(name, root, region, availability_zone, shutdown_after_init_script = True)

def ps(name, region, root):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    instances = [instance for reservation in ec2.describe_instances()['Reservations'] for instance in reservation['Instances']]
    for instance in instances:
        #TODO: filter by project name

        name = [tag['Value'] for tag in instance['Tags'] if tag['Key'] == 'Name'][0]
        availability_zone = instance['Placement']['AvailabilityZone']
        state = instance['State']
        instance_id = instance['InstanceId']
        public_ip = instance.get('PublicIpAddress')
        private_ip = instance.get('PrivateIpAddress')

        print(f'[{name} := {instance_id} @ {availability_zone}]: {state["Name"]}/{state["Code"]}, {public_ip or "no.public.ip.address"} ({private_ip or "no.private.ip.address"})')
        print('ssh -i ' + os.path.join(root, name + '.pem') + f' ubuntu@{public_ip}') if public_ip else print('ssh N/A')
        print()


def help(region):
    print('VPCs @', f'https://console.aws.amazon.com/vpc/home?region={region}#vpcs')
    print('Subnets @', f'https://console.aws.amazon.com/vpc/home?region={region}#subnets')
    print('Keypairs @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#KeyPairs')
    print('Instances @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances')
    print('EBS disks @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Volumes')

def ls(name, region, root):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    print('View EBS disks @', f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Volumes:', '\n')

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
    parser.add_argument('cmd', choices = ['help', 'ps', 'ls', 'setup', 'micro', 'prepare_datasets'])
    args = parser.parse_args()
    
    if args.cmd == 'help':
        help(region = args.region)
    
    if args.cmd == 'ps':
        ps(name = args.name, region = args.region, root = args.root)
    
    if args.cmd == 'ls':
        ls(name = args.name, region = args.region, root = args.root)

    if args.cmd == 'setup':
        setup(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone, vpc_id = args.vpc_id, cold_disk_size_gb = args.cold_disk_size_gb, hot_disk_size_gb = args.hot_disk_size_gb)
    
    if args.cmd == 'prepare_datasets':
        prepare_datasets(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone)
