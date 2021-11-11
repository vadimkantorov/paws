import os
import datetime
import json
import argparse
import subprocess
import boto3

def N(name, resource = '', suffix = ''):
    return 'poehali_' + name + ('_' + resource if resource else '') + ('_' + suffix if suffix else '')

def T(name, resource, suffix = ''):
    return [dict(ResourceType = resource, Tags = [dict(Key = 'Name', Value = name + ('_${suffix}' if suffix else '')  )])] 

def read_text(root, name):
    with open(os.path.join(root, name), 'r') as f:
        return f.read()

def write_text(root, name, text):
    with open(os.path.join(root, name), 'w') as f:
        f.write(text)
    print('Written to', os.path.join(root, name))

def write_json(root, name, obj):
    write_text(root, name, json.dumps(obj, indent = 2, default = json_converter))

def json_converter(o):
    if isinstance(o, datetime.datetime):
        return o.__str__()

def setup(name, root, region, availability_zone, vpc_id = None):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    iam = boto3.client('iam', region_name = region)

    key_pair = ec2.create_key_pair(KeyName = name) # err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate'
    write_text(root, 'key.pem', key_pair['KeyMaterial'])
    
    cidr_vpc = '192.168.0.0/16'
    
    if vpc_id is None:
        try:
            vpc = ec2.create_default_vpc()['Vpc']
            vpc_id = vpc['VpcId'])
        except:
            vpc_id_global = os.path.join(root, '../vpc_id.txt')
            if os.path.exists(vpc_id_global):
                vpc_id = read_text(vpc_id_global)
            else:
                vpc = ec2.create_vpc(CidrBlock = cidr_vpc, InstanceTenancy='default', TagSpecifications = T(name, 'vpc'))['Vpc']
                vpc_id = vpc['VpcId'])
                write_text(root, '../vpc_id.txt', vpc_id)

    write_text(root, 'vpc_id.txt', vpc_id)

    subnet = ec2.create_subnet(VpcId = vpc_id, AvailabilityZone = availability_zone, CidrBlock = cidr_vpc, TagSpecifications = T(name, 'subnet'))['Subnet']
    write_text(root, 'subnet_id.txt', subnet['SubnetId'])
    
    security_group = ec2.create_security_group(GroupName = name, Description = name)
    write_text(root, 'security_group_id.txt', security_group['GroupId'])

    cidr_public_internet = '0.0.0.0/0'
    security_group_authorized_ssh = ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpProtocol = 'tcp', FromPort = 22, ToPort = 22, CidrIp = cidr_public_internet)
    write_json(root, 'security_group_authorized_ssh.txt', security_group_authorized_ssh)

    policy_arn = [p for p in iam.list_policies(Scope = 'AWS', PathPrefix = '/service-role/')['Policies'] if p['PolicyName'] == 'AmazonEC2RoleforSSM'][0]['Arn']

    policy_document = dict(
        Version = '2012-10-17',
        Statement = dict(
            Effect = 'Allow',
            Principal = dict(Service = 'ec2.amazonaws.com'),
            Action = 'sts:AssumeRole'
        )
    )

    role_created = iam.create_role(RoleName = name, AssumeRolePolicyDocument = json.dumps(policy_document))
    write_json(root, 'role_created.txt', role_created)

    role_attached = iam.attach_role_policy(RoleName = name, PolicyArn = policy_arn)
    write_json(root, 'role_attached.txt', role_attached)

    instance_profile_created = iam.create_instance_profile(InstanceProfileName = name)
    write_json(root, 'instance_profile_created.txt', instance_profile_created)

    role_added_to_instance_profile = iam.add_role_to_instance_profile(InstanceProfileName = name, RoleName = name)
    write_json(root, 'role_added_to_instance_profile.txt', role_added_to_instance_profile)

def setup_disks(name, root, region, availability_zone, cold_disk_size_gb, hot_disk_size_gb, iops = 100):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    cold_disk_created = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = cold_disk_size_gb, Iops = iops, TagSpecifications = T(name, 'volume', 'datasets'))
    write_json(root, 'cold_disk_created.txt', cold_disk_created)
    write_text(root, 'cold_disk_volume_id.txt', cold_disk_created['VolumeId'])
    
    hot_disk_created = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = hot_disk_size_gb, Iops = iops, TagSpecifications = T(name, 'volume', 'experiments'))
    write_json(root, 'hot_disk_created.txt', hot_disk_created)
    write_text(root, 'hot_disk_volume_id.txt', hot_disk_created['VolumeId'])

def download_datasets(name, root, region, availability_zone, instance_type = 't2.micro', image_name = 'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20210430'):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)

    volume_id = read_text(root, 'cold_disk_volume_id.txt')
    security_group_id = read_text(root, 'security_group_id.txt')
    subnet_id = read_text(root, 'subnet_id.txt')

    images = ec2.describe_images(Filters = [dict(Name = 'name', Values = [image_name])])
    image_id = images['Images'][0]['ImageId']

    launch_script = '''#!/bin/bash -xe

    INSTANCEID=$(curl -s http://instance-data/latest/meta-data/instance-id)

    VOlUMEID=$(aws ec2 describe-volumes --region $REGION --filters Name=tag:Name,Values=$VOLUMENAME --query Volumes[].VolumeId --output text)

    aws ec2 attach-volume --device /dev/xvdf --instance-id $INSTANCEID --volume-id $VOLUMEID

    DATASTATE="unknown"
    until [ "$DATASTATE" == "attached" ]; do
      DATASTATE=$(aws ec2 describe-volumes --region $REGION --filters Name=attachment.instance-id,Values=$INSTANCEID Name=attachment.device,Values=/dev/xvdh --query Volumes[].Attachments[].State --output text)
      sleep 5
    done

    if [ "$(file -b -s /dev/xvdh)" == "data" ]; then
      mkfs -t xfs /dev/xvdh
    fi
    '''.replace('$REGION', region).replace('$VOLUMENAME', name + '_datasets')

    #mkdir ~/datasets
    #sudo mount /dev/nvme2n1 ~/datasets

    cold_instance_run = ec2.run_instances(
        InstanceType = instance_type, 
        ImageId = image_id, 
        MinCount = 1, 
        MaxCount = 1, 
        KeyName = name, 
        IamInstanceProfile = dict(Name = name), 
        Placement = dict(AvailabilityZone = availability_zone), 
        NetworkInterfaces = [dict(DeviceIndex = 0, Groups = [security_group_id], SubnetId = subnet_id, AssociatePublicIpAddress = True)], 
        TagSpecifications = T(name, 'instance', 'datasets'),
        UserData = launch_script,
    )
    # SecurityGroupIds = [security_group_id]
    #write_text(root, 'cold_instance_run.txt', json.dumps(cold_instance_run, indent = 2, default = json_converter))
    
    #cold_disk_attached = ec2.attach_volume(InstanceId = instance_id, Device = '/dev/xvdf', VolumeId = volume_id)
    #write_text(root, 'cold_disk_attached.txt', json.dumps(cold_disk_attached, indent = 2, default = json_converter))

def destroy(name):
    pass

def data():
    pass

def ps(name, region, root):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    instances = ec2.describe_instances()
    print(instances)

def ls(name, region, root):
    root = os.path.expanduser(os.path.join(root, '.poehali', name))
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        availability_zone = volume['AvailabilityZone']
        size = volume['Size']
        name = [tag['Value'] for tag in volume['Tags'] if tag['Key'] == 'Name'][0]
        volume_id = volume['VolumeId']
        state = volume['State']

        print(f'[{name} := {volume_id} @ {availability_zone}]: {size} Gb, {state}')

    if not volumes:
        print(f'No volumes @ {region}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default = 'us-east-1')
    parser.add_argument('--availability-zone', default = 'us-east-1a')
    parser.add_argument('--cold-disk-size-gb', type = int, default = 50)
    parser.add_argument('--name', default = 'poehalitest29')
    parser.add_argument('--root', default = '~')
    parser.add_argument('--vpc-id', default = '')
    parser.add_argument('cmd', choices = ['ps', 'ls', 'setup', 'setup_cold_disk', 'data', 'download_datasets'])
    args = parser.parse_args()
    
    if args.cmd == 'ps':
        ps(name = args.name, region = args.region, root = args.root)
    
    if args.cmd == 'ls':
        ls(name = args.name, region = args.region, root = args.root)

    if args.cmd == 'setup':
        setup(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone, vpc_id = args.vpc_id)
    
    if args.cmd == 'setup_disks':
        setup_cold_disk(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone, cold_disk_size_gb = args.cold_disk_size_gb)
    
    if args.cmd == 'download_datasets':
        download_datasets(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone)
