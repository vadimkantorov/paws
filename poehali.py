import os
import datetime
import json
import time
import random
import string
import argparse
import subprocess
import botocore
import boto3

po = 'poehali'
empty = [{}]

def N(name = '', resource = '', suffix = '', sep = '_'):
    return po + (sep + name if name else '') + (sep + resource if resource else '') + (sep + suffix if suffix else '')

def random_suffix():
    return ''.join(random.choices(string.ascii_uppercase.lower(), k = 4))

def TagSpecifications(resource, name = '', suffix = ''):
    return [dict(ResourceType = resource, Tags = [dict(Key = 'Name', Value = N(name = name, suffix = suffix)  )])] 

def setup(name, root, region, availability_zone, vpc_id = None, subnet_id = None, cold_disk_size_gb = 200, hot_disk_size_gb = 200, cidr_vpc = '192.168.0.0/16', cidr_public_internet = '0.0.0.0/0', iops = 100):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    print('- name is', name)
    print('- region is', region)
    print('- availability zone is', availability_zone)
    print('- root is', root)
    
    os.makedirs(root, exist_ok = True)

    ec2 = boto3.client('ec2', region_name = region)
    iam = boto3.client('iam', region_name = region)
    empty = [{}]

    key_path = os.path.join(root, name + '.pem')
    if not os.path.exists(key_path):
        print('- key does not exist, creating')
        try:
            key_pair = ec2.create_key_pair(KeyName = name)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
                key_pair = ec2.create_key_pair(KeyName = N(name = name, suffix = random_suffix()) )

        with open(key_path, 'w') as f:
            f.write(key_pair['KeyMaterial'])
        
        #os.chmod(os.path.join(root, name + '.pem'), 600)
        subprocess.call(['chmod', '600', os.path.join(root, name + '.pem')])

    print('- key at', key_path)

    if not vpc_id:
        vpc = (ec2.describe_vpcs(Filters = [dict(Name = 'tag:Name', Values = [po + '*'])])['Vpcs'] + empty)[0]
        if not vpc:
            print('- vpc not found, creating')
            try:
                vpc = ec2.create_default_vpc()['Vpc']
            except botocore.exceptions.ClientError as err:
                print(err)
                #TODO: filter out EC2-Classic not supporting default VPC
                vpc = ec2.create_vpc(CidrBlock = cidr_vpc, InstanceTenancy='default', TagSpecifications = TagSpecifications('vpc'))['Vpc']
        vpc_id = vpc['VpcId']
            
        security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc_id]), dict(Name = 'group-name', Values = [name])])['SecurityGroups'] + empty)[0]
        if not security_group:
            print('- security group not found, creating')
            security_group = ec2.create_security_group(GroupName = name, Description = name, VpcId = vpc_id, TagSpecifications = TagSpecifications('security-group'))
            ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpPermissions = [dict(IpProtocol = 'tcp', FromPort = 22, ToPort = 22, IpRanges = [dict(CidrIp = cidr_public_internet)])])
            print('- security group is', security_group['GroupId'])
    print('- vpc is', vpc_id)

    internet_gateway = (ec2.describe_internet_gateways(Filters = [dict(Name = 'attachment.vpc-id', Values = [vpc_id])])['InternetGateways'] + empty)[0]
    if not internet_gateway:
        print('- internet gateway not found, creating')
        internet_gateway = ec2.create_internet_gateway(TagSpecifications = TagSpecifications('internet-gateway'))['InternetGateway']
        ec2.attach_internet_gateway(InternetGatewayId = internet_gateway['InternetGatewayId'], VpcId = vpc_id)
    print('- internet gateway is', internet_gateway['InternetGatewayId'])

    if not subnet_id:
        subnet = (ec2.describe_subnets(Filters = [dict(Name = 'availability-zone', Values = [availability_zone]), dict(Name = 'tag:Name', Values = [po + '*'])])['Subnets'] + empty)[0]
        if not subnet:
            print('- subnet not found, creating')
            subnet = ec2.create_subnet(VpcId = vpc_id, AvailabilityZone = availability_zone, CidrBlock = cidr_vpc, TagSpecifications = TagSpecifications('subnet'))['Subnet']
            route_table_id = ec2.describe_route_tables(Filters = [dict(Name = 'association.subnet-id', Values = [subnet['SubnetId']])])['RouteTables'][0]['Associations'][0]['RouteTableId']
            print('- route table is', route_table_id)
            ec2.create_route(DestinationCidrBlock = cidr_public_internet, GatewayId = internet_gateway['InternetGatewayId'], RouteTableId = route_table_id)
        subnet_id = subnet['SubnetId']
    print('- subnet is', subnet_id)

    #policy_arn = [p for p in iam.list_policies(Scope = 'AWS', PathPrefix = '/service-role/')['Policies'] if p['PolicyName'] == 'AmazonEC2RoleforSSM'][0]['Arn']

    try:
        instance_profile = iam.get_instance_profile(InstanceProfileName = name)
    except iam.exceptions.NoSuchEntityException:
        print('- instance profile not found, creating') 
        trust_relationship_policy_document = dict(
            Version = '2012-10-17',
            Statement = dict(
                Effect = 'Allow',
                Principal = dict(Service = 'ec2.amazonaws.com'),
                Action = 'sts:AssumeRole'
            )
        )

        policy_document = dict(
            Version = '2012-10-17',
            Statement = [
                dict(
                    Effect = 'Allow',
                    Action = [
                        'ec2:AttachVolume',
                        'ec2:DetachVolume',
                    ],
                    Resource = ['arn:aws:ec2:*:*:volume/*', 'arn:aws:ec2:*:*:instance/*' ]
                ),
                
                dict(
                    Effect = 'Allow',
                    Action = [
                        'ec2:DescribeVolumes',
                        'ec2:DescribeVolumeAttribute',
                        'ec2:DescribeVolumeStatus',

                        'ec2:DescribeInstances',
                        'ec2:ReportInstanceStatus'
                    ],
                    Resource = "*"
                ),

                dict(
                    Effect = 'Allow',
                    Action = [
                        's3:ListBucket',
                        's3:CreateBucket',
                        's3:DeleteBucket',
                        's3:ListAllMyBuckets',
                        's3:GetBucketLocation'
                    ],
                    Resource = 'arn:aws:s3:::*'
                ),

                dict(
                    Effect = 'Allow',
                    Action = [
                        's3:PutObject',
                        's3:GetObject',
                        's3:DeleteObject',
                        's3:PutObjectAcl'
                    ],
                    Resource = 'arn:aws:s3:::*/*'
                )
            ]
        )
        
        role_arn = iam.create_role(RoleName = name, AssumeRolePolicyDocument = json.dumps(trust_relationship_policy_document))['Role']['Arn']
        print('- role is', role_arn)
        policy_arn = iam.create_policy(PolicyName = name, PolicyDocument = json.dumps(policy_document))['Policy']['Arn']
        print('- policy is', policy_arn)
        iam.attach_role_policy(RoleName = name, PolicyArn = policy_arn)
        instance_profile = iam.create_instance_profile(InstanceProfileName = name)
        iam.add_role_to_instance_profile(InstanceProfileName = name, RoleName = name)
    print('- instance profile is', instance_profile['InstanceProfile']['Arn'])

    disk_spec = dict(cold = ('datasets', cold_disk_size_gb), hot = ('experiments', hot_disk_size_gb))
    for disk_name, (suffix, gb) in disk_spec.items():
        disk = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name = name, suffix = suffix)])])['Volumes'] + empty)[0]
        if not disk:
            disk = dict(VolumeId = 'disabled')
            if gb:
                print('-', disk_name, '(', suffix, ') disk not found, creating', gb, 'gb')
                cold_disk = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = gb, Iops = iops, TagSpecifications = TagSpecifications('volume', name = name, suffix = suffix))
        print('-', disk_name, '(', suffix, ') disk is', disk['VolumeId'])

def run(region, availability_zone, name, instance_type = 't3.micro', image_name = 'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20210430', shutdown_after_init_script = False, env = {}, username = 'ubuntu'):
    print('- name is', name)
    print('- region is', region)
    print('- availability zone is', availability_zone)
    print('- instance type is', instance_type)
    print('- image name is', image_name)
    
    ec2 = boto3.client('ec2', region_name = region)
    
    vpc = (ec2.describe_vpcs(Filters = [dict(Name = 'tag:Name', Values = [po + '*'])])['Vpcs'] + empty)[0]
    subnet = (ec2.describe_subnets(Filters = [dict(Name = 'availability-zone', Values = [availability_zone]), dict(Name = 'tag:Name', Values = [po + '*'])])['Subnets'] + empty)[0]
    assert vpc and subnet
    print('- vpc is', vpc.get('VpcId'))
    print('- subnet is', subnet.get('SubnetId'))
    
    security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc['VpcId']]), dict(Name = 'group-name', Values = [name])])['SecurityGroups'] + empty)[0]
    image = (ec2.describe_images(Filters = [dict(Name = 'name', Values = [image_name])])['Images'] + empty)[0]
    assert security_group and image 
    print('- security group is', security_group.get('GroupId'))
    print('- image is', image.get('ImageId'))

    volume_cold = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'datasets')])])['Volumes'] + empty)[0]
    volume_hot = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'experiments')])])['Volumes'] + empty)[0]
    print('- volume cold is', volume_cold.get('VolumeId'))
    print('- volume hot is', volume_hot.get('VolumeId'))
    disk_spec = {
        **({f'/home/{username}/datasets'    : volume_cold['VolumeId'] } if volume_cold else {})
        **({f'/home/{username}/experiments' : volume_hot ['VolumeId'] } if volume_hot  else {})
    }
    
    init_script = '''#!/bin/bash -ex
    exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
    sudo apt update
    sudo apt install -y awscli
    '''
    
    for i, (mount_path, volume_id) in enumerate(disk_spec.items()):
        init_script += '''
    INSTANCEID=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
    VOLUMEID=${VOLUMEID}
    aws ec2 attach-volume --region ${REGION} --device /dev/nvme${DISKNUM}n1 --instance-id $INSTANCEID --volume-id $VOLUMEID
    aws ec2 wait volume-in-use --region ${REGION} --volume-ids $VOLUMEID
    MOUNTDEV=/dev/$(lsblk -o +SERIAL | grep ${VOLUMEID/-/} | awk '{print $1}')
    [ "$(sudo file -b -s $MOUNTDEV)" == "data" ] && sudo mkfs -t xfs $MOUNTDEV
    mkdir -p ${MOUNTPATH}
    sudo mount $MOUNTDEV ${MOUNTPATH}
    sudo chown -R ${USERNAME} ${MOUNTPATH}
    '''.replace('${REGION}', region).replace('${DISKNUM}', 1 + i).replace('${VOLUMEID}', volume_id).replace('${MOUNTPATH}', mount_path).replace('${USERNAME}', username)

    if shutdown_after_init_script:
        init_script += 'sudo shutdown'
    
    instance = ec2.run_instances(
        InstanceType = instance_type, 
        ImageId = image['ImageId'], 
        MinCount = 1, 
        MaxCount = 1, 
        KeyName = name, 
        Placement = dict(AvailabilityZone = availability_zone), 
        NetworkInterfaces = [dict(DeviceIndex = 0, Groups = [security_group['GroupId']], SubnetId = subnet['SubnetId'], AssociatePublicIpAddress = True)], 
        TagSpecifications = TagSpecifications('instance', name = name, suffix = 'micro'),
        IamInstanceProfile = dict(Name = name), 
        UserData = init_script,
    )['Instances'][0]
    print('- instance is', instance['InstanceId'])
    return instance['InstanceId']

def gpu(name, root, region, availability_zone):
    pass

def ps(region, name, root):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    print('- name is', name)
    print('- region is', region)
    print('- root is', root)
    print()
    
    os.makedirs(root, exist_ok = True)
    ec2 = boto3.client('ec2', region_name = region)
    
    #TODO: use Filters
    # https://github.com/aws/aws-cli/issues/4578
    filters = [dict(Name = 'tag:Name', Values = [po + '*'])]

    instances = [instance for reservation in ec2.describe_instances()['Reservations'] for instance in reservation['Instances']]
    for instance in instances:
        instance_name = ([tag['Value'] for tag in instance['Tags'] if tag['Key'] == 'Name'] + ['NoName'])[0]
        if not instance_name.startswith(po):
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
    print(ec2.terminate_instances(InstanceIds = [instance_id]))
    
def killall(region, name = None):
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    running_instances = [instance for reservation in ec2.describe_instances(Filters = [dict(Name = 'instance-state-name', Values = ['running'] ), dict(Name = 'tag:Name', Values = [N(name = name) + '_*'])]) ['Reservations'] for instance in reservation['Instances']]
    instance_ids = [instance['InstanceId'] for instance in running_instances]
    print('- instances terminating', instance_ids)
    if not instance_ids:
        return
    ec2.terminate_instances(InstanceIds = instance_ids)

def ssh(region, name, root, instance_id = None, username = 'ubuntu', scp = False):
    root = os.path.expanduser(os.path.join(root, '.' + po))
    print('- name is', name)
    print('- region is', region)
    print('- root is', root)
    ec2 = boto3.client('ec2', region_name = region)
    
    instance = {}
    if not instance_id:
        running_instances = [instance for reservation in ec2.describe_instances(Filters = [dict(Name = 'instance-state-name', Values = ['running'] ), dict(Name = 'tag:Name', Values = [N(name = name) + '_*'])]) ['Reservations'] for instance in reservation['Instances']]

        if len(running_instances) == 1:
            instance = running_instances[0]
        else:
            print('- running instances:', len(running_instances), ', cant autoselect.')
            print(running_instances)
            return
    else:
        instance = ([instance for reservation in ec2.describe_instances(InstanceIds = [instance_id])['Reservations'] for instance in reservation['Instances']] + empty )[0]
    
    print('- instance is', instance.get('InstanceId'))
    assert instance
    
    public_ip = instance.get('PublicIpAddress')
    print('- ip is', public_ip)
    assert public_ip

    cmd = ['ssh' if not scp else 'scp', '-o', 'StrictHostKeyChecking=no', '-i', os.path.join(root, name + '.pem'), f'{username}@{public_ip}']
    print(' '.join(c if ' ' not in c else f'"{c}"' for c in cmd))
    print()

    if not scp:
        subprocess.call(['chmod', '600', os.path.join(root, name + '.pem')])
        subprocess.call(cmd)

def help(region):
    print(f'https://console.aws.amazon.com/iam/home?region={region}')
    print(f'https://console.aws.amazon.com/vpc/home?region={region}#vpcs')
    print(f'https://console.aws.amazon.com/vpc/home?region={region}#subnets')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#KeyPairs')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Volumes')

def datasets(name, root, region, availability_zone):
    run(region = region, availability_zone = availability_zone, name = name, shutdown_after_init_script = True)

def blkdeactivate(region, name):
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    
    volume_ids_deleting, volume_ids_other = [], []

    #TODO: use Filters
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        volume_name = ([tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Name'] + ['NoName'])[0]
        if (name and volume_name.startswith(po + '_' + name)) or (not name and volume_name.startswith(po)):
            if volume['State'] == 'available':
                volume_ids_deleting.append(volume['VolumeId'])
                ec2.delete_volume(VolumeId = volume['VolumeId'])
            else:
                volume_ids_other.append(volume['VolumeId'])

    print('- volumes deleting:', volume_ids_deleting)
    print('- volumes other:', volume_ids_other)
            

def lsblk(region, name):
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        volume_name = ([tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Name'] + ['NoName'])[0]
        availability_zone = volume['AvailabilityZone']
        state = volume['State']
        volume_id = volume['VolumeId']
        size = volume['Size']

        print(f'[{name} := {volume_id} @ {availability_zone}]: {size} Gb, {state}')

def ls(region, name):
    print('- name is', name)
    print('- region is', region)
    s3 = boto3.client('s3', region_name = region)
    paginator_list_objects_v2 = s3.get_paginator('list_objects_v2')
    bucket_name_prefix = N(name = name).lower().replace('_', '-')
    buckets = s3.list_buckets()['Buckets']
    for bucket in buckets:
        if bucket['Name'].startswith(bucket_name_prefix):
            num_objects = sum(page['KeyCount'] for page in paginator_list_objects_v2.paginate(Bucket = bucket['Name'], Delimiter = '/'))
            print('- bucket is', 's3://' + bucket['Name'], '| file count is', num_objects)

def mkdir(region, name, suffix, retry = 5):
    print('- name is', name)
    print('- region is', region)
    s3 = boto3.client('s3', region_name = region)
    iam = boto3.client('iam', region_name = region)
    if suffix == '':
        suffix = random_suffix()

    bucket_name = N(name = name, suffix = suffix).lower().replace('_', '-')
    print('- bucket name is', bucket_name)
    
    if any(bucket['Name'] == bucket_name for bucket in s3.list_buckets()['Buckets']):
        return print('- bucket exists, quitting')
    
    bucket_configuration_kwargs = dict(CreateBucketConfiguration = dict(LocationConstraint = region)) if not region.startswith('us-east-1') else {}
    bucket = s3.create_bucket(Bucket = bucket_name, **bucket_configuration_kwargs)
    print('- bucket is', 's3:/' + bucket['Location'])
    print('- listing is', f'https://s3.amazonaws.com/{bucket_name}/')
    
    iam_username = name
    try:
        user = iam.get_user(UserName = iam_username)['User']
    except:
        print('- user does not exist, creating')
        user = iam.create_user(UserName = iam_username)['User']
        access_key = iam.create_access_key(UserName = iam_username)['AccessKey']
        print('- access key is', access_key['AccessKeyId']) 
        cmd = 'AWS_ACCESS_KEY_ID="{AccessKeyId}" AWS_SECRET_ACCESS_KEY="{SecretAccessKey}" AWS_REGION="{region}" AWS_DEFAULT_OUTPUT="json" aws s3 ls s3:/{Location}'.format(region = region, **access_key, **bucket)
        print('- test command is\n\n', cmd, '\n')
    print('- user is', user['Arn'])

    bucket_policy = dict(
        Version= '2012-10-17',
        Statement= [
            dict(
                Sid = 'FullAccess',
                Effect = 'Allow',
                Principal = dict(AWS = user['Arn']),
                Action = 's3:*',
                Resource =  [f'arn:aws:s3:::{bucket_name}/*', f'arn:aws:s3:::{bucket_name}'],
            ),

            dict(
                Sid = 'PublicList',
                Effect = 'Allow',
                Principal = '*',
                Action = 's3:ListBucket',
                Resource = f'arn:aws:s3:::{bucket_name}',
            ),

            dict(
                Sid = 'PublicGet',
                Effect = 'Allow',
                Principal = '*',
                Action = 's3:GetObject',
                Resource = [f'arn:aws:s3:::{bucket_name}/public/*', f'arn:aws:s3:::{bucket_name}/index.html'],
            )
        ]
    )
    for k in range(retry):
        try:
            # policy = iam.create_policy(PolicyName=policy_name, PolicyDocument=json.dumps(bucket_policy))
            # print(iam.attach_user_policy(UserName=iam_username, PolicyArn=policy['Policy']['Arn']))
            s3.put_bucket_policy(Bucket = bucket_name, Policy = json.dumps(bucket_policy))
        except Exception as e:
            if 'Invalid principal in policy' in str(e):
                print('- bucket policy retry')
                time.sleep(retry)
                continue
            else:
                raise
        print('- bucket policy set')
        break
    
    s3.put_object(ACL = 'public-read', Body = b'<html><b>Hello world (public)!<b></html>', Bucket = bucket_name, Key = 'public/index.html', ContentType = 'text/html')
    s3.put_object(ACL = 'public-read', Body = b'<html>Error (public)</html>', Bucket = bucket_name, Key = 'public/error.html', ContentType = 'text/html')
    s3.put_bucket_website(Bucket = bucket_name, WebsiteConfiguration = dict(ErrorDocument = dict(Key = 'public/error.html'), IndexDocument = dict(Suffix = 'index.html')))

    public_url = f'http://{bucket_name}.s3-website-{region}.amazonaws.com/public'
    print('- public is', public_url)

def rmdir(region, name, suffix):
    print('- name is', name)
    print('- region is', region)
    s3 = boto3.client('s3', region_name = region)
    paginator_list_objects_v2 = s3.get_paginator('list_objects_v2')
    bucket_name = N(name = name, suffix = suffix).lower().replace('_', '-')
    print('- bucket deleting', bucket_name)
    
    for page in paginator_list_objects_v2.paginate(Bucket=bucket_name, Delimiter='/'):
        keys = [c['Key'] for c in page['Contents']]
        deleted = s3.delete_objects(Bucket = bucket_name, Delete = dict(Objects = [dict(Key = key) for key in keys]))['Deleted']
        print('- files deleting', ['s3://' + bucket_name + '/' + k['Key'] for k in deleted])

    s3.delete_bucket(Bucket = bucket_name)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--region', default = 'us-east-1')
    parser.add_argument('--availability-zone', default = 'us-east-1a')
    parser.add_argument('--username', default = 'ubuntu')
    parser.add_argument('--vpc-id')
    parser.add_argument('--subnet-id')
    parser.add_argument('--instance-id')
    parser.add_argument('--root', default = '~')
    parser.add_argument('--name'  , default = 'poehalitest80')
    parser.add_argument('--suffix')
    parser.add_argument('cmd', choices = ['help', 'ps', 'lsblk', 'blkdeactivate', 'kill', 'killall', 'ssh', 'scp', 'setup', 'micro', 'datasets', 'mkdir', 'ls', 'rmdir'])
    parser.add_argument('--cold-disk-size-gb', type = int, default = 0)
    parser.add_argument('--hot-disk-size-gb', type = int, default = 0)
    args = parser.parse_args()
    
    if args.cmd == 'help':
        help(region = args.region)
    
    if args.cmd == 'kill':
        kill(region = args.region, instance_id = args.instance_id)
    
    if args.cmd == 'killall':
        killall(region = args.region, name = args.name)
    
    if args.cmd == 'ps':
        ps(region = args.region, name = args.name, root = args.root)
    
    if args.cmd == 'lsblk':
        lsblk(region = args.region, name = args.name)
    
    if args.cmd == 'blkdeactivate':
        blkdeactivate(region = args.region, name = args.name)
    
    if args.cmd == 'ssh':
        ssh(region = args.region, name = args.name, root = args.root, instance_id = args.instance_id)
    
    if args.cmd == 'scp':
        ssh(region = args.region, name = args.name, root = args.root, instance_id = args.instance_id, scp = True)

    if args.cmd == 'setup':
        setup(name = args.name, region = args.region, root = args.root, availability_zone = args.availability_zone, vpc_id = args.vpc_id, cold_disk_size_gb = args.cold_disk_size_gb, hot_disk_size_gb = args.hot_disk_size_gb)
    
    if args.cmd == 'micro':
        instance_id = run(name = args.name, region = args.region, availability_zone = args.availability_zone, instance_type = 't3.micro', username = args.username)
        ssh(name = args.name, region = args.region, root = args.root, instance_id = instance_id, username = args.username)
    
    if args.cmd == 'datasets':
        datasets(name = args.name, region = args.region, availability_zone = args.availability_zone)

    if args.cmd == 'mkdir':
        mkdir(name = args.name, region = args.region, suffix = args.suffix)
    
    if args.cmd == 'rmdir':
        rmdir(name = args.name, region = args.region, suffix = args.suffix)
    
    if args.cmd == 'ls':
        ls(name = args.name, region = args.region)

    # tar -c ./myfiles | aws s3 cp - s3://my-bucket/myobject"
    # https://docs.aws.amazon.com/cli/latest/topic/s3-config.html
    # https://www.linkedin.com/pulse/aws-s3-multipart-uploading-milind-verma
    # https://www.slideshare.net/AmazonWebServices/deep-dive-aws-command-line-interface-50367179
    # export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    # export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    # export AWS_DEFAULT_REGION=us-west-2
    # https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-envvars.html
