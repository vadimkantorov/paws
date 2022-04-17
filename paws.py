import os
import datetime
import json
import time
import base64
import random
import string
import argparse
import subprocess
import botocore
import boto3

paws_prefix = 'paws'

empty = [{}]

def N(name = '', resource = '', suffix = '', sep = '_'):
    if not name and not resource and not suffix:
        return paws_prefix + sep

    return paws_prefix + (sep + name if name else '') + (sep + resource if resource else '') + (sep + suffix if suffix else '')

def R(root):
    return os.path.abspath(os.path.expanduser(os.path.join(root, '.' + paws_prefix))) if not root.startswith('/') else root 

def random_suffix():
    return ''.join(random.choices(string.ascii_uppercase.lower(), k = 4))

def TagSpecifications(resource, name = '', suffix = ''):
    return [dict(ResourceType = resource, Tags = [dict(Key = 'Name', Value = N(name = name, suffix = suffix)  )])] 

def setup(name, root, region, availability_zone, cold_disk_size_gb = 200, hot_disk_size_gb = 200, cidr_public_internet = '0.0.0.0/0', iops = 100, cold_bucket = False, hot_bucket = False, **ignored):
    root = R(root)
    print('- name is', name)
    print('- region is', region)
    print('- availability zone is', availability_zone)
    print('- root is', root)
    
    os.makedirs(root, exist_ok = True)

    ec2 = boto3.client('ec2', region_name = region)
    iam = boto3.client('iam', region_name = region)

    vpc = (ec2.describe_vpcs(Filters = [dict(Name = 'is-default', Values = ['true'])])['Vpcs'] + empty)[0]
    assert vpc
    vpc_id = vpc['VpcId']
    
    print('- vpc is', vpc_id)
    security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc_id]), dict(Name = 'group-name', Values = [paws_prefix])])['SecurityGroups'] + empty)[0]
    if not security_group:
        print('- security group not found, creating')
        security_group = ec2.create_security_group(GroupName = paws_prefix, Description = paws_prefix, VpcId = vpc_id, TagSpecifications = TagSpecifications('security-group', name = paws_prefix))
        ec2.authorize_security_group_ingress(GroupId = security_group['GroupId'], IpPermissions = [dict(IpProtocol = 'tcp', FromPort = 22, ToPort = 22, IpRanges = [dict(CidrIp = cidr_public_internet)])])
    print('- security group is', security_group['GroupId'])
    
    sshkey_path = os.path.join(root, f'{name}_{region}.pem')
    if not os.path.exists(sshkey_path):
        print('- key does not exist, creating')
        key_name = N(name = name)
        try:
            key_pair = ec2.create_key_pair(KeyName = key_name)
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'InvalidKeyPair.Duplicate':
                key_name = N(name = name, suffix = random_suffix())
                key_pair = ec2.create_key_pair(KeyName = key_name)

        with open(sshkey_path, 'w') as f:
            f.write(key_pair['KeyMaterial'])
        
        #os.chmod(sshkey_path, 600)
        subprocess.call(['chmod', '600', sshkey_path])

    print('- key at', sshkey_path)
    
    iamkey_path = sshkey_path.replace('.pem', '.ini')
    iam_name = N(name = name)
    try:
        user = iam.get_user(UserName = iam_name)['User']
    except:
        print('- user does not exist, creating')
        user = iam.create_user(UserName = iam_name)['User']
        access_key = iam.create_access_key(UserName = iam_name)['AccessKey']
        print('- access key is', access_key['AccessKeyId'])
        
        with open(iamkey_path, 'w') as f:
            f.write('[default]\naws_access_key_id = {AccessKeyId}\naws_secret_access_key = {SecretAccessKey}\n'.format(**access_key))
            
    print('- user is', user['Arn'])
    print('- access key backup is', iamkey_path)
    print('- waiting for user to exist')
    iam.get_waiter('user_exists').wait(UserName = iam_name)

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
        
        role_arn = iam.create_role(RoleName = iam_name, AssumeRolePolicyDocument = json.dumps(trust_relationship_policy_document))['Role']['Arn']
        print('- role is', role_arn)
        policy_arn = iam.create_policy(PolicyName = iam_name, PolicyDocument = json.dumps(policy_document))['Policy']['Arn']
        print('- policy is', policy_arn)
        iam.attach_role_policy(RoleName = iam_name, PolicyArn = policy_arn)
        instance_profile = iam.create_instance_profile(InstanceProfileName = iam_name)
        iam.add_role_to_instance_profile(InstanceProfileName = iam_name, RoleName = iam_name)
    print('- instance profile is', instance_profile['InstanceProfile']['Arn'])

    bucket_spec = dict(cold = cold_bucket, hot = hot_bucket)
    for bucket_suffix, enabled in bucket_spec.items():
        if enabled:
            mkdir(name = name, region = region, suffix = bucket_suffix, root = root)
        else:
            print('- bucket is disabled', bucket_suffix)

    disk_spec = dict(cold = cold_disk_size_gb, hot = hot_disk_size_gb)
    for bucket_suffix, gb in disk_spec.items():
        disk = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name = name, suffix = bucket_suffix)])])['Volumes'] + empty)[0]
        if not disk:
            disk = dict(VolumeId = 'disabled')
            if gb:
                print('-', suffix, 'disk not found, creating', gb, 'gb')
                disk = ec2.create_volume(VolumeType = 'io1', MultiAttachEnabled = True, AvailabilityZone = availability_zone, Size = gb, Iops = iops, TagSpecifications = TagSpecifications('volume', name = name, suffix = bucket_suffix))
        print('- disk', bucket_suffix, 'is', disk['VolumeId'])

def run(
        region, 
        availability_zone, 
        name, 
        instance_type = 't3.micro', 
        image_name = 'ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-20210430', 
        shutdown = False, 
        username = 'ubuntu', 
        env_path = None, 
        env = {}, 
        git_clone = None, 
        git_tag = None, 
        git_key_path = None, 
        working_dir = None, 
        ssh_when_running = False, 
        hot_bucket_sync_dir = None, 
        verbose = False, 
        dry = False, 
        conda = True,
        conda_installer_name = None,

        shell = '/bin/bash',

        job_script,
        job_script_embed,
        job_command,

        requirements_script,
        requirements_script_embed,
        requirements_command,

        data_script,
        data_script_embed,
        data_command,

        pip_requirements,
        pip_requirements_embed,
        pip_install_packages,

        apt_install_packages,
        
        **ignored
    ):
    #TODO: support expiration
    print('- name is', name)
    print('- region is', region)
    print('- availability zone is', availability_zone)
    print('- instance type is', instance_type)
    print('- image name is', image_name)
    
    ec2 = boto3.client('ec2', region_name = region)
        
    subnet = (ec2.describe_subnets(Filters = [dict(Name = 'availability-zone', Values = [availability_zone]), dict(Name = 'default-for-az', Values = ['true'])])['Subnets'] + empty)[0]
    assert subnet
    print('- subnet is', subnet.get('SubnetId'))
    
    security_group = (ec2.describe_security_groups(Filters = [dict(Name = 'vpc-id', Values = [vpc['VpcId']]), dict(Name = 'group-name', Values = [paws_prefix])])['SecurityGroups'] + empty)[0]
    image = (ec2.describe_images(Filters = [dict(Name = 'name', Values = [image_name])])['Images'] + empty)[0]
    assert security_group and image 
    print('- security group is', security_group.get('GroupId'))
    print('- image is', image.get('ImageId'))

    volume_cold= (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name, 'cold')])])['Volumes'] + empty)[0]
    volume_hot = (ec2.describe_volumes(Filters = [dict(Name = 'tag:Name', Values = [N(name,  'hot')])])['Volumes'] + empty)[0]
    print('- volume cold is', volume_cold.get('VolumeId'))
    print('- volume hot is',  volume_hot .get('VolumeId'))
    disk_spec = {
        **({f'/home/{username}/cold': volume_cold['VolumeId'] } if volume_cold else {})
        **({f'/home/{username}/hot' : volume_hot ['VolumeId'] } if volume_hot  else {})
    }
    
    init_script = f'''#!{shell}
    set -ex
    exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
    sudo apt update
    sudo apt install -y awscli git wget
    curl -s http://169.254.169.254/latest/user-data > /home/{username}/initscript.sh
    '''
    
    if apt_install_packages:
        init_script += 'sudo apt install -y {pkgs}'.format(pkgs = ' '.join(apt_install_packages))
    
    init_script += f'export AWS_REGION="{region}\n'

    if env_path:
        with open(env_path) as f:
            init_script += f.read() + '\n'
    init_script += '\n'.join(f'export {k}="{v}"' for k, v in env.items()) + '\n'
    
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

    if job_script:
        if job_script_embed:
            with open(job_script) as f:
                job_command += f.read() + '\n'
        else:
            job_command += f'{shell} "{job_script}"\n'


    preamble = []

    if conda and conda_installer_name:
        preamble.extend([
            'PREFIX=$(realpath prefix)', 
            'export PATH=$PREFIX/miniconda/bin:$PATH',
            f'curl -L -so ./miniconda.sh https://repo.anaconda.com/miniconda/{conda_installer_name} && chmod +x miniconda.sh && ./miniconda.sh -b -p $PREFIX/miniconda && rm ./miniconda.sh'
        ])

    if git_clone:
        working_dir = working_dir or os.path.basename(git_clone.replace('.git', ''))
        
        if git_key_path and os.path.exists(git_key_path):
            with open(git_key_path, 'rb') as f:
                git_key_base64 = base64.b64encode(f.read()).decode()

            git_key_path = '~/.ssh/id_rsa_git' 
            preamble.extend(['echo "{git_key_base64}" | base64 --decode > {git_key_path}', f'export GIT_SSH_COMMAND="ssh -i {git_key_path} -o IdentitiesOnly=yes"'])

        preamble.append('git clone --single-branch --depth 1' + (f' --branch "{git_tag}" ' if git_tag else '') + ' "{git_clone}"')

    if working_dir:
        preamble.append(f'cd "{working_dir}"')

    if pip_install_packages:
        preamble.append('python -m pip install ' +  ' '.join(pip_install_packages))

    if pip_requirements:
        if pip_requirements_embed:
            preamble.append('python -m pip install -r /dev/stdin <<EOF')
            with open(pip_requirements) as f:
                preamble.extend(f.readlines())
            preamble.extend(['EOF', ')'])
        else:
            preamble.append(f'python -m pip install -r "{pip_requirements}"')
    
    if requirements_script:
        if requirements_script_embed:
            with open(requirements_script_embed) as f:
                requirements_scommand += f.read() + '\n'
        else:
            requirements_command += f'{shell} "{requirements_script}"\n'
    preamble.append(requirements_command)
    
    if data_script:
        if data_script_embed:
            with open(data_script_embed) as f:
                data_scommand += f.read() + '\n'
        else:
            data_command += f'{shell} "{data_script}"\n'
    preamble.append(data_command)

    job_command = '\n'.join(preamble) + '\n\n' + job_command

    if job_command:
        init_script += f'''
    set +e
    sudo -i -u {username} {shell} - << EOF
    {job_command}
    EOF
    set -e
    '''

    if hot_bucket_sync_dir:
        bucket_name = N(name = name, suffix = 'suffix').lower().replace('_', '-')
        init_script += f'[ -f "{hot_bucket_sync_dir}" ] && aws s3 sync --region ${region} "{hot_bucket_sync_dir}" "s3://{bucket_name}"\n'

    if shutdown:
        init_script += 'sudo shutdown\n'
    
    if verbose:
        print(init_script)

    if dry:
        return

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

    if ssh_when_running:
        ssh(region = region, name = name, root = root, instance_id = instance['InstanceId'], username = username)
    
    return instance['InstanceId']

def ps(region, name, root, **ignored):
    root = R(root)
    print('- name is', name)
    print('- region is', region)
    print('- root is', root)
    print()
    
    ec2 = boto3.client('ec2', region_name = region)
    
    #TODO: print instance tags

    #TODO: use Filters
    # https://github.com/aws/aws-cli/issues/4578
    filters = [dict(Name = 'tag:Name', Values = [paws_prefix + '*'])]

    instances = [instance for reservation in ec2.describe_instances()['Reservations'] for instance in reservation['Instances']]
    for instance in instances:
        instance_name = ([tag['Value'] for tag in instance['Tags'] if tag['Key'] == 'Name'] + ['NoName'])[0]
        if not instance_name.startswith(paws_prefix):
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

def kill(region, instance_id, **ignored):
    ec2 = boto3.client('ec2', region_name = region)
    print(ec2.terminate_instances(InstanceIds = [instance_id]))
    
def killall(region, name = None, **ignored):
    # TODO; detach volumes before termination?
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    running_instances = [instance for reservation in ec2.describe_instances(Filters = [dict(Name = 'instance-state-name', Values = ['running'] ), dict(Name = 'tag:Name', Values = [N(name = name) + '_*'])]) ['Reservations'] for instance in reservation['Instances']]
    instance_ids = [instance['InstanceId'] for instance in running_instances]
    print('- instances terminating', instance_ids)
    if not instance_ids:
        return
    ec2.terminate_instances(InstanceIds = instance_ids)

def ssh(region, name, root, instance_id = None, username = 'ubuntu', scp = False, **ignored):
    root = R(root)
    print('- name is', name)
    print('- region is', region)
    print('- root is', root)
    ec2 = boto3.client('ec2', region_name = region)

    key_path = os.path.join(root, f'{name}_{region}.pem')
    
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
    
    print('- waiting until instance is running')
    ec2.get_waiter('instance_running').wait(InstanceIds = [instance['InstanceId']])
    print('- waiting until instance has available network interface')
    ec2.get_waiter('network_interface_available').wait(InstanceIds = [instance['InstanceId']])
    
    public_ip = instance.get('PublicIpAddress')
    print('- ip is', public_ip)
    #TODO: implement waiting for public IP and for disks ready
    assert public_ip

    cmd = ['ssh' if not scp else 'scp', '-o', 'StrictHostKeyChecking=no', '-i', key_path, f'{username}@{public_ip}']
    print(' '.join(c if ' ' not in c else f'"{c}"' for c in cmd))
    print()

    if not scp:
        subprocess.call(['chmod', '600', key_path])
        subprocess.call(cmd)

def help(region, **ignored):
    print(f'https://console.aws.amazon.com/iam/home?region={region}')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#KeyPairs')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances')
    print(f'https://console.aws.amazon.com/ec2/v2/home?region={region}#Volumes')

def blkdeactivate(region, name, **ignored):
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    
    volume_ids_deleting, volume_ids_other = [], []

    #TODO: use Filters
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        volume_name = ([tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Name'] + ['NoName'])[0]
        if (name and volume_name.startswith(paws_prefix + '_' + name)) or (not name and volume_name.startswith(paws_prefix)):
            if volume['State'] == 'available':
                volume_ids_deleting.append(volume['VolumeId'])
                ec2.delete_volume(VolumeId = volume['VolumeId'])
            else:
                volume_ids_other.append(volume['VolumeId'])

    print('- volumes deleting:', volume_ids_deleting)
    print('- volumes other:', volume_ids_other)
            

def lsblk(region, name, **ignored):
    print('- name is', name)
    print('- region is', region)
    ec2 = boto3.client('ec2', region_name = region)
    
    #TODO: filter by name, maybe with filters
    volumes = ec2.describe_volumes()['Volumes']
    for volume in volumes:
        volume_name = ([tag['Value'] for tag in volume.get('Tags', []) if tag['Key'] == 'Name'] + ['NoName'])[0]
        availability_zone = volume['AvailabilityZone']
        state = volume['State']
        volume_id = volume['VolumeId']
        size = volume['Size']

        print(f'[{name} := {volume_id} @ {availability_zone}]: {size} Gb, {state}')

def ls(region, name, **ignored):
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

def mkdir(region, name, suffix, retry = 5, root = None, **ignored):
    print('- name is', name)
    print('- region is', region)
    s3 = boto3.client('s3', region_name = region)
    iam = boto3.client('iam', region_name = region)
    if suffix == '':
        suffix = random_suffix()
    print('- waiting for iam user to exist')
    bucket_name = N(name = name, suffix = suffix).lower().replace('_', '-')
    print('- bucket name is', bucket_name)
    
    if any(bucket['Name'] == bucket_name for bucket in s3.list_buckets()['Buckets']):
        return print('- bucket exists', 's3://' + bucket_name, ', quitting')
    
    iam_name = N(name = name)
    try:
        user = iam.get_user(UserName = iam_name)['User']
    except:
        return print('- user does not exist, quitting')

    iam.get_waiter('user_exists').wait(UserName = iam_name)
    print('- user is', user['Arn'])
    
    bucket_configuration_kwargs = dict(CreateBucketConfiguration = dict(LocationConstraint = region)) if not region.startswith('us-east-1') else {}
    bucket = s3.create_bucket(Bucket = bucket_name, **bucket_configuration_kwargs)
    print('- bucket is', 's3:/' + bucket['Location'])
    print('- listing is', f'https://s3.amazonaws.com/{bucket_name}/')
    
    if root:
        root = R(root)
        iamkey_path = os.path.join(root, f'{name}_{region}.ini')
        if os.path.exists(iamkey_path):
            with open(iamkey_path) as f:
                access_key_ini = dict(line.strip().split(' = ') for line in f.read().split('\n')[1:3])
        else:
            iamkey_path = os.path.basename(iamkey_path)
            access_key_ini = dict(aws_access_key_id = f'<{iamkey_path} not found>', aws_secret_access_key = f'<{iamkey_path} not found>')

        cmd = 'AWS_ACCESS_KEY_ID="{aws_access_key_id}" AWS_SECRET_ACCESS_KEY="{aws_secret_access_key}" AWS_REGION="{region}" AWS_DEFAULT_OUTPUT="json" aws s3 ls s3:/{Location}'.format(region = region, **access_key_ini, **bucket)
        print('- test command is\n\n', cmd, '\n')
    
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
            # print(iam.attach_user_policy(UserName=name, PolicyArn=policy['Policy']['Arn']))
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
    print('- public site is', public_url)

def rm(region, name, suffix = None, **ignored):
    print('- name is', name)
    print('- region is', region)
    s3 = boto3.client('s3', region_name = region)
    paginator_list_objects_v2 = s3.get_paginator('list_objects_v2')
    bucket_name = N(name = name, suffix = suffix).lower().replace('_', '-')
    print('- bucket deleting', bucket_name)
    
    for page in paginator_list_objects_v2.paginate(Bucket = bucket_name, Delimiter = '/'):
        keys = [c['Key'] for c in page['Contents']]
        deleted = s3.delete_objects(Bucket = bucket_name, Delete = dict(Objects = [dict(Key = key) for key in keys]))['Deleted']
        print('- files deleting', ['s3://' + bucket_name + '/' + k['Key'] for k in deleted])

    s3.delete_bucket(Bucket = bucket_name)

def clean(region, name, root, delete_data, **ignored):
    if input('Please type in [iunderstanddanger]: ') != 'iunderstanddanger':
        return print('- confirmation not received, quitting')
    
    print('- confirmation received')
    
    root = R(root)
    print('- name is', name)
    print('- region is', region)
    print('- root is', root)
    print()
    
    ec2 = boto3.client('ec2', region_name = region)
    iam = boto3.client('iam', region_name = region)

    killall(region = region, name = name)
    
    if delete_data:
        #TODO: retry multiple times
        blkdeactivate(region = region, name = name)
        rm(region = reigon, name = name)

    key_pair_names = [key['Name'] for key in ec2.describe_key_pairs(Filters = [dict(Name = 'tag:Name', Values = [N(name = name) + '*'])])['KeyPairs']]
    if not name:
        key_pair_names = [key['Name'] for key in ec2.describe_keypairs(Filters = [dict(Name = 'tag:Name', Values = [paws_prefix + '*'])])['KeyPairs']]
        
        for security_group in ec2.describe_security_groups(Filters = [dict(Name = 'group-name', Values = [paws_prefix])])['SecurityGroups']:
            ec2.delete_security_group(GroupName = security_group['GroupName'])
            print('- deleted security group', security_group['GroupName'])
    
    for key_name in key_pair_names:    
        ec2.delete_key_pair(KeyName = key_name)
        print('- deleted key pair', key_name)

    iam_prefix = (N(name = name) + '\n') if name else N()

    for role in iam.list_roles()['Roles']:
        if not (role['RoleName'] + '\n').startswith(iam_prefix):
            continue

        for policy in iam.list_attached_role_policies(RoleName = role['RoleName'])['AttachedPolicies']:
            iam.detach_role_policy(RoleName = role['RoleName'], PolicyArn = policy['PolicyArn'])
            iam.delete_policy(PolicyArn = policy['PolicyArn'])
            print('- deleted policy', policy['PolicyArn'])
        
        for instance_profile in iam.list_instance_profiles_for_role(RoleName = role['RoleName'])['InstanceProfiles']:
            iam.remove_role_from_instance_profile(InstanceProfileName = instance_profile['InstanceProfileName'], RoleName = role['RoleName'])
            iam.delete_instance_profile(InstanceProfileName = instance_profile['InstanceProfileName'])
            print('- deleted instance profile', instance_profile['InstanceProfileName'])

        iam.delete_role(RoleName = role['RoleName'])
        print('- deleted role', role['RoleName'])

    for user in iam.list_users()['Users']:
        if not (user['UserName'] + '\n').startswith(iam_prefix):
            continue
        for access_key in iam.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']:
            print(access_key)
            iam.delete_access_key(AccessKeyId = access_key['AccessKeyId'], UserName = user['UserName'])
            print('- deleted access key', access_key['AccessKeyId'])

        iam.delete_user(UserName = user['UserName'])
        print('- deleted user', user['UserName'])

    if name:
        key_path = os.path.join(root, f'{name}_{region}.pem')
        if os.path.exists(key_path):
            os.remove(key_path)
            print('- deleted key', key_path)
    else:
        for key_name in os.listdir(root):
            if key_name.endswith(region + '.pem'):
                key_path = os.path.join(root, key_name)
                os.remove(key_path)
                print('- deleted key', key_path)

        if not os.listdir(root):
            os.rmdir(root)
            print('- deleted root', root)

def micro(name, root, region, availability_zone, instance_type_micro, **ignored):
    run(region = region, availability_zone = availability_zone, name = name, instance_type = instance_type_micro)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('cmd', choices = ['help', 'ps', 'lsblk', 'blkdeactivate', 'kill', 'killall', 'ssh', 'setup', 'micro', 'mkdir', 'ls', 'rm', 'clean', 'run'])
    parser.add_argument('--verbose', action = 'store_true')
    parser.add_argument('--dry', action = 'store_true')
    parser.add_argument('--region', default = 'us-east-1')
    parser.add_argument('--availability-zone', default = 'us-east-1a')
    parser.add_argument('--name'  , default = 'pawstest85')
    parser.add_argument('--username', default = 'ubuntu')
    parser.add_argument('--instance-id')
    parser.add_argument('--ssh', dest = 'ssh_when_running', action = 'store_true')
    parser.add_argument('--scp', action = 'store_true')
    parser.add_argument('--root', default = '~')
    parser.add_argument('--instance-type', default = 't3.mciro', choices = ['t3.micro'])
    parser.add_argument('--instance-type-micro', default = 't3.mciro')
    parser.add_argument('--delete-data', action = 'store_true')
    parser.add_argument('--suffix')
    parser.add_argument('--env-path')
    parser.add_argument('--env', nargs = '*')
    parser.add_argument('--env-export', nargs = '*')
    parser.add_argument('--cold-disk-size-gb', type = int, default = 0)
    parser.add_argument('--hot-disk-size-gb', type = int, default = 0)
    parser.add_argument('--cold-bucket', action = 'store_true')
    parser.add_argument('--hot-bucket', action = 'store_true')
    parser.add_argument('--hot-bucket-sync-dir')
    parser.add_argument('--git-clone')
    parser.add_argument('--git-tag')
    parser.add_argument('--git-key-path')
    parser.add_argument('--git-dir')
    parser.add_argument('--conda-installer-name', default = 'Miniconda3-py39_4.11.0-Linux-x86_64.sh')
    parser.add_argument('--conda', action = 'store_true')
    parser.add_argument('--working-dir')
    parser.add_argument('--job-script')
    parser.add_argument('--job-script-embed', action = 'store_true')
    parser.add_argument('--job-command', default = '')
    parser.add_argument('--requirements-script')
    parser.add_argument('--requirements-script-embed')
    parser.add_argument('--requirements-command', default = '')
    parser.add_argument('--data-script')
    parser.add_argument('--data-script-embed')
    parser.add_argument('--data-command', default = '')
    parser.add_argument('--pip-requirements')
    parser.add_argument('--pip-requirements-embed')
    parser.add_argument('--pip-install-packages', nargs = '*')
    parser.add_argument('--apt-install-packages', nargs = '*')

    args = parser.parse_args()

    args.env = {**dict(kv.split('=') for kv in args.env), **{k : os.getenv(k, '') for k in args.env_export}}
    argv = vars(args)
    cmd = globals()[argv.pop('cmd')]
    cmd(**argv)

    #TODO: echo nginx log server
    #TODO: SSM run + background
    #TODO: save init script somewhere - to instance tags? curl metadata to file?

    # tar -c ./myfiles | aws s3 cp - s3://my-bucket/myobject"
    # https://docs.aws.amazon.com/cli/latest/topic/s3-config.html
    # https://www.linkedin.com/pulse/aws-s3-multipart-uploading-milind-verma
    # https://www.slideshare.net/AmazonWebServices/deep-dive-aws-command-line-interface-50367179
    # https://www.thefreedictionary.com/words-that-end-in-aw
    # https://stackoverflow.com/questions/63950435/can-we-run-command-as-background-process-through-aws-ssm
