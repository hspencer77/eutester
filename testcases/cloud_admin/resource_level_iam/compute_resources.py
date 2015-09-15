#!/usr/bin/env python
import re
import string
import random
import socket
import os
from eucaops import Eucaops
from eucaops import EC2ops
from eutester.euinstance import EuInstance
from eutester.eutestcase import EutesterTestCase
from awacs.aws import Action, Allow, Policy, Principal, Statement
from awacs.ec2 import ARN as EC2_ARN


class ComputeResourceLevelTest(EutesterTestCase):
    def __init__(self):
        self.setuptestcase()
        self.setup_parser()
        self.parser.add_argument('--clean_on_exit',
                                 action='store_true', default=True,
                                 help=("Boolean, used to flag whether "
                                       + "to run clean up method after "
                                       + "running test list"))
        self.get_args()
        self.tester = Eucaops(credpath=self.args.credpath,
                              config_file=self.args.config,
                              password=self.args.password)
        self.testers = []
        self.regions = []
        self.reserved_addresses = []
        self.keypairs = []
        for region in self.tester.ec2.get_all_regions():
            region_info = {'name': str(region.name),
                           'endpoint': str(region.endpoint)}
            self.regions.append(region_info)

    def clean_method(self):
        for tester in self.testers:
           try:
               tester.show_euare_whoami()
           except: pass
           tester.cleanup_artifacts()
        self.tester.delete_account('ec2-account',
                                   recursive=True)
        for key in self.keypairs:
            os.remove(key)

    def setup_users(self, account_name, group_name, user_name):
        users = ['admin', user_name]
        self.tester.info("Setting up users in " + account_name)
        for user in users:
            self.tester.debug("Create access key for "
                              + user + " user in " + account_name)
            keys = self.tester.create_access_key(user_name=user,
                                                 delegate_account=account_name)
            access_key = keys['access_key_id']
            secret_key = keys['secret_access_key']
            self.tester.debug("Creating EC2ops object with access key "
                              + access_key + " and secret key "
                              + secret_key)
            new_tester = Eucaops(aws_access_key_id=access_key,
                                 aws_secret_access_key=secret_key,
                                 ec2_ip=self.tester.ec2.host,
                                 ec2_path=self.tester.ec2.path,
                                 iam_ip=self.tester.euare.host,
                                 iam_path=self.tester.euare.path,
                                 s3_ip=self.tester.s3.host,
                                 s3_path=self.tester.s3.path,
                                 sts_ip=self.tester.tokens.host,
                                 sts_path=self.tester.tokens.path,
                                 cw_ip=self.tester.cw.host,
                                 cw_path=self.tester.cw.path,
                                 as_ip=self.tester.autoscale.host,
                                 as_path=self.tester.autoscale.path,
                                 elb_ip=self.tester.elb.host,
                                 elb_path=self.tester.elb.path,
                                 username=user, account=account_name)
            self.testers.append(new_tester)
            if user != 'admin':
                self.tester.debug("Adding " + user + " to "
                                  + group_name)
                self.tester.add_user_to_group(group_name,
                                              user,
                                              delegate_account=account_name)

    def group_policy_add(self, group_name, account_name):
        policy_id = "EC2-Instance-Resource-Level-Permissions"
        sid = "Stmt" + self.tester.id_generator()
        pd = Policy(
                 Version="2012-10-17",
                 Id=policy_id,
                 Statement=[
                     Statement(
                         Sid=sid,
                         Effect=Allow,
                         Action=[Action("ec2", "*")],
                         Resource=[EC2_ARN("instance/*"),],
                     ),
                 ],
             )
        self.tester.debug("Applying " + policy_id + " policy to "
                          + group_name + " group") 
        self.tester.attach_policy_group(group_name,
                                        policy_id,
                                        pd.to_json(),
                                        delegate_account=account_name)

    def setup_instance_resources(self, tester, region):
        if re.search('^https', region['endpoint']):
            ssl_flag = True
        else:
            ssl_flag = False
        endpoint = region['endpoint'].strip(':8773/')
        fqdn_endpoint = endpoint.strip('http://https://')
        ip_endpoint = socket.gethostbyname(fqdn_endpoint)
        tester.info("Establishing EC2 connection to " + region['name']
                   + " region")
        try:
            tester.setup_ec2_connection(
                        endpoint=ip_endpoint,
                        region=region['name'],
                        aws_access_key_id=tester.ec2.aws_access_key_id,
                        aws_secret_access_key=tester.ec2.aws_secret_access_key,
                        port=8773,
                        path="services/compute",
                        is_secure=ssl_flag)
        except Exception, e:
            self.errormsg("Unable to establish EC2 connection to "
                          + "region " + region['name'])
            raise e
        zone = random.choice(tester.get_zones())
        keypair = tester.add_keypair("keypair-" + tester.id_generator())
        keypath = '%s/%s.pem' % (os.curdir, keypair.name)
        self.keypairs.append(keypath)
        group = tester.add_group("group-" + tester.id_generator())
        tester.authorize_group_by_name(group_name=group.name)
        tester.authorize_group_by_name(group_name=group.name,
                                       port=-1,
                                       protocol="icmp")
        if self.args.emi:
            image = tester.get_emi(emi=self.args.emi)
        else:
            image = tester.get_emi(root_device_type="instance-store",
                                   basic_image=True)
        params = {'image': image,
                  'user_data': self.args.user_data,
                  'username': self.args.instance_user,
                  'keypair': keypair.name,
                  'group': group.name,
                  'zone': zone,
                  'return_reservation': True,
                  'timeout': 600}
        reservation = tester.run_image(**params)
        for instance in reservation.instances:
            self.assertTrue(tester.wait_for_reservation(reservation),
                            'Instance did not go to running')
            self.assertTrue(tester.ping(instance.ip_address),
                            'Could not ping instance')
        tester.show_addresses(None, True)
        address = tester.allocate_address()
        tester.info("Allocate address "
                   + address.public_ip + " for instance resource "
                   + "test in region " + region['name'])
        addr_info = {'region': region['name'],
                     'address': address}
        self.reserved_addresses.append(addr_info)

    def test_instance_resources(self, tester, region):
        if re.search('^https', region['endpoint']):
            ssl_flag = True
        else:
            ssl_flag = False
        endpoint = region['endpoint'].strip(':8773/')
        fqdn_endpoint = endpoint.strip('http://https://')
        ip_endpoint = socket.gethostbyname(fqdn_endpoint)
        tester.info("Establishing EC2 connection to " + region['name']
                   + " region")
        try:
            tester.setup_ec2_connection(
                        endpoint=ip_endpoint,
                        region=region['name'],
                        aws_access_key_id=tester.ec2.aws_access_key_id,
                        aws_secret_access_key=tester.ec2.aws_secret_access_key,
                        port=8773,
                        path="services/compute",
                        is_secure=ssl_flag)
        except Exception, e:
            self.errormsg("Unable to establish EC2 connection to "
                          + "region " + region['name'])
            raise e
        reservations = tester.ec2.get_all_reservations()
        tester.info("Execute DescribeInstances as " 
                   + tester.username + " user")
        for reservation in reservations:
            self.assertIsNotNone(reservation,
                                 msg=("DescribeInstances failed for "
                                      + region['name'] + " region."))

    def remove_instance_resources(self, tester, region):
        if re.search('^https', region['endpoint']):
            ssl_flag = True
        else:
            ssl_flag = False
        endpoint = region['endpoint'].strip(':8773/')
        fqdn_endpoint = endpoint.strip('http://https://')
        ip_endpoint = socket.gethostbyname(fqdn_endpoint)
        tester.info("Establishing EC2 connection to " + region['name']
                   + " region")
        try:
            tester.setup_ec2_connection(
                        endpoint=ip_endpoint,
                        region=region['name'],
                        aws_access_key_id=tester.ec2.aws_access_key_id,
                        aws_secret_access_key=tester.ec2.aws_secret_access_key,
                        port=8773,
                        path="services/compute",
                        is_secure=ssl_flag)
        except Exception, e:
            self.errormsg("Unable to establish EC2 connection to "
                          + "region " + region['name'])
            raise e
        if self.args.clean_on_exit:
            tester.info("Terminate all instances in "
                        + "region " + region['name'])
            reservations = tester.ec2.get_all_reservations()
            for reservation in reservations:
                tester.terminate_instances(reservation)
            tester.info("Release allocated addresses in "
                        + "region " + region['name'])
            for addr_info in self.reserved_addresses:
                if addr_info['region'] == region['name']:
                    tester.release_address(addr_info['address'])

    def InstanceResourceLevel(self):
        account_name = 'ec2-account'
        group_name = 'ec2_instance_admins'
        user_name = 'instance_admin'
        self.tester.info("Creating " + account_name)
        self.tester.create_account(account_name)
        self.tester.info("Creating " + group_name
                          + " in account " + account_name)
        self.tester.create_group(group_name, "/",
                                 delegate_account=account_name)
        self.group_policy_add(group_name, account_name)
        self.tester.create_user(user_name,
                                "/",
                                delegate_account=account_name)
        self.setup_users(account_name,
                         group_name,
                         user_name)
        for resource_tester in self.testers:
            if resource_tester.username == 'admin':
                for region in self.regions:
                    self.setup_instance_resources(resource_tester, region)
            else:
               self.test_instance_resources(resource_tester, region)
        for resource_tester in self.testers:
            if resource_tester.username == 'admin':
                for region in self.regions:
                    self.remove_instance_resources(resource_tester, region)
                    

if __name__ == '__main__':
    testcase = ComputeResourceLevelTest()
    list = ['InstanceResourceLevel']
    unit_list = []
    for test in list:
        unit_list.append(testcase.create_testunit_by_name(test))
    result = testcase.run_test_case_list(unit_list, clean_on_exit=testcase.args.clean_on_exit)
    exit(result)
