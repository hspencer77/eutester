# Software License Agreement (BSD License)
#
# Copyright (c) 2009-2011, Eucalyptus Systems, Inc.
# All rights reserved.
#
# Redistribution and use of this software in source and binary forms, with or
# without modification, are permitted provided that the following conditions
# are met:
#
#   Redistributions of source code must retain the above
#   copyright notice, this list of conditions and the
#   following disclaimer.
#
#   Redistributions in binary form must reproduce the above
#   copyright notice, this list of conditions and the
#   following disclaimer in the documentation and/or other
#   materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Author: vic.iglesias@eucalyptus.com
from eutester import Eutester

class IAMops(Eutester):
    
    def create_user(self, user_name,path="/"):
        self.debug("Attempting to create user: " + user_name)
        self.euare.create_user(user_name, path)
    
    def delete_user(self, user_name):
        self.debug("Deleting user " + user_name)
        self.euare.delete_user(user_name)
    
    def attach_policy_user(self, user_name, policy_name, policy_json):
        self.debug("Attaching the following policy to " + user_name + ":" + policy_json)
        self.euare.put_user_policy(user_name, policy_name, policy_json)
    
    def detach_policy_user(self, user_name, policy_name):
        self.debug("Detaching the following policy from " + user_name + ":" + policy_name)
        self.euare.delete_user_policy(user_name, policy_name)
    
    def create_group(self, group_name,path="/"):
        self.debug("Attempting to create group: " + group_name)
        self.euare.create_group(group_name, path)
    
    def delete_group(self, group_name):
        self.debug("Deleting group " + group_name)
        self.euare.delete_group(group_name)
    
    def add_user_to_group(self, group_name, user_name):
        self.debug("Adding user "  +  user + " to group " + group)
        self.euare.add_user_to_group(group_name, user_name)
    
    def remove_user_from_group(self, group_name, user_name):
        self.debug("Removing user "  +  user + " to group " + group)
        self.euare.remove_user_from_group(group_name, user_name)
    
    def attach_policy_group(self, group_name, policy_name, policy_json):
        self.debug("Attaching the following policy to " + group_name + ":" + policy_json)
        self.euare.put_group_policy(group_name, policy_name, policy_json)
    
    def detach_policy_group(self, group_name, policy_name):
        self.debug("Detaching the following policy from " + group_name + ":" + policy_name)
        self.euare.delete_group_policy(group_name, policy_name)
        
    def create_account(self,account_name):
        '''Create an account with the given name'''
        self.debug("Creating account: " + account_name)
        params = {'AccountName': account_name}
        self.euare.get_response('CreateAccount', params)
    
        
        
        
    
        
    