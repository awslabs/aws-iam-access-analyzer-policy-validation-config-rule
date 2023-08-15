"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
from urllib.parse import unquote

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class IamRoleConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def __init__(self, invoking_event):
		super().__init__(invoking_event)
		self.resource_type_is_trust_policy = True

	def evaluate_applicability(self, configuration_item):
		path = configuration_item['configuration']['path']
		return not path.startswith('/aws-service-role/'), 'Role is service-linked role.'

	def get_resource_name(self, configuration_item):
		# remove the leading / from the path, so a policy without a path does not include a /
		# a policy with a path returns "my-path/my-policy-name"
		role_path = configuration_item['configuration'].get('path', '/').lstrip('/')
		role_name = configuration_item['configuration']['roleName']

		return f'{role_path}{role_name}'

	def get_policy_type(self):
		if self.resource_type_is_trust_policy:
			self.resource_type_is_trust_policy = False
			return 'RESOURCE_POLICY'

		return 'IDENTITY_POLICY'

	def get_validate_policy_resource_type(self, policy_type):
		if policy_type == 'RESOURCE_POLICY':
			return 'AWS::IAM::AssumeRolePolicyDocument'

		return None

	def get_policy_documents(self, configuration_item):
		policy_documents = [configuration_item['configuration']['assumeRolePolicyDocument']]
		policy_documents.extend([policy['policyDocument'] for policy in configuration_item['configuration'].get('rolePolicyList', [])])

		return [json.loads(unquote(document)) for document in policy_documents]
