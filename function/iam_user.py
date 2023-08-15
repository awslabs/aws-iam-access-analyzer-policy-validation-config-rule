"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
from urllib.parse import unquote

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class IamUserConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'IDENTITY_POLICY'

	def get_resource_name(self, configuration_item):
		# remove the leading / from the path, so a policy without a path does not include a /
		# a policy with a path returns "my-path/my-policy-name"
		user_path = configuration_item['configuration'].get('path', '/').lstrip('/')
		user_name = configuration_item['configuration']['userName']

		return f'{user_path}{user_name}'

	def get_policy_documents(self, configuration_item):
		policy_documents = [policy['policyDocument'] for policy in configuration_item['configuration'].get('userPolicyList', [])]
		return [json.loads(unquote(document)) for document in policy_documents]
