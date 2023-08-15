"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
from urllib.parse import unquote

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class IamPolicyConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'IDENTITY_POLICY'

	def get_resource_name(self, configuration_item):
		# remove the leading / from the path, so a policy without a path does not include a /
		# a policy with a path returns "my-path/my-policy-name"
		policy_path = configuration_item['configuration'].get('path', '/').lstrip('/')
		policy_name = configuration_item['configuration']['policyName']

		return f'{policy_path}{policy_name}'

	def get_policy_document(self, configuration_item):
		policy_version_list = configuration_item['configuration']['policyVersionList']
		default_policy_version = next(iter([version for version in policy_version_list if version['isDefaultVersion']]))

		return json.loads(unquote(default_policy_version['document']))
