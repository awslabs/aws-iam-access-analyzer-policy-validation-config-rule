"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class S3AccessPointConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_resource_name(self, configuration_item):
		return configuration_item['configuration']['Name']

	def get_validate_policy_resource_type(self, policy_type):
		return 'AWS::S3::AccessPoint'

	def get_policy_document(self, configuration_item):
		access_point_policy = configuration_item['configuration'].get('Policy', {})
		if access_point_policy is None or len(access_point_policy) == 0:
			return None

		return access_point_policy
