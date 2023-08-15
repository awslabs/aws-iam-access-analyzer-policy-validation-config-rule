"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class KmsKeyConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_resource_name(self, configuration_item):
		# choosing key id over alias to avoid issues with swapping aliases
		return configuration_item['configuration']['keyId']

	def get_policy_document(self, configuration_item):
		return json.loads(configuration_item['supplementaryConfiguration']['Policy'])
