"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class LogsDestinationConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_resource_name(self, configuration_item):
		return configuration_item['configuration']['DestinationName']

	def get_policy_document(self, configuration_item):
		destination_policy = configuration_item['configuration'].get('DestinationPolicy')
		if destination_policy is None:
			return None

		return json.loads(destination_policy)
