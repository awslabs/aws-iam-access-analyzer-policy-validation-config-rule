"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class SQSQueueConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_resource_name(self, configuration_item):
		return configuration_item['resourceName']

	def get_policy_document(self, configuration_item):
		queue_policy = configuration_item['configuration'].get('Policy')
		if queue_policy is None:
			return None

		return json.loads(queue_policy)
