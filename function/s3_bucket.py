"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json

import logging

from base_config_handler import PolicyValidationConfigRuleHandler

LOGGER = logging.getLogger('policy-validation-config-rule')


class S3BucketConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_validate_policy_resource_type(self, policy_type):
		return 'AWS::S3::Bucket'

	def get_resource_name(self, configuration_item):
		return configuration_item['resourceName']

	def get_policy_document(self, configuration_item):
		bucket_policy = configuration_item['supplementaryConfiguration'].get('BucketPolicy', {})
		if isinstance(bucket_policy, str):
			bucket_policy = json.loads(bucket_policy)

		policy_text = bucket_policy.get('policyText')
		if policy_text is None:
			return None

		return json.loads(policy_text)
