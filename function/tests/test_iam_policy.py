"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import os
import sys
from urllib.parse import quote, unquote

sys.path.insert(0, os.path.abspath('..'))

import handler

import json
import utils


from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable


class BasePolicyTest(BaseConfigRuleTest):
	def use_policy_with_findings(self):
		self.__use_policy(utils.invalid_identity_policy)
		self.expect_findings(utils.invalid_identity_policy, 'IDENTITY_POLICY')

	def use_policy_with_no_findings(self):
		self.__use_policy(utils.valid_identity_policy)
		self.expect_no_findings(utils.valid_identity_policy, 'IDENTITY_POLICY')

	def __use_policy(self, new_policy_text):
		def func(configuratoin_item):
			configuratoin_item['configuration']['policyVersionList'][0]['document'] = quote(json.dumps(new_policy_text))
		self.update_configuration_item(func)

	def update_resource_name(self, policy_name, path='/'):
		def func(configuration_item):
			configuration_item['configuration']['path'] = path
			configuration_item['configuration']['policyName'] = policy_name

		self.update_configuration_item(func)


class WhenCreatingAPolicy(BasePolicyTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-iam-policy.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_valid_policy(self):
		self.use_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-policy')
		self.expect_exception_for_resource_name('AWS::IAM::Policy', 'config-test-policy')
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyPolicy', '/my-policy-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Policy', 'my-policy-path/MyPolicy')
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingAPolicy(BasePolicyTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-iam-policy.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.use_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-policy')
		self.expect_exception_for_resource_name('AWS::IAM::Policy', 'config-test-policy')
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyPolicy', '/my-policy-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Policy', 'my-policy-path/MyPolicy')
		self.use_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingAPolicy(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-iam-policy.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_any_policy(self):
		handler.handle(self.event, self.context)


class WhenUpdatingAPolicyAndMessageIsOversized(BasePolicyTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('ANPAABCDEFGHIJKLMNOPQ', 'AWS::IAM::Policy')
		self.sample_config_item = self.load_historical_config_item('history-iam-policy.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		configuration = json.loads(self.sample_config_item['configuration'])
		expected_policy = json.loads(unquote(configuration['policyVersionList'][0]['document']))
		self.expect_no_findings(expected_policy, 'IDENTITY_POLICY')

		handler.handle(self.event, self.context)

