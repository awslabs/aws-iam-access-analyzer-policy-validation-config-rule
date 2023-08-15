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


class BaseGroupTest(BaseConfigRuleTest):
	def clear_inline_policies(self):
		def func(config_item): config_item['configuration']['groupPolicyList'] = []
		self.update_configuration_item(func)

	def add_inline_policy_with_findings(self):
		self.__add_inline_policy(utils.invalid_identity_policy)
		self.expect_findings(utils.invalid_identity_policy, 'IDENTITY_POLICY')

	def add_inline_policy_with_no_findings(self):
		self.__add_inline_policy(utils.valid_identity_policy)
		self.expect_no_findings(utils.valid_identity_policy, 'IDENTITY_POLICY')

	def __add_inline_policy(self, new_role_text):
		def func(configuration_item):
			configuration_item['configuration']['groupPolicyList'].append({
				'policyName': 'Policy',
				'policyDocument': quote(json.dumps(new_role_text))
			})
		self.update_configuration_item(func)

	def update_resource_name(self, group_name, path='/'):
		def func(configuration_item):
			configuration_item['configuration']['path'] = path
			configuration_item['configuration']['groupName'] = group_name

		self.update_configuration_item(func)


class WhenCreatingAGroup(BaseGroupTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-iam-group.json')
		self.clear_inline_policies()
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_policy(self):
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-group')
		self.expect_exception_for_resource_name('AWS::IAM::Group', 'config-test-group')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyGroup', '/my-group-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Group', 'my-group-path/MyGroup')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingAGroup(BaseGroupTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-iam-group.json')
		self.clear_inline_policies()
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-group')
		self.expect_exception_for_resource_name('AWS::IAM::Group', 'config-test-group')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyGroup', '/my-group-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Group', 'my-group-path/MyGroup')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingAGroup(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-iam-group.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingAGroupAndMessageIsOversized(BaseGroupTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('AGPAABCDEFGHIJKLMNOPQ', 'AWS::IAM::Group')
		self.sample_config_item = self.load_historical_config_item('history-iam-group.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		configuration = json.loads(self.sample_config_item['configuration'])
		expected_policy = json.loads(unquote(configuration['groupPolicyList'][0]['policyDocument']))
		self.expect_no_findings(expected_policy, 'IDENTITY_POLICY')

		handler.handle(self.event, self.context)
