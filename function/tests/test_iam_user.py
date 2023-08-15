"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import os
import sys

from urllib.parse import quote, unquote

import handler

sys.path.insert(0, os.path.abspath('..'))

import json
import utils

from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable


class BaseUserTest(BaseConfigRuleTest):
	def clear_inline_policies(self):
		def func(configuration_item): configuration_item['configuration']['userPolicyList'] = []
		self.update_configuration_item(func)

	def add_inline_policy_with_findings(self):
		self.__add_inline_policy(utils.invalid_identity_policy)
		self.expect_findings(utils.invalid_identity_policy, 'IDENTITY_POLICY')

	def add_inline_policy_with_no_findings(self):
		self.__add_inline_policy(utils.valid_identity_policy)
		self.expect_no_findings(utils.valid_identity_policy, 'IDENTITY_POLICY')

	def __add_inline_policy(self, new_role_text):
		def func(configuration_item): configuration_item['configuration']['userPolicyList'].append({
			'policyName': 'Policy',
			'policyDocument': quote(json.dumps(new_role_text))
		})
		self.update_configuration_item(func)

	def update_resource_name(self, user_name, path='/'):
		def func(configuration_item):
			configuration_item['configuration']['path'] = path
			configuration_item['configuration']['userName'] = user_name

		self.update_configuration_item(func)


class WhenCreatingAUser(BaseUserTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-iam-user.json')
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
		self.update_resource_name('config-test-user')
		self.expect_exception_for_resource_name('AWS::IAM::User', 'config-test-user')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyUser', '/my-user-path/')
		self.expect_exception_for_resource_name('AWS::IAM::User', 'my-user-path/MyUser')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingAUser(BaseUserTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-iam-user.json')
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
		self.update_resource_name('config-test-user')
		self.expect_exception_for_resource_name('AWS::IAM::User', 'config-test-user')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyUser', '/my-user-path/')
		self.expect_exception_for_resource_name('AWS::IAM::User', 'my-user-path/MyUser')
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingAUser(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-iam-user.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingAUserAndMessageIsOversized(BaseUserTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('AIDAABCDEFGHIJKLMNOPQ', 'AWS::IAM::User')
		self.sample_config_item = self.load_historical_config_item('history-iam-user.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		configuration = json.loads(self.sample_config_item['configuration'])
		expected_policy = json.loads(unquote(configuration['userPolicyList'][0]['policyDocument']))
		self.expect_no_findings(expected_policy, 'IDENTITY_POLICY')

		handler.handle(self.event, self.context)
