"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import os
import sys
from unittest import mock
from urllib.parse import quote, unquote

import handler

sys.path.insert(0, os.path.abspath('..'))

import json
import utils

from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable


class BaseRoleTest(BaseConfigRuleTest):
	def add_inline_policy_with_findings(self):
		self.__add_inline_policy(utils.invalid_identity_policy)
		self.expect_findings(utils.invalid_identity_policy, 'IDENTITY_POLICY')

	def add_inline_policy_with_no_findings(self):
		self.__add_inline_policy(utils.valid_identity_policy)
		self.expect_no_findings(utils.valid_identity_policy, 'IDENTITY_POLICY')

	def __add_inline_policy(self, new_role_text):
		def func(configuration_item):
			configuration_item['configuration']['rolePolicyList'].append({
				'policyName': 'Policy',
				'policyDocument': quote(json.dumps(new_role_text))
			})
		self.update_configuration_item(func)

	def use_trust_policy_with_findings(self):
		self.__use_trust_policy(utils.invalid_resource_policy)
		self.expect_findings(utils.invalid_resource_policy, 'RESOURCE_POLICY', 'AWS::IAM::AssumeRolePolicyDocument')

	def use_trust_policy_with_no_findings(self):
		self.__use_trust_policy(utils.valid_resource_policy)
		self.expect_no_findings(utils.valid_resource_policy, 'RESOURCE_POLICY', 'AWS::IAM::AssumeRolePolicyDocument')

	def __use_trust_policy(self, new_role_text):
		def func(configuration_item): configuration_item['configuration']['assumeRolePolicyDocument'] = quote(json.dumps(new_role_text))
		self.update_configuration_item(func)

	def clear_inline_policies(self):
		def func(configuration_item): configuration_item['configuration']['rolePolicyList'] = []
		self.update_configuration_item(func)

	def update_resource_name(self, role_name, path='/'):
		def func(configuration_item):
			configuration_item['configuration']['path'] = path
			configuration_item['configuration']['roleName'] = role_name

		self.update_configuration_item(func)


class WhenCreatingARole(BaseRoleTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-iam-role.json')
		self.clear_inline_policies()
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_inline_policy_and_valid_trust_policy(self):
		self.use_trust_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_no_inline_policy_and_invalid_trust_policy(self):
		self.use_trust_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_role(self):
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_trust_policy(self):
		self.use_trust_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_inline_policy(self):
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_not_applicable('Role is service-linked role.')
	def test_when_role_is_slr(self):
		self.remove_existing_s3_stubs()

		def func(configuration_item): configuration_item['configuration']['path'] = '/aws-service-role/abc123'
		self.update_configuration_item(func)
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-role')
		self.expect_exception_for_resource_name('AWS::IAM::Role', 'config-test-role')
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyRole', '/my-role-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Role', 'my-role-path/MyRole')
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempting_only_trust_policy(self):
		self.mock_exceptions({
			'global': {
				'ignoreFindingsWith': [{
					'policyType': 'RESOURCE_POLICY'
				}]
			}
		})
		self.use_trust_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingARole(BaseRoleTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-iam-role.json')
		self.clear_inline_policies()
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_inline_policy_and_valid_trust_policy(self):
		self.use_trust_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_no_inline_policy_and_invalid_trust_policy(self):
		self.use_trust_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_role(self):
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_trust_policy(self):
		self.use_trust_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_inline_policy(self):
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('config-test-role')
		self.expect_exception_for_resource_name('AWS::IAM::Role', 'config-test-role')
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name_with_path(self):
		self.update_resource_name('MyRole', '/my-role-path/')
		self.expect_exception_for_resource_name('AWS::IAM::Role', 'my-role-path/MyRole')
		self.use_trust_policy_with_no_findings()
		self.add_inline_policy_with_findings()
		handler.handle(self.event, self.context)

	@mock.patch.dict(os.environ, utils.default_env_variables)
	@expect_compliance()
	def test_when_exempting_only_trust_policy(self):
		self.mock_exceptions({
			'global': {
				'ignoreFindingsWith': [{
					'policyType': 'RESOURCE_POLICY'
				}]
			}
		})
		self.use_trust_policy_with_findings()
		self.add_inline_policy_with_no_findings()
		handler.handle(self.event, self.context)


class WhenDeletingARole(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-iam-role.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_any_role(self):
		handler.handle(self.event, self.context)


class WhenUpdatingARoleAndMessageIsOversized(BaseRoleTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('AROAABCDEFGHIJKLMNOPQ', 'AWS::IAM::Role')
		self.sample_config_item = self.load_historical_config_item('history-iam-role.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		configuration = json.loads(self.sample_config_item['configuration'])
		expected_policy = json.loads(unquote(configuration['rolePolicyList'][0]['policyDocument']))
		expected_trust_policy = json.loads(unquote(configuration['assumeRolePolicyDocument']))

		self.expect_no_findings(expected_trust_policy, 'RESOURCE_POLICY', 'AWS::IAM::AssumeRolePolicyDocument')
		self.expect_no_findings(expected_policy, 'IDENTITY_POLICY')

		handler.handle(self.event, self.context)


