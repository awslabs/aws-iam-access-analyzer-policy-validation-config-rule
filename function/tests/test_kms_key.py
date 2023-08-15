"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import os
import sys
import uuid

import handler

sys.path.insert(0, os.path.abspath('..'))

import json
import utils

from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable


class BaseKeyTest(BaseConfigRuleTest):
	def set_key_policy_with_findings(self):
		self.__set_key_policy(utils.invalid_resource_policy)
		self.expect_findings(utils.invalid_resource_policy, 'RESOURCE_POLICY')

	def set_key_policy_without_findings(self):
		self.__set_key_policy(utils.valid_resource_policy)
		self.expect_no_findings(utils.valid_resource_policy, 'RESOURCE_POLICY')

	def __set_key_policy(self, policy):
		def func(configuration_item):
			configuration_item['supplementaryConfiguration']['Policy'] = json.dumps(policy)
		self.update_configuration_item(func)

	def update_resource_name(self, resource_name):
		def func(configuration_item):
			configuration_item['configuration']['keyId'] = resource_name
		self.update_configuration_item(func)


class WhenCreatingAKey(BaseKeyTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-kms-key.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_valid_policy(self):
		self.set_key_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.set_key_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		key_id = str(uuid.uuid4())
		self.update_resource_name(key_id)
		self.expect_exception_for_resource_name('AWS::KMS::Key', key_id)
		self.set_key_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingAKey(BaseKeyTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-kms-key.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.set_key_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.set_key_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		key_id = str(uuid.uuid4())
		self.update_resource_name(key_id)
		self.expect_exception_for_resource_name('AWS::KMS::Key', key_id)
		self.set_key_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingAKey(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-kms-key.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingAKeyAndMessageIsOversized(BaseKeyTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('b7a563db-8243-49ad-911b-70cadadf3fe1', 'AWS::KMS::Key')
		self.sample_config_item = self.load_historical_config_item('history-kms-key.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		expected_policy = json.loads(self.sample_config_item['supplementaryConfiguration']['Policy'])
		self.expect_no_findings(expected_policy, 'RESOURCE_POLICY')

		handler.handle(self.event, self.context)
