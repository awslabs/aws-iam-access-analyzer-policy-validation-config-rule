"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
import os
import sys

import handler
import secretsmanager_secret

sys.path.insert(0, os.path.abspath('..'))

import utils

from botocore.stub import Stubber
from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable

secret_name = 'config-test-secret-Tn8fX8'
secret_arn = f'arn:aws:secretsmanager:us-east-1:111111111111:secret:{secret_name}'


class BaseSecretTest(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.secretsmanager_stubber = Stubber(secretsmanager_secret.secretsmanager_client)
		self.secretsmanager_stubber.activate()

	def tearDown(self):
		super().tearDown()
		try:
			self.secretsmanager_stubber.assert_no_pending_responses()
		finally:
			self.secretsmanager_stubber.deactivate()

	def set_no_secret_policy(self):
		self.__set_secret_policy(None)

	def set_secret_policy_with_findings(self):
		self.__set_secret_policy(utils.invalid_resource_policy)
		self.expect_findings(utils.invalid_resource_policy, 'RESOURCE_POLICY')

	def set_secret_policy_with_no_findings(self):
		self.__set_secret_policy(utils.valid_resource_policy)
		self.expect_no_findings(utils.valid_resource_policy, 'RESOURCE_POLICY')

	def __set_secret_policy(self, policy):
		self._expect_get_resource_policy(policy)

	def _expect_get_resource_policy(self, policy):
		response = {
			'ARN': secret_arn,
			'Name': secret_name
		}

		if policy is not None:
			response['ResourcePolicy'] = json.dumps(policy)

		self.secretsmanager_stubber.add_response(
			'get_resource_policy',
			response,
			expected_params={
				'SecretId': secret_arn
			}
		)

	def update_resource_name(self, resource_name):
		def func(configuration_item):
			configuration_item['configuration']['Name'] = resource_name

		self.update_configuration_item(func)


class WhenCreatingASecret(BaseSecretTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-secretsmanager-secret.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		self.set_no_secret_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_policy(self):
		self.set_secret_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.set_secret_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_secret_is_soft_deleted(self):
		def func(configuration_item): configuration_item['configuration']['Deleted'] = True
		self.update_configuration_item(func)
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_secret_is_no_longer_exists(self):
		self.secretsmanager_stubber.add_client_error('get_resource_policy', 'ResourceNotFoundException')
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MySecret')
		self.expect_exception_for_resource_name('AWS::SecretsManager::Secret', 'MySecret')
		self.set_secret_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingASecret(BaseSecretTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-secretsmanager-secret.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		self.set_no_secret_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.set_secret_policy_with_no_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.set_secret_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_secret_is_soft_deleted(self):
		def func(configuration_item): configuration_item['configuration']['Deleted'] = True
		self.update_configuration_item(func)
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_secret_is_no_longer_exists(self):
		self.secretsmanager_stubber.add_client_error('get_resource_policy', 'ResourceNotFoundException')
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MySecret')
		self.expect_exception_for_resource_name('AWS::SecretsManager::Secret', 'MySecret')
		self.set_secret_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingASecret(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-sqs-queue.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingASecretAndMessageIsOversized(BaseSecretTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event(secret_arn, 'AWS::SecretsManager::Secret')
		self.sample_config_item = self.load_historical_config_item('history-secretsmanager-secret.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		self.set_secret_policy_with_no_findings()
		handler.handle(self.event, self.context)
