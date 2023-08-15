"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import os
import sys

import handler

sys.path.insert(0, os.path.abspath('..'))

import json
import utils

from utils import expect_non_compliance, BaseConfigRuleTest, expect_compliance, expect_not_applicable


class BaseDestinationTest(BaseConfigRuleTest):
	def set_no_destination_policy(self):
		self.__set_destination_policy(None)

	def set_destination_policy_with_findings(self):
		self.__set_destination_policy(utils.invalid_resource_policy)
		self.expect_findings(utils.invalid_resource_policy, 'RESOURCE_POLICY')

	def set_destination_policy_without_findings(self):
		self.__set_destination_policy(utils.valid_resource_policy)
		self.expect_no_findings(utils.valid_resource_policy, 'RESOURCE_POLICY')

	def __set_destination_policy(self, policy):
		def func(configuration_item):
			if policy is None:
				configuration_item['configuration'].pop('DestinationPolicy', None)
			else:
				configuration_item['configuration']['DestinationPolicy'] = json.dumps(policy)

		self.update_configuration_item(func)

	def update_resource_name(self, resource_name):
		def func(configuration_item):
			configuration_item['configuration']['DestinationName'] = resource_name
		self.update_configuration_item(func)


class WhenCreatingADestination(BaseDestinationTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-logs-destination.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		self.set_no_destination_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_policy(self):
		self.set_destination_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.set_destination_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MyDestination')
		self.expect_exception_for_resource_name('AWS::Logs::Destination', 'MyDestination')
		self.set_destination_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingADestination(BaseDestinationTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-logs-destination.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_policy(self):
		self.set_no_destination_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.set_destination_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.set_destination_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MyDestination')
		self.expect_exception_for_resource_name('AWS::Logs::Destination', 'MyDestination')
		self.set_destination_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingADestination(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-logs-destination.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingADestinationAndMessageIsOversized(BaseDestinationTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('testDestination', 'AWS::Logs::Destination')
		self.sample_config_item = self.load_historical_config_item('history-logs-destination.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		configuration = json.loads(self.sample_config_item['configuration'])
		expected_policy = json.loads(configuration['DestinationPolicy'])
		self.expect_no_findings(expected_policy, 'RESOURCE_POLICY')

		handler.handle(self.event, self.context)
