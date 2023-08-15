"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
from unittest.mock import patch
from urllib.parse import quote

import handler
from base_config_handler import PolicyValidationConfigRuleHandler
from tests import utils
from tests.utils import BaseConfigRuleTest, expect_compliance


class WhenHandlingDetectionEvent(BaseConfigRuleTest):
	class SomeFakeType(PolicyValidationConfigRuleHandler):
		def __init__(self, invoking_event):
			super().__init__(invoking_event)
			self.handler_was_called = False

		def get_resource_name(self, configuration_item):
			return 'Fake resource'

		def get_policy_document(self, configuration_item):
			return utils.valid_identity_policy

	def setUp(self):
		super().setUp()
		self.load_event('some-fake-type.json')
		self.expect_no_exceptions()

	@patch.dict(handler.resource_handlers, {'AWS::IAM::FakeType': SomeFakeType})
	@expect_compliance()
	def test_routes_to_handler_of_correct_type(self):
		def func(configuration_item):
			configuration_item['configuration']['policyVersionList'][0]['document'] = quote(json.dumps(utils.valid_identity_policy))
		self.update_configuration_item(func)

		self.expect_no_findings(utils.valid_identity_policy, 'IDENTITY_POLICY')

		handler.handle(self.event, self.context)
