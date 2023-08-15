"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import unittest
from unittest.mock import MagicMock

from base_config_handler import PolicyValidationConfigRuleHandler


class WhenBuildingNonCompliantReason(unittest.TestCase):
	def setUp(self):
		self.errors = [
			{'findingType': 'ERROR', 'issueCode': 'code1'},
			{'findingType': 'ERROR', 'issueCode': 'code2'},
			{'findingType': 'ERROR', 'issueCode': 'code3'}
		]
		self.security_warnings = [
			{'findingType': 'SECURITY_WARNING', 'issueCode': 'code4'}
		]
		self.warnings = [
			{'findingType': 'WARNING', 'issueCode': 'code5'}
		]
		self.suggestions = [
			{'findingType': 'SUGGESTION', 'issueCode': 'code6'}
		]
		# just to make the constructor happy
		mock_invoking_event = MagicMock()
		self.config_handler = PolicyValidationConfigRuleHandler(mock_invoking_event)

	@staticmethod
	def __build_expected_message(number_of_findings, issue_codes):
		return f'{number_of_findings} noncompliant finding(s) with issue codes: {issue_codes}'

	def test_with_only_error(self):
		reason = self.config_handler._build_noncompliant_reason(self.errors)
		self.assertEqual(self.__build_expected_message(3, 'code1, code2, code3'), reason)

	def test_with_only_security_warning(self):
		reason = self.config_handler._build_noncompliant_reason(self.security_warnings)
		self.assertEqual(self.__build_expected_message(1, 'code4'), reason)

	def test_with_only_warning(self):
		reason = self.config_handler._build_noncompliant_reason(self.warnings)
		self.assertEqual(self.__build_expected_message(1, 'code5'), reason)

	def test_with_only_suggestion(self):
		reason = self.config_handler._build_noncompliant_reason(self.suggestions)
		self.assertEqual(f'1 noncompliant finding(s) with issue codes: code6', reason)
		self.assertEqual(self.__build_expected_message(1, 'code6'), reason)

	def test_with_all_types(self):
		reason = self.config_handler._build_noncompliant_reason(self.warnings + self.errors + self.suggestions + self.security_warnings)
		self.assertEqual(self.__build_expected_message(6, 'code1, code2, code3, code4, code5, code6'), reason)

	def test_issue_codes_are_distinct(self):
		reason = self.config_handler._build_noncompliant_reason(self.errors + self.errors)
		self.assertEqual(self.__build_expected_message(6, 'code1, code2, code3'), reason)

	def test_when_longer_than_250_characters(self):
		really_long_list = [{'findingType': 'ERROR', 'issueCode': f'issue{i}'} for i in range(0, 100)]
		reason = self.config_handler._build_noncompliant_reason(really_long_list)
		self.assertEqual(self.__build_expected_message(100, 'issue0, issue1, issue2, issue3, issue4, issue5, issue6, issue7, issue8, issue9, issue10, issue11, issue12, issue13, issue14, issue15, issue16, issue17, issue18, issue19, issue20, issue21, issue22, issue23..'), reason)
		self.assertLessEqual(len(reason), 256)
