"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import fnmatch
import os


class IgnoreFindingsWithFilter:
	def __init__(self, exceptions, resource_type, resource_name, policy_type):
		self.ignore_findings_with = exceptions.get('ignoreFindingsWith', [])
		self.resource_type = resource_type
		self.resource_name = resource_name
		self.policy_type = policy_type
		self.region = os.environ['AWS_REGION']

	def filter(self, findings):
		for rule in self.ignore_findings_with:
			resource_type_matches = self._resource_type_matches(rule)
			resource_name_matches = self._resource_name_matches(rule)
			policy_type_matches = self._policy_type_matches(rule)
			region_matches = self._region_matches(rule)

			for finding in findings:
				if resource_type_matches and \
					resource_name_matches and \
					policy_type_matches and \
					region_matches and \
					self._finding_type_matches(finding, rule) and \
					self._issue_code_matches(finding, rule):

					finding['is_ignorable'] = True

		return findings

	def _resource_type_matches(self, rule):
		expected_resource_type = rule.get('resourceType')
		if expected_resource_type is None:
			return True

		return self.resource_type.lower() == expected_resource_type.lower()

	@staticmethod
	def _issue_code_matches(finding, rule):
		expected_issue_code = rule.get('issueCode')
		if expected_issue_code is None:
			return True

		return finding['issueCode'].lower() == expected_issue_code.lower()

	@staticmethod
	def _finding_type_matches(finding, rule):
		expected_finding_type = rule.get('findingType')
		if expected_finding_type is None:
			return True

		return finding['findingType'].lower() == expected_finding_type.lower()

	def _resource_name_matches(self, rule):
		expected_resource_name_pattern = rule.get('resourceName')
		if expected_resource_name_pattern is None:
			return True

		return fnmatch.fnmatch(self.resource_name.lower(), expected_resource_name_pattern.lower())

	def _policy_type_matches(self, rule):
		expected_policy_type = rule.get('policyType')
		if expected_policy_type is None:
			return True

		return expected_policy_type.lower() == self.policy_type.lower()

	def _region_matches(self, rule):
		expected_region = rule.get('region')
		if expected_region is None:
			return True

		return expected_region.lower() == self.region.lower()
