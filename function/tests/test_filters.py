"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import sys
import os

sys.path.insert(0, os.path.abspath('..'))
from filters.validation_filters import PolicyValidationFindingsFilter
from tests import utils
from tests.utils import BaseConfigRuleTest

sample_resource_name = 'MyResource'
sample_resource_type = 'AWS::Sample::Resource'
sample_policy_type = 'IDENTITY_POLICY'


class BaseFindingsTest(BaseConfigRuleTest):
	def assert_finding_is_ignorable(self, finding):
		self.assertTrue('is_ignorable' in finding)

	def assert_finding_is_not_ignorable(self, finding):
		self.assertFalse('is_ignorable' in finding)

	@staticmethod
	def build_finding_with(finding_type, issue_code='issue'):
		return {
			'findingType': finding_type,
			'findingDetails': 'detail',
			'learnMoreLink': 'learn more',
			'locations': [],
			'issueCode': issue_code
		}


class WhenIgnoringFindingTypes(BaseFindingsTest):
	def setUp(self):
		super().setUp()
		self.findings_filter = PolicyValidationFindingsFilter()

		self.findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('SECURITY_WARNING'),
			self.build_finding_with('WARNING'),
			self.build_finding_with('SUGGESTION')
		]

	def test_finding_type_defaults(self):
		exceptions = {}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name, sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])

	def test_ignores_error_findings(self):
		exceptions = {
			'global': {
				'ignoreErrorFindings': True
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name, sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])

	def test_ignores_security_warning_findings(self):
		exceptions = {
			'global': {
				'ignoreSecurityWarningFindings': True
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name,
			sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])

	def test_does_not_ignore_warning_findings(self):
		exceptions = {
			'global': {
				'ignoreWarningFindings': False
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name,
			sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_not_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])

	def test_does_not_ignore_suggestion_findings(self):
		exceptions = {
			'global': {
				'ignoreSuggestionFindings': False
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name,
			sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_not_ignorable(findings[3])


class WhenNoExceptionsBucketIsSpecified(BaseFindingsTest):
	def setUp(self):
		super().setUp()

		self.findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('SECURITY_WARNING'),
			self.build_finding_with('WARNING'),
			self.build_finding_with('SUGGESTION')
		]

	def test_loads_empty_exceptions(self):
		self.s3_stubber._queue.clear()

		os.environ.pop('EXCEPTIONS_S3_BUCKET_NAME', None)
		self.findings_filter = PolicyValidationFindingsFilter()
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name,
			sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])


class WhenAccountAndGlobalConfigurationAreSet(BaseFindingsTest):
	def setUp(self):
		super().setUp()

		self.findings_filter = PolicyValidationFindingsFilter()
		self.findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('SECURITY_WARNING'),
			self.build_finding_with('WARNING'),
			self.build_finding_with('SUGGESTION')
		]

	def test_account_configuration_overrides_global_for_finding_types(self):
		exceptions = {
			'global': {
				'ignoreErrorFindings': False
			},
			utils.account_id: {
				'ignoreErrorFindings': True
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = self.findings_filter.mark_findings_as_ignorable(self.findings, sample_resource_name,
			sample_resource_type, sample_policy_type)
		self.assertEqual(4, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
		self.assert_finding_is_ignorable(findings[2])
		self.assert_finding_is_ignorable(findings[3])

	def test_account_configuration_ignores_global_when_inherit_not_set(self):
		resource_type = 'AWS::Not::Ignored'
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceType': resource_type
				}]
			},
			utils.account_id: {
				'inheritGlobalIgnoreRules': False
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, resource_type, sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_findings_with_are_merged(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'findingType': 'SECURITY_WARNING'
				}]
			},
			utils.account_id: {
				'ignoreFindingsWith': [{
					'findingType': 'ERROR'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('SECURITY_WARNING')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])


class WhenIgnoringFindingsByProperty(BaseFindingsTest):
	def setUp(self):
		super().setUp()
		self.findings_filter = PolicyValidationFindingsFilter()

	def test_ignore_by_resource_type(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceType': 'AWS::My::ReSoUrCeType'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, 'AWS::MY::RESOURCETYPE',
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])

	def test_not_ignored_by_resource_type(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceType': 'AWS::My::ReSoUrCeType'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, 'AWS::NotMY::RESOURCETYPE',
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_issue_code(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'issueCode': 'iSS123'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR', issue_code='iss123'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_finding_type(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'findingType': 'ERROR'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('SECURITY_WARNING')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_resource_name_exact_match_case_insensitive(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceName': 'MyReSOurCe'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, 'MYRESOURCE', sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])

	def test_not_ignored_by_resource_name_exact_match_case_insensitive(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceName': 'MyReSOurCe'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, 'NOTMYRESOURCE', sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_resource_name_wildcard(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceName': 'PrEFix/*'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, 'prefix/MYRESOURCE', sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])

	def test_not_ignored_by_resource_name_wildcard(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceName': 'PrEFix/*'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, '1prefix/MYRESOURCE', sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_policy_type(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'policyType': 'resource_policy'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			'RESOURCE_POLICY')
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])

	def test_not_ignored_by_policy_type(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'policyType': 'resource_policy'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			'SERVICE_CONTROL_POLICY')
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_region(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'region': utils.region.upper()
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_ignorable(findings[1])

	def test_not_ignored_by_region(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'region': 'us-west-2'
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR'),
			self.build_finding_with('ERROR')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, sample_resource_name, sample_resource_type,
			sample_policy_type)
		self.assertEqual(2, len(findings))
		self.assert_finding_is_not_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])

	def test_ignore_by_all_properties(self):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceType': 'AWS::My::Type',
					'resourceName': 'MyResource',
					'issueCode': 'Issue1',
					'findingType': 'ERROR',
					'policyType': 'RESOURCE_POLICY',
					'region': utils.region.upper()
				}]
			}
		}
		self.mock_exceptions(exceptions)
		self.findings_filter.load_exceptions()

		findings = [
			self.build_finding_with('ERROR', 'Issue1'),
			self.build_finding_with('ERROR', 'Issue2')
		]

		findings = self.findings_filter.mark_findings_as_ignorable(findings, 'MyResource', 'AWS::My::Type',
			'RESOURCE_POLICY')
		self.assertEqual(2, len(findings))
		self.assert_finding_is_ignorable(findings[0])
		self.assert_finding_is_not_ignorable(findings[1])
