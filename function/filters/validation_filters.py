"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import json
from json import JSONDecodeError

import boto3
import logging
import os

from filters.ignore_finding_types import IgnoreErrorFindings, IgnoreSecurityWarningFindings, IgnoreWarningFindings, \
	IgnoreSuggestionFindings
from filters.ignore_findings_with_filter import IgnoreFindingsWithFilter

s3 = boto3.resource('s3')


LOGGER = logging.getLogger('policy-validation-config-rule')


class IgnorePolicyFindingsPipeline:
	def __init__(self, exceptions, resource_type, resource_name, policy_type):
		self.filters = [
			IgnoreErrorFindings(exceptions),
			IgnoreSecurityWarningFindings(exceptions),
			IgnoreWarningFindings(exceptions),
			IgnoreSuggestionFindings(exceptions),
			IgnoreFindingsWithFilter(exceptions, resource_type, resource_name, policy_type)
		]

	def mark_findings_as_ignored(self, findings):
		filter_results = findings
		for findings_filter in self.filters:
			filter_results = findings_filter.filter(filter_results)

		return filter_results


class PolicyValidationFindingsFilter:
	def __init__(self):
		self.exceptions_bucket_name = os.environ.get('EXCEPTIONS_S3_BUCKET_NAME')
		self.exceptions_file_prefix = os.environ.get('EXCEPTIONS_S3_FILE_PREFIX')
		self.exceptions_for_this_account = None

	def load_exceptions(self):
		validation_exceptions = self.__read_exceptions_from_s3_bucket()
		self.exceptions_for_this_account = self.__filter_exceptions_for_this_account(validation_exceptions)

	def mark_findings_as_ignorable(self, findings, resource_name, resource_type, policy_type):
		if self.exceptions_for_this_account is None:
			raise Exception('You must load the exceptions before marking findings as ignorable.')

		filter_pipeline = IgnorePolicyFindingsPipeline(self.exceptions_for_this_account, resource_type, resource_name, policy_type)
		findings_with_ignorable_markings = filter_pipeline.mark_findings_as_ignored(findings)

		return findings_with_ignorable_markings

	def __read_exceptions_from_s3_bucket(self):
		if self.exceptions_bucket_name is None or self.exceptions_file_prefix is None:
			LOGGER.info('No exceptions bucket name provided. Using exception defaults.')
			return {}

		try:
			obj = s3.Object(self.exceptions_bucket_name, self.exceptions_file_prefix)
			raw_file_as_string = obj.get()['Body'].read().decode('utf-8')
		except Exception:
			LOGGER.error(f'An error occurred retrieving policy validation exceptions file from bucket {self.exceptions_bucket_name} with prefix {self.exceptions_file_prefix}')
			raise

		try:
			return json.loads(raw_file_as_string)
		except JSONDecodeError:
			LOGGER.error('Unable to retrieve policy validation exceptions file. Validate that your exceptions file is valid JSON.')

	def __filter_exceptions_for_this_account(self, exceptions):
		global_exceptions = exceptions.get('global', {})

		account_id = os.environ.get('AWS_ACCOUNT_ID')
		if account_id is None:
			account_exceptions = {}
		else:
			account_exceptions = exceptions.get(account_id, {})

		should_inherit_global_exceptions = account_exceptions.get('inheritGlobalIgnoreRules', True)
		if not should_inherit_global_exceptions:
			return account_exceptions

		merged_exceptions = {}

		self.__merge_value('ignoreErrorFindings', account_exceptions, global_exceptions, merged_exceptions)
		self.__merge_value('ignoreSecurityWarningFindings', account_exceptions, global_exceptions, merged_exceptions)
		self.__merge_value('ignoreWarningFindings', account_exceptions, global_exceptions, merged_exceptions)
		self.__merge_value('ignoreSuggestionFindings', account_exceptions, global_exceptions, merged_exceptions)

		# ignoreFindingsWith is additive and account level configurations won't conflict with global configurations
		merged_exceptions['ignoreFindingsWith'] = global_exceptions.get('ignoreFindingsWith', []) + account_exceptions.get('ignoreFindingsWith', [])

		if os.environ.get('LOG_EXCEPTIONS', False):
			LOGGER.info(f'Using exceptions configuration:')
			LOGGER.info(merged_exceptions)

		return merged_exceptions

	@staticmethod
	def __merge_value(property_name, account_exceptions, global_exceptions, merged_exceptions):
		ignore_findings = account_exceptions.get(property_name, global_exceptions.get(property_name))
		if ignore_findings is not None:
			merged_exceptions[property_name] = ignore_findings
