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


class BaseBucketTest(BaseConfigRuleTest):
	def set_no_bucket_policy(self):
		self.__set_bucket_policy(None)

	def set_bucket_policy_with_findings(self):
		self.__set_bucket_policy(utils.invalid_resource_policy)
		self.expect_findings(utils.invalid_resource_policy, 'RESOURCE_POLICY', 'AWS::S3::Bucket')

	def set_bucket_policy_without_findings(self):
		self.__set_bucket_policy(utils.valid_resource_policy)
		self.expect_no_findings(utils.valid_resource_policy, 'RESOURCE_POLICY', 'AWS::S3::Bucket')

	def __set_bucket_policy(self, policy):
		def func(configuration_item):
			policy_string = policy if policy is None else json.dumps(policy)
			configuration_item['supplementaryConfiguration']['BucketPolicy']['policyText'] = policy_string
		self.update_configuration_item(func)

	def update_resource_name(self, resource_name):
		def func(configuration_item):
			configuration_item['resourceName'] = resource_name
		self.update_configuration_item(func)


class WhenCreatingABucket(BaseBucketTest):
	def setUp(self):
		super().setUp()
		self.load_event('create-s3-bucket.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_bucket_policy(self):
		self.set_no_bucket_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_with_valid_policy(self):
		self.set_bucket_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_with_invalid_policy(self):
		self.set_bucket_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MyBucket')
		self.expect_exception_for_resource_name('AWS::S3::Bucket', 'MyBucket')
		self.set_bucket_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenUpdatingABucket(BaseBucketTest):
	def setUp(self):
		super().setUp()
		self.load_event('update-s3-bucket.json')
		self.expect_no_exceptions()

	@expect_compliance()
	def test_with_no_bucket_policy(self):
		self.set_no_bucket_policy()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_policy_is_updated_to_valid(self):
		self.set_bucket_policy_without_findings()
		handler.handle(self.event, self.context)

	@expect_non_compliance()
	def test_when_policy_is_updated_to_invalid(self):
		self.set_bucket_policy_with_findings()
		handler.handle(self.event, self.context)

	@expect_compliance()
	def test_when_exempt_by_exact_resource_name(self):
		self.update_resource_name('MyBucket')
		self.expect_exception_for_resource_name('AWS::S3::Bucket', 'MyBucket')
		self.set_bucket_policy_with_findings()
		handler.handle(self.event, self.context)


class WhenDeletingABucket(BaseConfigRuleTest):
	def setUp(self):
		super().setUp()
		self.load_event('delete-s3-bucket.json')

	@expect_not_applicable('Resource has been taken out of scope.')
	def test_when_deleted(self):
		handler.handle(self.event, self.context)


class WhenUpdatingABucketAndMessageIsOversized(BaseBucketTest):
	def setUp(self):
		super().setUp()
		self.load_oversized_event('bucket-bucket-444', 'AWS::S3::Bucket')
		self.sample_config_item = self.load_historical_config_item('history-s3-bucket.json')
		self.expect_no_exceptions()

	def add_additional_responses(self):
		self.add_get_resource_history_stub(self.sample_config_item)

	@expect_compliance()
	def test_when_updated_to_valid(self):
		expected_policy = json.loads(json.loads(self.sample_config_item['supplementaryConfiguration']['BucketPolicy'])['policyText'])
		self.expect_no_findings(expected_policy, 'RESOURCE_POLICY', 'AWS::S3::Bucket')

		handler.handle(self.event, self.context)
