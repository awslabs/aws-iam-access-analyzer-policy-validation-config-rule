"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import io
import json
import os
import unittest

import base_config_handler
from unittest import mock

from botocore.stub import Stubber
from botocore.response import StreamingBody

from filters import validation_filters

region = 'us-east-1'
account_id = '111111111111'
exceptions_bucket_name = "my-exceptions-bucket"
exceptions_file_prefix = "my-prefix/file.json"

default_env_variables = {
	"AWS_REGION": region,
	"AWS_ACCOUNT_ID": account_id,
	"EXCEPTIONS_S3_BUCKET_NAME": exceptions_bucket_name,
	"EXCEPTIONS_S3_FILE_PREFIX": exceptions_file_prefix
}

valid_resource_policy = {
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": "111111111111"
		},
		"Action": "*"
	}]
}

invalid_resource_policy = {
	"Statement": [{
		"Effect": "Allow",
		"Principal": {
			"AWS": "*"
		},
		"Action": "*"
	}]
}

valid_identity_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "VisualEditor0",
		"Effect": "Allow",
		"Action": "s3:PutObject",
		"Resource": "*"
	}]
}

invalid_identity_policy = {
	"Version": "2012-10-17",
	"Statement": [{
		"Sid": "VisualEditor0",
		"Effect": "Allow",
		"Action": "s3:DoesNotExist",
		"Resource": "*"
	}]
}


def expect_exception():
	def decorator(func):
		def wrapper(*args, **kwargs):
			func(*args, **kwargs)

		return wrapper
	return decorator


def expect_non_compliance(resource_id=None, resource_type=None, reason='1 noncompliant finding(s) with issue codes: issue'):
	def decorator(func):
		def wrapper(*args, **kwargs):
			self = args[0]

			expected_resource_id = self.resource_id if resource_id is None else resource_id
			expected_resource_type = self.resource_type if resource_type is None else resource_type

			_exec_function(self.build_non_compliant_evaluation, reason, expected_resource_id, expected_resource_type, func, *args, **kwargs)

		return wrapper
	return decorator


def expect_compliance(resource_id=None, resource_type=None, reason='Policy has no validation findings.'):
	def decorator(func):
		def wrapper(*args, **kwargs):
			self = args[0]

			expected_resource_id = self.resource_id if resource_id is None else resource_id
			expected_resource_type = self.resource_type if resource_type is None else resource_type

			_exec_function(self.build_compliant_evaluation, reason, expected_resource_id, expected_resource_type, func, *args, **kwargs)

		return wrapper
	return decorator


def expect_not_applicable(reason, resource_id=None, resource_type=None):
	def decorator(func):
		def wrapper(*args, **kwargs):
			self = args[0]

			expected_resource_id = self.resource_id if resource_id is None else resource_id
			expected_resource_type = self.resource_type if resource_type is None else resource_type

			_exec_function(self.build_not_applicable_evaluation, reason, expected_resource_id, expected_resource_type, func, *args, **kwargs)

		return wrapper
	return decorator


def _exec_function(build_evaluation, reason, resource_id, resource_type, func, *func_args, **func_kwargs):
	self = func_args[0]
	if not hasattr(self, 'config_stubber'):
		self.config_stubber = Stubber(base_config_handler.config_client)
		self.config_stubber.activate()

	if not hasattr(self, 'expected_evaluations'):
		# a previous decorator may have created this list already and if so, we want to keep adding evaluations to it
		self.expected_evaluations = []

	try:
		expected_evaluation = build_evaluation(reason, resource_id, resource_type)
		self.expected_evaluations.append(expected_evaluation)

		if hasattr(self, 'add_additional_responses'):
			self.add_additional_responses()

		# if this is the last expected call in the list, add the stub
		# this does limit this decorator's usefulness to only test classes, but I don't think it applies anywhere else
		if func.__name__.startswith("test_"):
			self.config_stubber.add_response('put_evaluations', {}, self.expected_put_evaluations_call(self.expected_evaluations))

		func(*func_args, **func_kwargs)
		self.config_stubber.assert_no_pending_responses()
	finally:
		self.config_stubber.deactivate()


def create_sns_event_with_message(message):
	return {
		'Records': [{
			'Sns': {
				'Message': message
			}
		}]
	}


class BaseConfigRuleTest(unittest.TestCase):
	def setUp(self):
		super().setUp()
		self.event = {}
		self.context = {}
		self.resource_type = None
		self.resource_id = None
		self.configuration_item_capture_time = None

		self.access_analyzer_stubber = Stubber(base_config_handler.access_analyzer_client)
		self.access_analyzer_stubber.activate()

		self.s3_stubber = Stubber(validation_filters.s3.meta.client)
		self.s3_stubber.activate()

		self.environ_patch = mock.patch.dict(os.environ, default_env_variables)
		self.environ_patch.start()

	def tearDown(self):
		try:
			self.access_analyzer_stubber.assert_no_pending_responses()
			self.s3_stubber.assert_no_pending_responses()
		finally:
			try:
				self.access_analyzer_stubber.deactivate()
				self.s3_stubber.deactivate()
			finally:
				self.environ_patch.stop()

	def expect_exception_for_resource_name(self, resource_type, resource_name):
		exceptions = {
			'global': {
				'ignoreFindingsWith': [{
					'resourceType': resource_type,
					'resourceName': resource_name
				}]
			}
		}

		self.mock_exceptions(exceptions)

	def expect_no_exceptions(self):
		self.mock_exceptions({})

	def mock_exceptions(self, exceptions):
		encoded_message = json.dumps(exceptions).encode()
		raw_stream = StreamingBody(
			io.BytesIO(encoded_message),
			len(encoded_message)
		)

		self.remove_existing_s3_stubs()

		self.s3_stubber.add_response(
			'get_object',
			{
				'Body': raw_stream
			},
			{
				'Bucket': exceptions_bucket_name,
				'Key': exceptions_file_prefix
			}
		)

	def remove_existing_s3_stubs(self):
		# not a great solution, but there's no easier way to remove the default response from the queue
		self.s3_stubber._queue.clear()

	def expect_findings(self, policy_document, policy_type, validate_policy_resource_type=None):
		self.__expect_findings(policy_document, policy_type, validate_policy_resource_type,
			[{
				'findingType': 'ERROR',
				'findingDetails': 'detail',
				'learnMoreLink': 'learn more',
				'locations': [],
				'issueCode': 'issue'
			}]
		)

	def expect_no_findings(self, policy_document, policy_type, validate_policy_resource_type=None):
		self.__expect_findings(policy_document, policy_type, validate_policy_resource_type, [])

	def __expect_findings(self, policy_document, policy_type, validate_policy_resource_type, findings):
		expected_params = {
			'policyDocument': json.dumps(policy_document),
			'policyType': policy_type
		}

		if validate_policy_resource_type is not None:
			expected_params['validatePolicyResourceType'] = validate_policy_resource_type

		self.access_analyzer_stubber.add_response(
			'validate_policy',
			{
				'findings': findings
			},
			expected_params=expected_params
		)

	@staticmethod
	def __load_file(filename):
		this_scripts_directory = os.path.dirname(os.path.realpath(__file__))
		with open(os.path.join(this_scripts_directory, "..", "sample-events", filename)) as f:
			return json.load(f)

	def load_event(self, filename):
		self.set_event(self.__load_file(filename))

	def set_event(self, event):
		self.event = event
		invoking_event = json.loads(event['invokingEvent'])
		configuration_item = invoking_event['configurationItem']
		self.resource_type = configuration_item['resourceType']
		self.resource_id = configuration_item['resourceId']
		self.configuration_item_capture_time = configuration_item['configurationItemCaptureTime']

	def load_historical_config_item(self, filename):
		historical_config_record = self.__load_file(filename)
		configuration_item = historical_config_record['configurationItems'][0]
		self.configuration_item_capture_time = configuration_item['configurationItemCaptureTime']
		return configuration_item

	def load_oversized_event(self, resource_id, of_type):
		this_scripts_directory = os.path.dirname(os.path.realpath(__file__))
		with open(os.path.join(this_scripts_directory, "..", "sample-events", 'oversized.json')) as f:
			event = json.load(f)
			invoking_event = json.loads(event['invokingEvent'])
			invoking_event['configurationItemSummary']['resourceType'] = of_type
			invoking_event['configurationItemSummary']['resourceId'] = resource_id
			configuration_item = invoking_event['configurationItemSummary']
			self.resource_type = of_type
			self.resource_id = resource_id
			self.configuration_item_capture_time = configuration_item['configurationItemCaptureTime']

			event['invokingEvent'] = json.dumps(invoking_event)
			self.event = event

	def update_oversized_configuration_item(self, config_item):
		invoking_event = json.loads(self.event['invokingEvent'])
		invoking_event['configurationItemSummary'] = config_item
		self.event['invokingEvent'] = json.dumps(invoking_event)

		self.resource_type = config_item['resourceType']
		self.resource_id = config_item['resourceId']
		self.configuration_item_capture_time = config_item['configurationItemCaptureTime']

	def update_configuration_item(self, update_configuration_item_func):
		invoking_event = json.loads(self.event['invokingEvent'])
		update_configuration_item_func(invoking_event['configurationItem'])
		self.event['invokingEvent'] = json.dumps(invoking_event)
		self.set_event(self.event)

	def add_get_resource_history_stub(self, config_item):
		invoking_event = json.loads(self.event['invokingEvent'])
		self.config_stubber.add_response('get_resource_config_history', {
			'configurationItems': [
				config_item
			]
		},
		{
			'resourceType': invoking_event['configurationItemSummary']['resourceType'],
			'resourceId': invoking_event['configurationItemSummary']['resourceId'],
			'laterTime': invoking_event['configurationItemSummary']['configurationItemCaptureTime'],
			'limit': 1
		})

	def build_non_compliant_evaluation(self, reason, resource_id, resource_type):
		return {
			"ComplianceResourceType": resource_type,
			"ComplianceResourceId": resource_id,
			"ComplianceType": 'NON_COMPLIANT',
			"Annotation": reason,
			"OrderingTimestamp": self.configuration_item_capture_time
		}

	def build_compliant_evaluation(self, reason, resource_id, resource_type):
		return {
			"ComplianceResourceType": resource_type,
			"ComplianceResourceId": resource_id,
			"ComplianceType": 'COMPLIANT',
			"Annotation": reason,
			"OrderingTimestamp": self.configuration_item_capture_time
		}

	def build_not_applicable_evaluation(self, reason, resource_id, resource_type):
		return {
			"ComplianceResourceType": resource_type,
			"ComplianceResourceId": resource_id,
			"ComplianceType": 'NOT_APPLICABLE',
			"Annotation": reason,
			"OrderingTimestamp": self.configuration_item_capture_time
		}

	def expected_put_evaluations_call(self, evaluations):
		if not isinstance(evaluations, list):
			evaluations = [evaluations]

		return {
			"Evaluations": evaluations,
			"ResultToken": self.event['resultToken']
		}