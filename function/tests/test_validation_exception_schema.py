"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import unittest
import json
import jsonschema
import os


this_files_directory = os.path.dirname(os.path.realpath(__file__))
with open(os.path.join(this_files_directory, '..', 'filters', 'exceptions-file-schema.json')) as f:
	validation_schema = json.load(f)


def expect_is_valid():
	def decorator(func):
		def wrapper(*args, **kwargs):
			self = args[0]

			func(*args, **kwargs)
			self.assertTrue(True)

		return wrapper
	return decorator


def expect_not_valid():
	def decorator(func):
		def wrapper(*args, **kwargs):
			self = args[0]

			with self.assertRaises(jsonschema.ValidationError):
				func(*args, **kwargs)

		return wrapper
	return decorator


class WhenValidatingExceptionsSchema(unittest.TestCase):
	@expect_is_valid()
	def test_empty_is_valid(self):
		instance = {}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_global_is_allowed_at_root(self):
		instance = {
			'global': {}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_not_valid()
	def test_account_id_not_numeric(self):
		instance = {
			'a123456': {}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_id_numeric(self):
		instance = {
			'123456789012': {}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_global_references_findings_schema(self):
		# simple example to validate that global and account reference the same schema
		instance = {
			'123456789012': {
				"ignoreErrorFindings": False
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_can_disable_inherit_global_findings(self):
		instance = {
			'123456789012': {
				"inheritGlobalIgnoreRules": False
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_can_ignore_error_findings(self):
		instance = {
			'123456789012': {
				"ignoreErrorFindings": True
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_can_ignore_security_warning_findings(self):
		instance = {
			'123456789012': {
				"ignoreSecurityWarningFindings": True
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_can_ignore_warning_findings(self):
		instance = {
			'123456789012': {
				"ignoreWarningFindings": True
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_account_can_ignore_suggestion_findings(self):
		instance = {
			'123456789012': {
				"ignoreSuggestionFindings": True
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_not_valid()
	def test_account_with_unsupported_property(self):
		instance = {
			'123456789012': {
				"unsupported": "property"
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_is_valid()
	def test_ignore_findings_with_schema(self):
		instance = {
			'123456789012': {
				"ignoreFindingsWith": [{
					"resourceType": "abc123",
					"issueCode": "code",
					"findingType": "ERROR",
					"resourceName": "name",
					"policyType": "IDENTITY_POLICY",
					"region": "us-east-1"
				},
				{
					"resourceType": "abc123",
					"issueCode": "code",
					"findingType": "ERROR",
					"resourceName": "name",
					"policyType": "IDENTITY_POLICY",
					"region": "us-east-1"
				}]
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)

	@expect_not_valid()
	def test_ignore_findings_with_additional_properties(self):
		instance = {
			'123456789012': {
				"ignoreFindingsWith": [{
					"resourceType": "abc123",
					"issueCode": "code",
					"findingType": "ERROR",
					"resourceName": "name",
					"policyType": "IDENTITY_POLICY",
					"region": "us-east-1",
					"additional": "property"
				}]
			}
		}
		jsonschema.validate(instance=instance, schema=validation_schema)
