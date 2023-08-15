"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import boto3
import json

import logging

from botocore.exceptions import ClientError
from base_config_handler import PolicyValidationConfigRuleHandler, client_config

LOGGER = logging.getLogger('policy-validation-config-rule')
secretsmanager_client = boto3.client('secretsmanager', config=client_config)


class SecretsManagerSecretConfigRuleHandler(PolicyValidationConfigRuleHandler):
	def get_policy_type(self):
		return 'RESOURCE_POLICY'

	def get_resource_name(self, configuration_item):
		return configuration_item['configuration']['Name']

	def get_policy_document(self, configuration_item):
		# secrets manager secrets do not contain the resource policy so we must query to get it

		secret_arn = configuration_item['ARN']

		configuration = configuration_item['configuration']
		if isinstance(configuration, str):
			# oversized items will serialize the configuration
			configuration = json.loads(configuration)

		secret_is_soft_deleted = configuration['Deleted']
		if secret_is_soft_deleted:
			LOGGER.info('This secret is soft deleted.  Skipping evaluation.')
			return None

		try:
			get_resource_policy_response = secretsmanager_client.get_resource_policy(SecretId=secret_arn)
		except ClientError as e:
			if e.response['Error']['Code'] == 'ResourceNotFoundException':
				LOGGER.info('Secret no longer exists. Ignoring.')
				return None

			raise

		secret_policy = get_resource_policy_response.get('ResourcePolicy')
		if secret_policy is None:
			return None

		return json.loads(secret_policy)
