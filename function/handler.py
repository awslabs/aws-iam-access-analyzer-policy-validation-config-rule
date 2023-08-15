"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import iam_group
import iam_policy
import iam_role
import iam_user
import kms_key
import logs_destination
import s3_access_point
import s3_bucket
import secretsmanager_secret
import sns_topic
import sqs_queue
from base_config_handler import ConfigHandler

resource_handlers = {
	'AWS::IAM::Policy': iam_policy.IamPolicyConfigRuleHandler,
	'AWS::IAM::Role': iam_role.IamRoleConfigRuleHandler,
	'AWS::IAM::User': iam_user.IamUserConfigRuleHandler,
	'AWS::IAM::Group': iam_group.IamGroupConfigRuleHandler,
	'AWS::KMS::Key': kms_key.KmsKeyConfigRuleHandler,
	'AWS::S3::Bucket': s3_bucket.S3BucketConfigRuleHandler,
	'AWS::S3::AccessPoint': s3_access_point.S3AccessPointConfigRuleHandler,
	'AWS::SQS::Queue': sqs_queue.SQSQueueConfigRuleHandler,
	'AWS::SecretsManager::Secret': secretsmanager_secret.SecretsManagerSecretConfigRuleHandler,
	'AWS::SNS::Topic': sns_topic.SNSTopicConfigRuleHandler,
	'AWS::Logs::Destination': logs_destination.LogsDestinationConfigRuleHandler
}


def handle(event, context):
	config_handler = ConfigHandler()
	config_handler.handle_detection(event, context)

	resource_handler = resource_handlers.get(config_handler.resource_type)
	if resource_handler is None:
		raise Exception(f'Could not find handler for {config_handler.resource_type}')

	config_handler.run_validator(resource_handler)
