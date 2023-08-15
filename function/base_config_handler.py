"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

import boto3
import json

from botocore import config

import logger
import logging

from filters.validation_filters import PolicyValidationFindingsFilter

client_config = config.Config(retries={
	'total_max_attempts': 20,
	'mode': 'standard'
})

logger.configure()
LOGGER = logging.getLogger('policy-validation-config-rule')

config_client = boto3.client('config')
access_analyzer_client = boto3.client('accessanalyzer', config=client_config)


class InvokingEvent:
	def __init__(
			self,
			configuration_item,
			result_token,
			resource_type,
			resource_id,
			configuration_item_capture_time,
			event_left_scope
	):
		self.configuration_item = configuration_item
		self.result_token = result_token
		self.resource_type = resource_type
		self.resource_id = resource_id
		self.configuration_item_capture_time = configuration_item_capture_time
		self.event_left_scope = event_left_scope


class PolicyValidationConfigRuleHandler:
	def __init__(
			self,
			invoking_event: InvokingEvent
	):
		self.configuration_item = invoking_event.configuration_item
		self.result_token = invoking_event.result_token
		self.resource_type = invoking_event.resource_type
		self.resource_id = invoking_event.resource_id
		self.configuration_item_capture_time = invoking_event.configuration_item_capture_time
		self.event_left_scope = invoking_event.event_left_scope

		self.evaluations = []
		self.evaluation_errors = []
		self.policy_validation_findings_filter = PolicyValidationFindingsFilter()

	def handle_configuration_item(self):
		if self.event_left_scope:
			LOGGER.info('Resource was taken out of scope.')
			self.evaluation_is_not_applicable('Resource has been taken out of scope.')
			return self.__put_evaluations()

		is_applicable, reason = self.evaluate_applicability(self.configuration_item)
		if not is_applicable:
			self.evaluation_is_not_applicable(reason)
			self.__put_evaluations()
			return

		policy_documents = self.get_policy_documents(self.configuration_item)

		self.policy_validation_findings_filter.load_exceptions()

		non_compliant_findings = []
		for document in policy_documents:
			if document is None:
				continue

			findings = self.run_validation(document)
			non_compliant_findings.extend(findings)

		self.report_compliance(non_compliant_findings, self.resource_id)
		self.__put_evaluations()

	def run_validation(self, policy_document):
		policy_type = self.get_policy_type()
		validate_policy_resource_type = self.get_validate_policy_resource_type(policy_type)
		findings = self.__validate_policy(policy_document, policy_type, validate_policy_resource_type)

		LOGGER.info(f'Validating policy of type {policy_type}..')
		LOGGER.info(f'Policy contents: {policy_document}')

		resource_name = self.get_resource_name(self.configuration_item)
		marked_findings = self.policy_validation_findings_filter.mark_findings_as_ignorable(findings, resource_name, self.resource_type, policy_type)

		non_compliant_findings = [finding for finding in marked_findings if 'is_ignorable' not in finding]
		ignorable_findings = [finding for finding in marked_findings if 'is_ignorable' in finding]

		self.__log_non_compliant_findings(non_compliant_findings)
		self.__log_ignorable_findings(ignorable_findings)

		return non_compliant_findings

	# must be overridden
	def get_policy_document(self, configuration_item):
		raise NotImplementedError('get_policy_document must be overridden by derived class.')

	def get_resource_name(self, configuration_item):
		raise NotImplementedError('get_resource_name must be overridden by derived class.')

	# can be overridden
	def get_policy_documents(self, configuration_item):
		return [self.get_policy_document(configuration_item)]

	# should be overridden if different policy type required
	def get_policy_type(self):
		return 'IDENTITY_POLICY'

	# should be overridden for resource specific checks
	def get_validate_policy_resource_type(self, policy_type):
		return None

	# this should return false if there are cases where an evaluation is not applicable
	# for example, we don't validate the policies for SLRs
	# return True/False for applicability with a reason if N/A
	def evaluate_applicability(self, configuration_item):
		return True, None

	@staticmethod
	def __validate_policy(policy_document, policy_type='IDENTITY_POLICY', resource_type=None):
		paginator = access_analyzer_client.get_paginator('validate_policy')
		args = {
			'policyDocument': json.dumps(policy_document),
			'policyType': policy_type
		}

		if resource_type is not None:
			args['validatePolicyResourceType'] = resource_type

		response_iterator = paginator.paginate(**args)
		findings = []
		for page in response_iterator:
			findings.extend(page['findings'])

		return findings

	@staticmethod
	def __log_non_compliant_findings(non_compliant_findings):
		if len(non_compliant_findings) == 0:
			LOGGER.info('Policy is compliant.')
			return

		LOGGER.info(f'Found {len(non_compliant_findings)} noncompliant policy validation finding(s):')
		for finding in non_compliant_findings:
			LOGGER.info(finding)

	@staticmethod
	def __log_ignorable_findings(ignorable_findings):
		if len(ignorable_findings) == 0:
			return

		LOGGER.info(f'Found {len(ignorable_findings)} ignorable policy validation finding(s):')
		for finding in ignorable_findings:
			finding.pop('is_ignorable', None)
			LOGGER.info(finding)

	def report_compliance(self, non_compliant_findings, resource_id):
		if len(non_compliant_findings) == 0:
			self.resource_is_compliant(resource_id=resource_id)
		else:
			reason = self._build_noncompliant_reason(non_compliant_findings)
			self.resource_is_non_compliant(reason, resource_id=resource_id)

	def _build_noncompliant_reason(self, findings):
		findings_by_severity = self.__order_findings_by_severity(findings)
		distinct_issue_codes_by_severity = self.__filter_for_distinct_issue_codes(findings_by_severity)
		issue_code_string = ', '.join(distinct_issue_codes_by_severity)

		reason = f'{len(findings)} noncompliant finding(s) with issue codes: {issue_code_string}'
		reason = (reason[:250] + '..') if len(reason) > 250 else reason
		return reason

	@staticmethod
	def __get_findings_of_type(finding_type, findings):
		return [finding for finding in findings if finding['findingType'] == finding_type]

	def __order_findings_by_severity(self, findings):
		finding_types_by_severity = [
			'ERROR',
			'SECURITY_WARNING',
			'WARNING',
			'SUGGESTION'
		]

		sorted_findings = []
		for finding_type in finding_types_by_severity:
			sorted_findings.extend(self.__get_findings_of_type(finding_type, findings))

		return sorted_findings

	@staticmethod
	def __filter_for_distinct_issue_codes(findings):
		return list(dict.fromkeys([finding['issueCode'] for finding in findings]))

	def evaluation_is_not_applicable(self, reason, resource_id=None):
		if resource_id is None:
			resource_id = self.resource_id

		LOGGER.info('Resource evaluation is not applicable.')
		return self.__add_evaluation(resource_id, 'NOT_APPLICABLE', reason)

	def resource_is_compliant(self, reason="Policy has no validation findings.", resource_id=None):
		if resource_id is None:
			resource_id = self.resource_id

		LOGGER.info(f'Resource with resource ID {resource_id} is compliant.')
		return self.__add_evaluation(resource_id, 'COMPLIANT', reason)

	def resource_is_non_compliant(self, reason, resource_id=None):
		if resource_id is None:
			resource_id = self.resource_id

		LOGGER.info(f'Resource with resource ID {resource_id} is non_compliant.')
		return self.__add_evaluation(resource_id, 'NON_COMPLIANT', reason)

	def __add_evaluation(self, resource_id, compliance_type, reason):
		self.evaluations.append({
			"ComplianceResourceType": self.resource_type,
			"ComplianceResourceId": resource_id,
			"ComplianceType": compliance_type,
			"Annotation": reason,
			"OrderingTimestamp": self.configuration_item_capture_time
		})

	def __put_evaluations(self):
		evaluations_copy = self.evaluations[:]
		while evaluations_copy:
			config_client.put_evaluations(
				Evaluations=evaluations_copy[:100],
				ResultToken=self.result_token
			)
			del evaluations_copy[:100]


class ConfigHandler:
	def __init__(self):
		self.configuration_item = None
		self.result_token = None
		self.resource_type = None
		self.resource_id = None
		self.configuration_item_capture_time = None
		self.configuration_item = None
		self.event_left_scope = None

	# this is expected to be overridden by implementers
	def handle_configuration_item(self, configuration_item):
		raise NotImplemented('This should be overridden by derived class.')

	def handle_detection(self, event, context):
		message_type = json.loads(event['invokingEvent'])['messageType']
		LOGGER.info(f'Handling detection for message type {message_type}.')

		if message_type == 'ScheduledNotification':
			LOGGER.info('Ignoring scheduled notification.  Not implemented.')
		else:
			self.handle_detection_on_event(event, context)

	def handle_detection_on_event(self, event, context):
		self.result_token = event['resultToken']

		invoking_event = json.loads(event['invokingEvent'])
		self.configuration_item = self._get_configuration_item(invoking_event)

		self.resource_type = self.configuration_item.get('resourceType', 'unknown')
		self.resource_id = self.configuration_item['resourceId']
		LOGGER.info(f'Evaluating {self.configuration_item.get("resourceName", self.resource_id)} of type {self.resource_type}..')

		self.configuration_item_capture_time = self.configuration_item['configurationItemCaptureTime']

		self.event_left_scope = event.get('eventLeftScope', False)

	def run_validator(self, validator_type):
		invoking_event = InvokingEvent(
			self.configuration_item,
			self.result_token,
			self.resource_type,
			self.resource_id,
			self.configuration_item_capture_time,
			self.event_left_scope
		)

		validator = validator_type(invoking_event)
		validator.handle_configuration_item()

	def _get_configuration_item(self, invoking_event):
		if invoking_event['messageType'] == 'OversizedConfigurationItemChangeNotification':
			LOGGER.info('Message is oversized.  Getting message from resource history.')
			return self._get_oversized_configuration_item(invoking_event['configurationItemSummary'])

		return invoking_event['configurationItem']

	@staticmethod
	def _get_oversized_configuration_item(configuration_item_summary):
		result = config_client.get_resource_config_history(
			resourceType=configuration_item_summary['resourceType'],
			resourceId=configuration_item_summary['resourceId'],
			laterTime=configuration_item_summary['configurationItemCaptureTime'],
			limit=1
		)
		configuration_item = result['configurationItems'][0]
		configuration_item['ARN'] = configuration_item['arn']

		configuration = configuration_item.get('configuration')
		if configuration is not None and isinstance(configuration, str):
			configuration_item['configuration'] = json.loads(configuration)

		return configuration_item
