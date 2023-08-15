"""
Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
SPDX-License-Identifier: MIT-0
"""

class IgnoreErrorFindings:
	def __init__(self, exceptions):
		self.ignore_error_findings = exceptions.get('ignoreErrorFindings', False)

	def filter(self, findings):
		if not self.ignore_error_findings:
			return findings

		for finding in findings:
			if finding['findingType'] == 'ERROR':
				finding['is_ignorable'] = True

		return findings


class IgnoreSecurityWarningFindings:
	def __init__(self, exceptions):
		self.ignore_security_warning_findings = exceptions.get('ignoreSecurityWarningFindings', False)

	def filter(self, findings):
		if not self.ignore_security_warning_findings:
			return findings

		for finding in findings:
			if finding['findingType'] == 'SECURITY_WARNING':
				finding['is_ignorable'] = True

		return findings


class IgnoreWarningFindings:
	def __init__(self, exceptions):
		self.ignore_warning_findings = exceptions.get('ignoreWarningFindings', True)

	def filter(self, findings):
		if not self.ignore_warning_findings:
			return findings

		for finding in findings:
			if finding['findingType'] == 'WARNING':
				finding['is_ignorable'] = True

		return findings


class IgnoreSuggestionFindings:
	def __init__(self, exceptions):
		self.ignore_suggestion_findings = exceptions.get('ignoreSuggestionFindings', True)

	def filter(self, findings):
		if not self.ignore_suggestion_findings:
			return findings

		for finding in findings:
			if finding['findingType'] == 'SUGGESTION':
				finding['is_ignorable'] = True

		return findings

