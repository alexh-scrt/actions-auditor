"""Test package for actions_auditor.

This package contains unit and integration tests for the actions_auditor
CLI security tool. Tests are organized by module:

- test_rules.py: Unit tests for each security rule checker function
- test_scanner.py: Tests for workflow file discovery and YAML parsing logic

Fixtures are located in the tests/fixtures/ directory:

- good_workflow.yml: A well-configured workflow (negative test case)
- bad_workflow.yml: A deliberately misconfigured workflow (positive test case)
"""
