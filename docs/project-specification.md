# SentinelForge X — Project Specification

## 1. Project summary

SentinelForge X is an explainable, testable and reproducible detection
engineering platform for investigating security events from Windows, Linux and
network telemetry.

The platform is designed to help analysts understand not only that an alert
was generated, but also:

- Which events caused the alert
- Why the detection logic matched
- Which systems and users were involved
- Whether the detection is reliable
- Whether the investigation can be reproduced
- What response actions should be considered

## 2. Problem statement

Security monitoring systems can generate large numbers of alerts, but an alert
alone does not provide enough context for a high-quality investigation.

Analysts need to determine:

1. Why the alert was generated
2. Which events are related
3. Whether the behaviour is malicious, benign or uncertain
4. Whether the detection creates false positives
5. Whether the detection still works after changes
6. How to communicate the investigation to another person

SentinelForge X addresses this problem by combining event normalisation,
detection-as-code, evidence-linked alerts, incident timelines, detection replay
and quality measurement.

## 3. Intended users

### Primary user: Security analyst

The analyst needs to investigate alerts, review supporting evidence, create
incident timelines and record conclusions.

### Secondary user: Detection engineer

The detection engineer needs to create, test, version and improve detection
rules.

### Secondary user: Security student

The student needs a safe and reproducible platform for understanding how
security telemetry becomes a detection and an incident investigation.

## 4. Core principles

SentinelForge X will follow these principles:

### Explainability

Every alert must identify the events and conditions that caused it.

### Reproducibility

A detection and its result should be reproducible using the same input data,
rule version and configuration.

### Testability

Every detection should have positive and negative test cases.

### Evidence before conclusions

The platform should display supporting evidence before presenting an
investigator with a conclusion.

### Secure by default

The application must avoid hardcoded secrets, unsafe defaults and unnecessary
network exposure.

### Honest scope

The project will clearly document its limitations and will not claim to be a
production replacement for a commercial SIEM.

## 5. Initial capabilities

The first major version should provide:

- Ingestion of structured security events
- Normalisation into a common event model
- Version-controlled detection rules
- Detection evaluation against events
- Explainable alert generation
- Evidence-linked alert details
- Incident timelines
- MITRE ATT&CK references
- Detection replay
- Positive and negative detection tests
- Basic detection quality metrics
- Incident report export
- Docker-based local deployment
- Automated code quality checks

## 6. Initial event sources

The first release will support representative data from:

- Linux authentication logs
- Windows Security events
- Sysmon-style process events
- Network connection events
- Synthetic test events

The initial implementation may use prepared JSON fixtures before connecting to
live endpoints.

## 7. Common event model

All supported sources should be converted into a common event structure.

A normalised event should support fields such as:

- Event identifier
- Timestamp
- Host identifier
- Username
- Source address
- Destination address
- Source type
- Event category
- Action
- Process information
- File information
- Raw event reference

The model should allow optional fields because not every log source provides
the same information.

## 8. Detection model

Each detection should include:

- Unique identifier
- Name
- Version
- Description
- Severity
- Data sources
- Conditions
- Thresholds
- Time window
- MITRE ATT&CK references
- False-positive guidance
- Investigation guidance
- Response guidance
- Test cases

Detection rules should be stored in the repository and reviewed as code.

## 9. Alert requirements

An alert should include:

- Alert identifier
- Detection identifier
- Detection version
- Creation timestamp
- Severity
- Affected hosts
- Related users
- Related addresses
- Triggering events
- Explanation of the match
- MITRE ATT&CK references
- Investigation status

## 10. Incident requirements

An incident should support:

- Incident identifier
- Title
- Severity
- Status
- Related alerts
- Affected systems
- Timeline
- Evidence
- Analyst notes
- Investigation conclusion
- Containment actions
- Recovery actions
- Lessons learned
- Exportable report

## 11. Detection quality

The platform should support evaluation of detections against labelled test data.

The first version should calculate:

- True positives
- False positives
- True negatives
- False negatives
- Precision
- Recall
- F1 score

The platform must show the underlying test results rather than presenting
metrics without evidence.

## 12. Security requirements

The application must:

- Validate user-controlled input
- Avoid hardcoded secrets
- Use safe configuration defaults
- Record important administrative actions
- Restrict access to protected operations
- Avoid exposing sensitive raw logs by default
- Document its network exposure
- Include dependency and container checks
- Provide a clear security boundary for the local lab

## 13. Non-goals

The first major version will not attempt to:

- Replace a commercial SIEM
- Detect every form of malicious activity
- Perform unauthorised security testing
- Collect data from public systems
- Automatically declare that an event is malicious
- Use an AI model as a substitute for evidence
- Provide production-scale multi-tenant hosting
- Guarantee zero false positives

## 14. Success criteria

The project will be considered successful when a new user can:

1. Start the platform locally using documented instructions.
2. Load the included sample event dataset.
3. Run the included detection rules.
4. View an explainable alert.
5. Trace the alert back to its triggering events.
6. View the related incident timeline.
7. Run the detection test suite.
8. View detection quality metrics.
9. Export an incident report.
10. Understand the system from the documentation alone.

## 15. Quality criteria

The finished project should include:

- Automated unit tests
- Integration tests for core workflows
- Static type checking
- Code formatting checks
- Linting
- Security scanning
- Reproducible local setup
- Clear error handling
- Architecture documentation
- Threat model
- Design decision records
- Example investigations
- Known limitations
- A demonstration video

## 16. Planned development stages

### Stage 1: Foundation

- Repository structure
- Project specification
- Development environment
- Basic application skeleton
- Initial automated checks

### Stage 2: Event model

- Common event schema
- Input validation
- Sample event fixtures
- Normalisation tests

### Stage 3: Detection engine

- Detection rule format
- Rule validation
- Event matching
- Alert generation
- Explanation generation

### Stage 4: Investigation

- Event search
- Alert detail view
- Evidence display
- Incident timelines
- Case status

### Stage 5: Detection quality

- Replay engine
- Positive test cases
- Negative test cases
- Quality metrics
- Regression testing

### Stage 6: Security and release quality

- Authentication
- Authorisation
- Audit logging
- Threat model
- Security checks
- Documentation
- Demonstration

## 17. Definition of done

A feature is not considered complete until:

- The feature works
- The feature has tests
- Errors are handled
- Documentation has been updated
- Security implications have been considered
- The feature has a meaningful commit
- The feature can be demonstrated
