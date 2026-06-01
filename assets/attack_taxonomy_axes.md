# Attack Taxonomy Breakdown

## Axis 1: Distribution Strategy
How the attack is split across PRs

├── Single PR Introduction
│   └── Vulnerable change in one reviewable PR
│
└── Precondition Staging
    └── Supporting changes staged before vulnerability

## Axis 2: Code Concealment  
How the vulnerability is hidden

├── Tiny Change
│   └── Minimal, localized modification
│
├── Buried in Complexity
│   └── Malicious change wrapped in structural refactoring
│
└── Semantic Equivalent
    └── Secure implementation replaced with vulnerable version

## Axis 3: PR Framing
How the reviewer is manipulated (15 strategies)

├── Fake Bug Fix
├── Unsafe Optimization
├── Refactoring
├── Misleading Pass
├── Review Bias
├── False Coverage
├── Appeal to Authority
├── Emotional Appeal
├── Jargon Smokescreen
├── AI Agent Authored
├── Build System Laundering
├── Prior Approval Signal
├── Dependency Compat Claim
├── Evidence Dilution
└── Misleading Hardening
