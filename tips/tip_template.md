---
id: TIP-XXXX
title: TIP Title
description: Short description for SEO
authors: <name/handle>
status: Draft | In Review | Ready for Consideration | Approved | Scheduled | Testnet | Mainnet
related: <links or IDs>
protocolVersion: <version at which TIP is scheduled to be included/was included>
---

# TIP-XXXX: TIP Title

## Abstract

Summarize the change, its purpose, and its main limitation in 2–4 sentences.

## Motivation

Explain the problem or capability, alternatives considered, and why the change is needed. Link prerequisite specifications.

## Assumptions

State the assumptions and consequences of violating them, including relevant upstream invariants, trust boundaries, deployment order, and backward compatibility.

---

# Specification

Define behavior precisely enough to implement and test without inferring rules.

## Overview

Define terms, scope, and the lifecycle. Explain who authorizes each operation and the critical trust boundary before the detailed mechanics.

## Mechanics

Describe operations in lifecycle order: authority, inputs, checks, state transitions, data structures, encodings, and data flow between components. Define failures, rollback and persistence, fee and nonce effects, and retry conditions where relevant.

Use prose for behavior and causality, ordered steps when order matters, and tables for comparisons. Use diagrams when they clarify the flow. State each rule once and link to it elsewhere.

## Interfaces

Put full interface definitions, selectors, events, errors, and storage layouts here. For precompiles, include complete NatSpec for parameters, return values, and errors. Keep encoding formulas and algorithm steps with the mechanics.

# Compatibility

Describe changes to existing flows and adoption work, linking relevant scope limits from the Overview. Include commands, SDKs/libraries, test helpers, fixtures, machine-readable outputs, debugging, recovery, and integration guidance for implementers, operators, support teams, and users. Distinguish required tooling from available support.

When a table helps, use `Integration | What changes` for recognizable flows, concrete behavior and consequences, and links to owning sections.

Cite specification sections or pinned implementation revisions. Distinguish specified behavior, observed implementation, deductions, and unverified partner risks. If no compatibility or tooling changes are required, write `N/A` and explain why.

# Observability

List each event that MUST be emitted, its fields, and the operational question it answers. Explain the evidence for failures and recovery. If no new events are required, write `N/A` and explain why existing observability is sufficient.

# Threat Model

Lead with the most consequential attack supported by the design. For each actor, state what they control, what the design trusts them to do, the enforcing check, and the consequence of failure or compromise. Use a concise table when comparing actors helps.

Name residual risks and excluded threats. A meta TIP owns shared actors and attacks spanning components; each component TIP still explains its local boundary and checks and links shared assumptions.

# Invariants

State checkable properties that must always hold and the critical cases the test suite must cover.
