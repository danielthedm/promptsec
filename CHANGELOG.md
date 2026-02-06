# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-01-01

### Added
- Heuristic detection guard with 30+ patterns across 5 threat categories
- Input sanitizer with Unicode normalization, homoglyph replacement, and payload decoding
- Taint tracking with trust level hierarchy
- Spotlighting guard (delimit, datamark, encode modes)
- Canary token injection and leakage detection
- Structure enforcer (sandwich, post-prompt, random enclosure, XML tags)
- Output validator with leak detection and format validation
- Embedding-based classifier with cosine similarity
- Attack memory for self-hardening
- Preflight red-team test runner with 50+ built-in attacks
- Composable middleware pipeline
- Preset configurations (Strict, Moderate, Lenient)
- Custom guard support via GuardFunc
