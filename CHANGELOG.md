# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/samp-reston/doip-sockets/compare/v0.1.0...v0.2.0) - 2025-01-13

### Added

- finish documentation and api polishing
- completed type safe UDP socket
- add into split method
- implements from_std for tcp
- implement tcp only sending and generic reading

### Fixed

- remove dead code and add remainder of tcp compliant payloadtypes

### Other

- fix tests
- update deps
- *(api)* updated module exports
- remove copies, add access to inner at ref
- extract into better mod structure
- added test for into_split()
- remove more dead code
- remove dead code
- improve send to only send applicable tcp types

## [0.1.0](https://github.com/samp-reston/doip-sockets/releases/tag/v0.1.0) - 2025-01-06

### Added

- add TcpStream connect and send

### Other

- update version
- export structs and add dependencies
- run first release-plz
- add boilerplate
- Initial commit

## [1.0.0](https://github.com/samp-reston/doip-sockets/releases/tag/v1.0.0) - 2025-01-06

### Other

- add boilerplate
- Initial commit
