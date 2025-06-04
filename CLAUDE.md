# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

TenbinDns is an Elixir library for DNS packet parsing and creation. The project provides functionality to handle DNS protocol operations including packet creation, parsing, and managing DNS constants (types, classes, opcodes, etc.).

## Commands

### Development
- `mix deps.get` - Install dependencies
- `mix compile` - Compile the project
- `mix test` - Run all tests
- `mix test --verbose` - Run tests with detailed output
- `mix credo` - Run code analysis for style and quality
- `mix dialyzer` - Run static type analysis
- `mix docs` - Generate documentation

### Testing
- `mix test test/specific_test.exs` - Run a specific test file
- `mix test --trace` - Run tests with detailed tracing

## Architecture

### Core Modules

**DNS** (`lib/dns.ex`):
- Central constants module containing DNS type, class, rcode, and option definitions
- Provides bidirectional mapping functions between numeric codes and atoms
- Contains predefined constants for standard DNS values
- Pattern: Uses module attributes to define constant pairs, then generates maps for O(1) lookups

**DNSpacket** (`lib/dns_packet.ex`):
- Main packet handling module with struct definition for DNS packets
- Binary protocol implementation for DNS packet creation and parsing
- Supports standard DNS records (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA)
- EDNS0 support with hybrid structure for optimal performance and ease of use
- Uses Elixir binary pattern matching extensively for protocol implementation
- EDNS naming convention documented in `docs/EDNS_NAMING_CONVENTION.md`

**TenbinDns** (`lib/tenbin_dns.ex`):
- Main module (currently minimal with placeholder functionality)

### Key Patterns

**Binary Protocol Handling**:
- Heavy use of binary pattern matching for packet parsing
- Custom functions for domain name decompression (parsing compressed names)
- RDATA parsing specialized per DNS record type

**Constant Management**:
- Centralized constant definitions in DNS module
- Compile-time map generation for efficient lookups
- Bidirectional mapping between codes and atoms

**EDNS Hybrid Structure**:
- Flattened common options for direct access (e.g., `ecs_family`, `cookie_client`)
- Unknown options preserved in `unknown_options` map
- Industry-standard naming: ECS, NSID, DAU/DHU/N3U for common options
- Full names for complex options: `extended_dns_error_*`, `edns_tcp_keepalive_*`
- Performance improvements: 35-69% faster access over nested structures

**Error Handling**:
- Functions return structured data rather than raising exceptions
- Graceful degradation for unknown DNS types/classes

## Development Notes

- Uses ExUnit for testing with extensive binary data validation
- Code analysis tools (Credo, Dialyxir) are configured and should be run before commits
- Binary data handling requires careful attention to byte alignment and endianness
- DNS name decompression uses pointer following in binary data for parsing compressed names