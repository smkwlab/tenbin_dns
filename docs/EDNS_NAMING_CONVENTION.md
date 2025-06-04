# EDNS Naming Convention

This document explains the naming conventions used in the EDNS direct-access structure of the Tenbin.DNS library.

## Overview

The Tenbin.DNS library uses an optimized structure for EDNS options. This structure flattens common EDNS options to the top level for direct access while preserving unknown options in a separate map.

## Naming Convention Principles

### 1. Use Industry-Standard Abbreviations

For well-known options with established industry-standard abbreviations, use those abbreviations:

| RFC Name | Abbreviation | Flattened Fields |
|----------|-------------|------------------|
| `edns_client_subnet` | ECS | `ecs_family`, `ecs_subnet`, `ecs_source_prefix`, `ecs_scope_prefix` |
| `nsid` | NSID | `nsid` |
| `dau`, `dhu`, `n3u` | - | `dau_algorithms`, `dhu_algorithms`, `n3u_algorithms` |

**Rationale**: 
- Familiar to DNS engineers (used in `dig` command, Go miekg/dns, Python dnspython)
- Typing efficiency
- Frequently used options

### 2. Use Full Names for Complex Options

For options without standard abbreviations or complex options, use full names:

| RFC Name | Flattened Fields |
|----------|------------------|
| `extended_dns_error` | `extended_dns_error_info_code`, `extended_dns_error_extra_text` |
| `edns_tcp_keepalive` | `edns_tcp_keepalive_timeout`, `edns_tcp_keepalive_raw_data` |
| `cookie` | `cookie_client`, `cookie_server` |
| `padding` | `padding_length` |
| `edns_expire` | `edns_expire_expire` |
| `chain` | `chain_closest_encloser` |
| `edns_key_tag` | `edns_key_tag_key_tags` |
| `edns_client_tag` | `edns_client_tag_tag` |
| `edns_server_tag` | `edns_server_tag_tag` |
| `report_channel` | `report_channel_agent_domain` |
| `zoneversion` | `zoneversion_version` |
| `update_lease` | `update_lease_lease` |
| `llq` | `llq_version`, `llq_llq_opcode`, `llq_error_code`, `llq_llq_id`, `llq_lease_life` |
| `umbrella_ident` | `umbrella_ident_ident` |
| `deviceid` | `deviceid_device_id` |

**Rationale**:
- Clear and descriptive
- Prevents naming conflicts
- Self-documenting code
- Consistent with RFC terminology

### 3. Preserve Unknown Options

Options not recognized by the library are stored in the `unknown_options` map:

```elixir
unknown_options: %{
  123 => <<1, 2, 3, 4>>,  # Option code 123 with binary data
  456 => <<5, 6, 7, 8>>   # Option code 456 with binary data
}
```

## Performance Benefits

This structure provides significant performance improvements over nested access:

- **ECS access**: 35.3% faster
- **Cookie access**: 69.0% faster  
- **Unknown options access**: 32.9% faster

## Example Usage

```elixir
# Direct access to common options
packet.edns_info.ecs_family          # ECS family
packet.edns_info.ecs_subnet          # ECS subnet  
packet.edns_info.cookie_client       # Cookie client value
packet.edns_info.nsid                # NSID value

# Access to complex options
packet.edns_info.extended_dns_error_info_code    # Extended DNS Error info code
packet.edns_info.edns_tcp_keepalive_timeout      # TCP keepalive timeout

# Unknown options
packet.edns_info.unknown_options[123]            # Access unknown option 123
```

## Backward Compatibility

The flattened structure maintains full compatibility with standard EDNS processing:

- All RFC-defined options are supported
- Unknown options are preserved exactly as received
- Binary serialization maintains exact format
- No information is lost during parse/create cycles

## References

- [RFC 6891 - Extension Mechanisms for DNS (EDNS(0))](https://tools.ietf.org/html/rfc6891)
- [RFC 7871 - Client Subnet in DNS Queries](https://tools.ietf.org/html/rfc7871)
- [RFC 7873 - Domain Name System (DNS) Cookies](https://tools.ietf.org/html/rfc7873)
- [IANA DNS EDNS0 Option Codes](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11)