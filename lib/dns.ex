defmodule DNS do
  @moduledoc """
  DNS constants and mappings for types, classes, response codes, and EDNS options.

  This module provides constant mappings for DNS protocol values.
  All lookups are compile-time optimized with pre-computed maps and aggressive
  function inlining for maximum speed.

  ## Features

  - **DNS Record Types**: A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, OPT, etc.
  - **DNS Classes**: IN (Internet), CH (Chaos), HS (Hesiod)
  - **Response Codes**: NOERROR, NXDOMAIN, REFUSED, etc.
  - **EDNS Options**: ECS, cookies, NSID, extended DNS errors, etc.
  - **Bidirectional Mapping**: Convert between numeric codes and atoms

  ## Usage

      # DNS record types
      DNS.type_code(:a)        # => 1
      DNS.type(1)              # => :a

      # DNS classes  
      DNS.class_code(:in)      # => 1
      DNS.class(1)             # => :in

      # Response codes
      DNS.rcode_code(:nxdomain) # => 3
      DNS.rcode(3)              # => :nxdomain

      # EDNS options
      DNS.option_code(:edns_client_subnet) # => 8
      DNS.option(8)                        # => :edns_client_subnet

  All constants are based on IANA DNS parameter assignments and RFCs.
  """

  # Inline DNS constant lookups for maximum performance
  @compile {:inline, [
    type: 1,
    type_code: 1,
    class: 1,
    class_code: 1,
    rcode: 1,
    rcode_code: 1,
    option: 1,
    option_code: 1
  ]}

  # Pre-compile lookup maps for better performance
  # Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
  @type_map %{
    1 => :a,       # RFC 1035 - a host address
    2 => :ns,      # RFC 1035 - an authoritative name server
    3 => :md,      # RFC 1035 - a mail destination (OBSOLETE)
    4 => :mf,      # RFC 1035 - a mail forwarder (OBSOLETE)
    5 => :cname,   # RFC 1035 - the canonical name for an alias
    6 => :soa,     # RFC 1035 - marks the start of a zone of authority
    7 => :mb,      # RFC 1035 - a mailbox domain name (EXPERIMENTAL)
    8 => :mg,      # RFC 1035 - a mail group member (EXPERIMENTAL)
    9 => :mr,      # RFC 1035 - a mail rename domain name (EXPERIMENTAL)
    10 => :null,   # RFC 1035 - a null RR (EXPERIMENTAL)
    11 => :wks,    # RFC 1035 - a well known service description
    12 => :ptr,    # RFC 1035 - a domain name pointer
    13 => :hinfo,  # RFC 1035 - host information
    14 => :minfo,  # RFC 1035 - mailbox or mail list information
    15 => :mx,     # RFC 1035 - mail exchange
    16 => :txt,    # RFC 1035 - text strings
    17 => :rp,
    18 => :afsdb,
    19 => :x25,
    20 => :isdn,
    21 => :rt,
    22 => :nsap,
    23 => :nsap_ptr,
    24 => :sig,
    25 => :key,
    26 => :px,
    27 => :gpos,
    28 => :aaaa,   # RFC 3596 - IP6 Address
    29 => :loc,    # RFC 1876 - Location Information
    30 => :nxt,    # RFC 3755 - Next Domain (OBSOLETE)
    31 => :eid,    # Nimrod Endpoint Identifier
    32 => :nimloc, # Nimrod Locator
    33 => :srv,    # RFC 2052 - Server Selection
    34 => :atma,   # ATM Address
    35 => :naptr,  # RFC 3403 - Naming Authority Pointer
    39 => :dname,  # RFC 2672 - DNAME
    41 => :opt,    # RFC 6891 - OPT
    48 => :dnskey, # RFC 4034 - DNS Key
    64 => :svcb,   # RFC 9460 - Service Binding
    65 => :https,  # RFC 9460 - HTTPS Service Parameter
    252 => :axfr,  # RFC 1035 - Authoritative Zone Transfer
    255 => :any,   # RFC 1035 - QTYPE ANY
    257 => :caa    # RFC 6844 - Certification Authority Authorization
  }

  @type_code_map for {k, v} <- @type_map, into: %{}, do: {v, k}

  @class_map %{
    1 => :in,     # RFC 1035 - Internet
    2 => :cs,     # RFC 1035 - CSNET (OBSOLETE)
    3 => :ch,     # RFC 1035 - CHAOS
    4 => :hs,     # RFC 1035 - Hesiod
    254 => :none, # RFC 2136 - QCLASS NONE
    255 => :any,  # RFC 1035 - QCLASS ANY
    65_536 => :max
  }

  @class_code_map for {k, v} <- @class_map, into: %{}, do: {v, k}

  @rcode_map %{
    0 => :noerror,
    1 => :formerr,
    2 => :servfail,
    3 => :nxdomain,
    4 => :notimp,
    5 => :refused,
    6 => :yxdomain,
    7 => :yxrrset,
    8 => :nxrrset,
    9 => :notauth,
    10 => :notzone,
    11 => :dsotypeni,
    16 => :badvers,
    17 => :badkey,
    18 => :badtime,
    19 => :badmode,
    20 => :badname,
    21 => :badalg,
    22 => :badtrunc,
    23 => :badcookie
  }

  @rcode_code_map for {k, v} <- @rcode_map, into: %{}, do: {v, k}

  # EDNS0 Option Codes
  # Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
  @option_map %{
    0 => :reserved,            # Reserved
    1 => :llq,                 # Apple - Long-lived query
    2 => :update_lease,        # RFC 4761 - Update Lease
    3 => :nsid,                # RFC 5001 - Name Server Identifier
    4 => :reserved4,           # Reserved
    5 => :dau,                 # RFC 6975 - DNSSEC Algorithm Understood
    6 => :dhu,                 # RFC 6975 - DS Hash Understood
    7 => :n3u,                 # RFC 6975 - NSEC3 Hash Understood
    8 => :edns_client_subnet,  # RFC 7871 - Client Subnet
    9 => :edns_expire,         # RFC 7314 - EDNS Expire
    10 => :cookie,             # RFC 7873 - DNS Cookie
    11 => :edns_tcp_keepalive, # RFC 7828 - TCP Keepalive
    12 => :padding,            # RFC 7830 - Padding
    13 => :chain,              # RFC 7901 - CHAIN Query
    14 => :edns_key_tag,       # RFC 8145 - Key Tag
    15 => :extended_dns_error, # RFC 8914 - Extended DNS Error
    16 => :edns_client_tag,    # draft-bellis-dnsop-edns-tags - Client Tag
    17 => :edns_server_tag,    # draft-bellis-dnsop-edns-tags - Server Tag
    18 => :report_channel,     # Apple - DNS Reporting
    19 => :zoneversion,        # Apple - Zone Version
    20_292 => :umbrella_ident, # Cisco Umbrella - Umbrella Identifier
    26_946 => :deviceid        # DSL Forum - Device ID
  }

  @option_code_map for {k, v} <- @option_map, into: %{}, do: {v, k}

  # Optimized pattern matching for most common DNS types with inlining
  def type(1), do: :a
  def type(2), do: :ns
  def type(5), do: :cname
  def type(15), do: :mx
  def type(16), do: :txt
  def type(28), do: :aaaa
  def type(41), do: :opt
  def type(255), do: :any
  def type(code), do: Map.get(@type_map, code)

  def type_code(:a), do: 1
  def type_code(:ns), do: 2
  def type_code(:cname), do: 5
  def type_code(:mx), do: 15
  def type_code(:txt), do: 16
  def type_code(:aaaa), do: 28
  def type_code(:opt), do: 41
  def type_code(:any), do: 255
  def type_code(atom), do: Map.get(@type_code_map, atom)

  # Optimized pattern matching for most common DNS classes with inlining
  def class(1), do: :in
  def class(255), do: :any
  def class(code), do: Map.get(@class_map, code)

  def class_code(:in), do: 1
  def class_code(:any), do: 255
  def class_code(atom), do: Map.get(@class_code_map, atom)

  # rcode lookup functions
  def rcode(code), do: Map.get(@rcode_map, code)
  def rcode_code(atom), do: Map.get(@rcode_code_map, atom)

  # option lookup functions
  def option(code), do: Map.get(@option_map, code)
  def option_code(atom), do: Map.get(@option_code_map, atom)

  @default_port 53
  @default_service "domain"

  # Pre-compile rcode text map for better performance
  @rcode_text %{
    :noerror => "No Error",
    :formerr => "Format Error",
    :servfail => "Server Failure",
    :nxdomain => "Non-Existent Domain",
    :notimp => "Not Implemented",
    :refused => "Query Refused",
    :yxdomain => "Name Exists when it should not",
    :yxrrset => "RR Set Exists when it should not",
    :nxrrset => "RR Set that should exist does not",
    :notauth => "Server Not Authoritative for zone",
    :notzone => "Name not contained in zone",
    :dsotypeni => "DSO-TYPE Not Implemented",
    :badvers => "Bad OPT Version / TSIG Signature Failure",
    :badsig => "Bad OPT Version / TSIG Signature Failure",
    :badkey => "Key not recognized",
    :badtime => "Signature out of time window",
    :badmode => "Bad TKEY Mode",
    :badname => "Duplicate key name",
    :badalg => "Algorithm not supported",
    :badtrunc => "Bad Truncation",
    :badcookie => "Bad/missing Server Cookie"
  }

  def rcode_text, do: @rcode_text

  def port, do: @default_port
  def service, do: @default_service

  def edns_max_udpsize, do: 1232
end
