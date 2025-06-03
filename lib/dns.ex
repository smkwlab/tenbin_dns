defmodule DNS do
  @moduledoc """
  DNS related constants
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
  @type_map %{
    1 => :a,
    2 => :ns,
    3 => :md,
    4 => :mf,
    5 => :cname,
    6 => :soa,
    7 => :mb,
    8 => :mg,
    9 => :mr,
    10 => :null,
    11 => :wks,
    12 => :ptr,
    13 => :hinfo,
    14 => :minfo,
    15 => :mx,
    16 => :txt,
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
    28 => :aaaa,
    29 => :loc,
    30 => :nxt,
    31 => :eid,
    32 => :nimloc,
    33 => :srv,
    34 => :atma,
    41 => :opt,
    64 => :svcb,
    65 => :https,
    252 => :axfr,
    255 => :any,
    257 => :caa
  }

  @type_code_map for {k, v} <- @type_map, into: %{}, do: {v, k}

  @class_map %{
    1 => :in,
    2 => :cs,
    3 => :ch,
    4 => :hs,
    254 => :none,
    255 => :any,
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

  @option_map %{
    0 => :reserved,
    1 => :llq,
    2 => :update_lease,
    3 => :nsid,
    4 => :reserved4,
    5 => :dau,
    6 => :dhu,
    7 => :n3u,
    8 => :edns_client_subnet,
    9 => :edns_expire,
    10 => :cookie,
    11 => :edns_tcp_keepalive,
    12 => :padding,
    13 => :chain,
    14 => :edns_key_tag,
    15 => :extended_dns_error,
    16 => :edns_client_tag,
    17 => :edns_server_tag,
    18 => :report_channel,
    19 => :zoneversion,
    20_292 => :umbrella_ident,
    26_946 => :deviceid
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
