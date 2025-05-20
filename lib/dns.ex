defmodule DNS do
  @moduledoc """
  DNS related constants
  """

  # type定義
  @type_pairs [
    {1, :a},
    {2, :ns},
    {3, :md},
    {4, :mf},
    {5, :cname},
    {6, :soa},
    {7, :mb},
    {8, :mg},
    {9, :mr},
    {10, :null},
    {11, :wks},
    {12, :ptr},
    {13, :hinfo},
    {14, :minfo},
    {15, :mx},
    {16, :txt},
    {17, :rp},
    {18, :afsdb},
    {19, :x25},
    {20, :isdn},
    {21, :rt},
    {22, :nsap},
    {23, :nsap_ptr},
    {24, :sig},
    {25, :key},
    {26, :px},
    {27, :gpos},
    {28, :aaaa},
    {29, :loc},
    {30, :nxt},
    {31, :eid},
    {32, :nimloc},
    {33, :srv},
    {34, :atma},
    {41, :opt},
    {64, :svcb},
    {65, :https},
    {252, :axfr},
    {255, :all},
    {255, :any},
    {257, :caa}
  ]

  # class定義
  @class_pairs [
    {1, :in},
    {2, :cs},
    {3, :ch},
    {4, :hs},
    {254, :none},
    {255, :any},
    {65_536, :max}
  ]

  # rcode定義
  @rcode_pairs [
    {0, :noerror},
    {1, :formerr},
    {2, :servfail},
    {3, :nxdomain},
    {4, :notimp},
    {5, :refused},
    {6, :yxdomain},
    {7, :yxrrset},
    {8, :nxrrset},
    {9, :notauth},
    {10, :notzone},
    {11, :dsotypeni},
    {16, :badvers},
    {16, :badsig},
    {17, :badkey},
    {18, :badtime},
    {19, :badmode},
    {20, :badname},
    {21, :badalg},
    {22, :badtrunc},
    {23, :badcookie}
  ]

  # option定義
  @option_pairs [
    {0, :reserved0},
    {1, :llq},
    {2, :ul},
    {3, :nsid},
    {4, :reserved4},
    {5, :dau},
    {6, :dhu},
    {7, :n3u},
    {8, :edns_client_subnet},
    {9, :edns_expire},
    {10, :cookie},
    {11, :edns_tcp_keepalive},
    {12, :padding},
    {13, :chain},
    {14, :edns_key_tag},
    {15, :extended_dns_error},
    {16, :edns_client_tag},
    {17, :edns_server_tag},
    {26_946, :deviceid}
  ]

  @type_map Map.new(@type_pairs)
  @type_reverse_map Map.new(@type_pairs, fn {k, v} -> {v, k} end)

  def type(num), do: Map.get(@type_map, num)
  def type_code(atom), do: Map.get(@type_reverse_map, atom)

  @class_map Map.new(@class_pairs)
  @class_reverse_map Map.new(@class_pairs, fn {k, v} -> {v, k} end)

  def class(num), do: Map.get(@class_map, num)
  def class_code(atom), do: Map.get(@class_reverse_map, atom)

  @rcode_map Map.new(@rcode_pairs)
  @rcode_reverse_map Map.new(@rcode_pairs, fn {k, v} -> {v, k} end)

  def rcode(num), do: Map.get(@rcode_map, num)
  def rcode_code(atom), do: Map.get(@rcode_reverse_map, atom)

  @option_map Map.new(@option_pairs)
  @option_reverse_map Map.new(@option_pairs, fn {k, v} -> {v, k} end)

  def option(num), do: Map.get(@option_map, num)
  def option_code(atom), do: Map.get(@option_reverse_map, atom)

  @default_port 53
  @default_service "domain"

  def rcode_text(), do: %{
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

  def port(), do: @default_port
  def service(), do: @default_service

  def edns_max_udpsize(), do: 1232
end
