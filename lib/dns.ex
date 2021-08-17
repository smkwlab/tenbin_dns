defmodule DNS do
  def type() do
    %{
      1 => :a,
      :a => 1,
      2 => :ns,
      :ns => 2,
      5 => :cname,
      :cname => 5,
      6 => :soa,
      :soa => 6,
      11 => :wks,
      :wks => 11,
      12 => :ptr,
      :ptr => 12,
      13 => :hinfo,
      :hinfo => 13,
      15 => :mx,
      :mx => 15,
      16 => :txt,
      :txt => 16,
      28 => :aaaa,
      :aaaa => 28,
      41 => :opt,
      :opt => 41,
      64 => :svcb,
      :svcb => 64,
      65 => :https,
      :https => 65,

      252 => :axfr,
      :axfr => 252,
      255 => :all,
      :all => 255,
      :any => 255,

      257 => :caa,
      :caa => 257
    }
  end

  def class() do
    %{
      1 => :in,
      :in => 1,
      2 => :cs,
      :cs => 2,
      3 => :ch,
      :ch => 3,
      4 => :hs,
      :hs => 4,
      254 => :none,
      :none => 254,
      255 => :any,
      :any => 255,
      65536 => :max,
      :max => 65536,
    }
  end

  def rcode() do
    %{
      0 => :noerror,
      :noerror => 0,
      1 => :formerr,
      :formerr => 1,
      2 => :servfail,
      :servfail => 2,
      3 => :nxdomain,
      :nxdomain => 3,
      4 => :notimp,
      :notimp => 4,
      5 => :refused,
      :refused => 5,
    }
  end

  def rcode_text() do
    %{
      :noerror => "No Error",
      :formerr => "Format Error",
      :servfail => "Server Failure",
      :nxdomain => "Non-Existent Domain",
      :notimp => "Not Implemented",
      :refused => "Query Refused",
      
    }
  end
  
  def option() do
    %{
      0 => :reserved0,
      :reserved0 => 0,
      1 => :llq,
      :llq => 1,
      2 => :ul,
      :ul => 2,
      3 => :nsid,
      :nsid => 3,
      4 => :reserved4,
      :reserved4 => 4,
      5 => :dau,
      :dau => 5,
      6 => :dhu,
      :dhu => 6,
      7 => :n3u,
      :n3u => 7,
      8 => :edns_client_subnet,
      :edns_client_subnet => 8,
      9 => :edns_expire,
      :edns_expire => 9,
      10 => :cookie,
      :cookie => 10,
      11 => :edns_tcp_keepalive,
      :edns_tcp_keepalive => 11,
      12 => :padding,
      :padding => 12,
      13 => :chain,
      :chain => 13,
      14 => :edns_key_tag,
      :edns_key_tag => 14,
      15 => :extended_dns_error,
      :extended_dns_error => 15,
      16 => :edns_client_tag,
      :edns_client_tag => 16,
      17 => :edns_server_tag,
      :edns_server_tag => 17,

      26946 => :deviceid,
      :deviceid => 26946,
    }
  end
  
  def port(), do: 53
  def service(), do: "domain"

end
