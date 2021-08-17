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
  
  def port(), do: 53
  def service(), do: "domain"

end
