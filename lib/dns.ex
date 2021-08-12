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

  def port(), do: 53
  def service(), do: "domain"

end
