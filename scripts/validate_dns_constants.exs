#!/usr/bin/env elixir

defmodule ValidateDNSConstants do
  @moduledoc """
  DNS定数の正当性を検証するスクリプト
  IANAレジストリの値と照合します
  """

  # IANA公式の値（2024年基準）
  @iana_types %{
    1 => {"A", "a host address", "RFC 1035"},
    2 => {"NS", "an authoritative name server", "RFC 1035"},
    5 => {"CNAME", "the canonical name for an alias", "RFC 1035"},
    6 => {"SOA", "marks the start of a zone of authority", "RFC 1035"},
    12 => {"PTR", "a domain name pointer", "RFC 1035"},
    15 => {"MX", "mail exchange", "RFC 1035"},
    16 => {"TXT", "text strings", "RFC 1035"},
    28 => {"AAAA", "IP6 Address", "RFC 3596"},
    41 => {"OPT", "OPT", "RFC 6891"},
    257 => {"CAA", "Certification Authority Restriction", "RFC 6844"}
  }

  @iana_classes %{
    1 => {"IN", "Internet", "RFC 1035"},
    2 => {"CS", "CSNET", "RFC 1035"},
    3 => {"CH", "CHAOS", "RFC 1035"},
    4 => {"HS", "Hesiod", "RFC 1035"},
    254 => {"NONE", "QCLASS NONE", "RFC 2136"},
    255 => {"ANY", "QCLASS ANY", "RFC 1035"}
  }

  @iana_rcodes %{
    0 => {"NOERROR", "No Error", "RFC 1035"},
    1 => {"FORMERR", "Format Error", "RFC 1035"},
    2 => {"SERVFAIL", "Server Failure", "RFC 1035"},
    3 => {"NXDOMAIN", "Non-Existent Domain", "RFC 1035"},
    4 => {"NOTIMP", "Not Implemented", "RFC 1035"},
    5 => {"REFUSED", "Query Refused", "RFC 1035"},
    16 => {"BADVERS", "Bad OPT Version", "RFC 6891"},
    23 => {"BADCOOKIE", "Bad/missing Server Cookie", "RFC 7873"}
  }

  @iana_edns_options %{
    1 => {"LLQ", "Long-lived query", "Apple"},
    2 => {"UL", "Update Lease", "RFC 4761"},
    3 => {"NSID", "Name Server Identifier", "RFC 5001"},
    5 => {"DAU", "DNSSEC Algorithm Understood", "RFC 6975"},
    6 => {"DHU", "DS Hash Understood", "RFC 6975"},
    7 => {"N3U", "NSEC3 Hash Understood", "RFC 6975"},
    8 => {"edns-client-subnet", "Client Subnet", "RFC 7871"},
    9 => {"EDNS EXPIRE", "EDNS Expire", "RFC 7314"},
    10 => {"COOKIE", "DNS Cookie", "RFC 7873"},
    11 => {"edns-tcp-keepalive", "TCP Keepalive", "RFC 7828"},
    12 => {"Padding", "Padding", "RFC 7830"},
    13 => {"CHAIN", "CHAIN Query", "RFC 7901"},
    14 => {"edns-key-tag", "Key Tag", "RFC 8145"},
    15 => {"Extended DNS Error", "Extended DNS Error", "RFC 8914"}
  }

  def run do
    IO.puts("DNS定数検証レポート")
    IO.puts("==================\n")

    validate_types()
    validate_classes()
    validate_rcodes()
    validate_edns_options()
  end

  defp validate_types do
    IO.puts("## DNS Types")
    IO.puts("------------")
    
    type_map = %{
      1 => :a,
      2 => :ns,
      5 => :cname,
      6 => :soa,
      12 => :ptr,
      15 => :mx,
      16 => :txt,
      28 => :aaaa,
      41 => :opt,
      257 => :caa
    }

    Enum.each(type_map, fn {code, atom} ->
      case @iana_types[code] do
        {iana_name, desc, rfc} ->
          expected = normalize_name(iana_name)
          actual = to_string(atom)
          
          if expected == actual do
            IO.puts("✅ #{code} => :#{atom} (#{desc}) - #{rfc}")
          else
            IO.puts("❌ #{code} => :#{atom} (Expected: :#{expected}, IANA: #{iana_name}) - #{rfc}")
          end
        nil ->
          IO.puts("⚠️  #{code} => :#{atom} (Not in IANA registry)")
      end
    end)
    IO.puts("")
  end

  defp validate_classes do
    IO.puts("## DNS Classes")
    IO.puts("--------------")
    
    class_map = %{
      1 => :in,
      2 => :cs,
      3 => :ch,
      4 => :hs,
      254 => :none,
      255 => :any
    }

    Enum.each(class_map, fn {code, atom} ->
      case @iana_classes[code] do
        {iana_name, desc, rfc} ->
          expected = normalize_name(iana_name)
          actual = to_string(atom)
          
          if expected == actual do
            IO.puts("✅ #{code} => :#{atom} (#{desc}) - #{rfc}")
          else
            IO.puts("❌ #{code} => :#{atom} (Expected: :#{expected}, IANA: #{iana_name}) - #{rfc}")
          end
        nil ->
          IO.puts("⚠️  #{code} => :#{atom} (Not in IANA registry)")
      end
    end)
    IO.puts("")
  end

  defp validate_rcodes do
    IO.puts("## Response Codes (RCODEs)")
    IO.puts("--------------------------")
    
    rcode_map = %{
      0 => :noerror,
      1 => :formerr,
      2 => :servfail,
      3 => :nxdomain,
      4 => :notimp,
      5 => :refused,
      16 => :badvers,
      23 => :badcookie
    }

    Enum.each(rcode_map, fn {code, atom} ->
      case @iana_rcodes[code] do
        {iana_name, desc, rfc} ->
          expected = normalize_name(iana_name)
          actual = to_string(atom)
          
          if expected == actual do
            IO.puts("✅ #{code} => :#{atom} (#{desc}) - #{rfc}")
          else
            IO.puts("❌ #{code} => :#{atom} (Expected: :#{expected}, IANA: #{iana_name}) - #{rfc}")
          end
        nil ->
          IO.puts("⚠️  #{code} => :#{atom} (Not in IANA registry)")
      end
    end)
    IO.puts("")
  end

  defp validate_edns_options do
    IO.puts("## EDNS0 Option Codes")
    IO.puts("---------------------")
    
    option_map = %{
      1 => :llq,
      2 => :update_lease,
      3 => :nsid,
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
      15 => :extended_dns_error
    }

    Enum.each(option_map, fn {code, atom} ->
      case @iana_edns_options[code] do
        {iana_name, desc, rfc} ->
          expected = normalize_edns_name(iana_name)
          actual = to_string(atom)
          
          if expected == actual do
            IO.puts("✅ #{code} => :#{atom} (#{desc}) - #{rfc}")
          else
            IO.puts("❌ #{code} => :#{atom} (Expected: :#{expected}, IANA: #{iana_name}) - #{rfc}")
          end
        nil ->
          IO.puts("⚠️  #{code} => :#{atom} (Not in IANA registry)")
      end
    end)
    IO.puts("")
  end

  defp normalize_name(name) do
    name
    |> String.downcase()
    |> String.replace("-", "_")
  end

  defp normalize_edns_name(name) do
    case name do
      "LLQ" -> "llq"
      "UL" -> "update_lease"
      "NSID" -> "nsid"
      "DAU" -> "dau"
      "DHU" -> "dhu"
      "N3U" -> "n3u"
      "edns-client-subnet" -> "edns_client_subnet"
      "EDNS EXPIRE" -> "edns_expire"
      "COOKIE" -> "cookie"
      "edns-tcp-keepalive" -> "edns_tcp_keepalive"
      "Padding" -> "padding"
      "CHAIN" -> "chain"
      "edns-key-tag" -> "edns_key_tag"
      "Extended DNS Error" -> "extended_dns_error"
      _ -> normalize_name(name)
    end
  end
end

ValidateDNSConstants.run()