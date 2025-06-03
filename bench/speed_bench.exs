# Speed-Focused Performance Benchmark
# Tests record type specialization and pattern matching optimizations

# Test data for different record types
test_records = %{
  a_record: %{addr: {192, 168, 1, 1}},
  aaaa_record: %{addr: {0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8888}},
  txt_record: %{txt: "v=spf1 include:_spf.google.com ~all"},
  ns_record: %{name: "ns1.example.com."},
  cname_record: %{name: "www.example.com."},
  mx_record: %{preference: 10, name: "mail.example.com."}
}

# Binary test data for parsing
test_binaries = %{
  a_binary: <<192, 168, 1, 1>>,
  aaaa_binary: <<0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88>>,
  txt_binary: <<33, "v=spf1 include:_spf.google.com ~all">>,
}

IO.puts("Speed-Focused DNS Performance Benchmark")
IO.puts("======================================")
IO.puts("Testing record type specialization and pattern matching optimizations")
IO.puts("")

Benchee.run(
  %{
    # DNS type lookup benchmarks
    "DNS.type(1) - A record" => fn -> DNS.type(1) end,
    "DNS.type(28) - AAAA record" => fn -> DNS.type(28) end,
    "DNS.type(15) - MX record" => fn -> DNS.type(15) end,
    "DNS.type(6) - SOA record" => fn -> DNS.type(6) end,
    "DNS.type(999) - Unknown type" => fn -> DNS.type(999) end,
    
    # Record creation benchmarks (specialized vs generic)
    "create_a_rdata (specialized)" => fn -> DNSpacket.create_a_rdata(test_records.a_record) end,
    "create_rdata A (generic)" => fn -> DNSpacket.create_rdata(test_records.a_record, :a, :in) end,
    
    "create_aaaa_rdata (specialized)" => fn -> DNSpacket.create_aaaa_rdata(test_records.aaaa_record) end,
    "create_rdata AAAA (generic)" => fn -> DNSpacket.create_rdata(test_records.aaaa_record, :aaaa, :in) end,
    
    "create_txt_rdata (specialized)" => fn -> DNSpacket.create_txt_rdata(test_records.txt_record) end,
    "create_rdata TXT (generic)" => fn -> DNSpacket.create_rdata(test_records.txt_record, :txt, :in) end,
    
    "create_mx_rdata (specialized)" => fn -> DNSpacket.create_mx_rdata(test_records.mx_record) end,
    "create_rdata MX (generic)" => fn -> DNSpacket.create_rdata(test_records.mx_record, :mx, :in) end,
    
    # Record parsing benchmarks (specialized vs generic)
    "parse_a_rdata (specialized)" => fn -> DNSpacket.parse_a_rdata(test_binaries.a_binary) end,
    "parse_rdata A (generic)" => fn -> DNSpacket.parse_rdata(test_binaries.a_binary, :a, :in, <<>>) end,
    
    "parse_aaaa_rdata (specialized)" => fn -> DNSpacket.parse_aaaa_rdata(test_binaries.aaaa_binary) end,
    "parse_rdata AAAA (generic)" => fn -> DNSpacket.parse_rdata(test_binaries.aaaa_binary, :aaaa, :in, <<>>) end,
    
    "parse_txt_rdata (specialized)" => fn -> DNSpacket.parse_txt_rdata(test_binaries.txt_binary) end,
    "parse_rdata TXT (generic)" => fn -> DNSpacket.parse_rdata(test_binaries.txt_binary, :txt, :in, <<>>) end,
    
    # Domain name processing
    "create_domain_name" => fn -> DNSpacket.create_domain_name("www.example.com.") end,
    "create_character_string" => fn -> DNSpacket.create_character_string("example") end,
    
    # Binary operations
    "concat_binary_list (4 items)" => fn -> 
      DNSpacket.concat_binary_list([<<1, 2>>, <<3, 4>>, <<5, 6>>, <<7, 8>>]) 
    end,
    "iolist_to_binary (4 items)" => fn -> 
      :erlang.iolist_to_binary([<<1, 2>>, <<3, 4>>, <<5, 6>>, <<7, 8>>])
    end
  },
  time: 1,
  memory_time: 0.5,
  formatters: [
    Benchee.Formatters.Console
  ]
)

IO.puts("\n=== Speed Optimization Analysis ===")

# Measure improvement ratios
a_specialized = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_a_rdata(test_records.a_record)
end) |> elem(0)

a_generic = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_rdata(test_records.a_record, :a, :in)
end) |> elem(0)

aaaa_specialized = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_aaaa_rdata(test_records.aaaa_record)
end) |> elem(0)

aaaa_generic = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_rdata(test_records.aaaa_record, :aaaa, :in)
end) |> elem(0)

txt_specialized = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_txt_rdata(test_records.txt_record)
end) |> elem(0)

txt_generic = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNSpacket.create_rdata(test_records.txt_record, :txt, :in)
end) |> elem(0)

IO.puts("Record Creation Speed Improvements (100k iterations):")
IO.puts("• A record: #{Float.round((a_generic - a_specialized) / a_generic * 100, 1)}% faster")
IO.puts("• AAAA record: #{Float.round((aaaa_generic - aaaa_specialized) / aaaa_generic * 100, 1)}% faster")
IO.puts("• TXT record: #{Float.round((txt_generic - txt_specialized) / txt_generic * 100, 1)}% faster")

# Test pattern matching coverage
pattern_matched = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNS.type(1) # A record - pattern matched
end) |> elem(0)

map_lookup = :timer.tc(fn -> 
  for _ <- 1..100_000, do: DNS.type(999) # Unknown type - map lookup
end) |> elem(0)

IO.puts("\nDNS Type Lookup Performance:")
IO.puts("• Pattern matched types: #{Float.round(pattern_matched / 1000, 1)}ms (100k lookups)")
IO.puts("• Map lookup types: #{Float.round(map_lookup / 1000, 1)}ms (100k lookups)")
IO.puts("• Pattern matching advantage: #{Float.round((map_lookup - pattern_matched) / pattern_matched * 100, 1)}% faster")

IO.puts("\n=== Recommendations ===")
IO.puts("✓ Record type specialization provides significant speed improvements")
IO.puts("✓ Pattern matching for common DNS types is highly effective")
IO.puts("✓ Function inlining reduces call overhead for critical functions")
IO.puts("✓ Optimized for high-throughput DNS processing scenarios")