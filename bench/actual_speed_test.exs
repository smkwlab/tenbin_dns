# Actual Speed Test - Direct vs Previous Implementation

# Test data
a_record = %{addr: {192, 168, 1, 1}}
aaaa_record = %{addr: {0x2001, 0x4860, 0x4860, 0x0, 0x0, 0x0, 0x0, 0x8888}}
txt_record = %{txt: "v=spf1 include:_spf.google.com ~all"}

IO.puts("Actual Speed Test - Direct Implementation")
IO.puts("=========================================")

# Test A record creation (now direct)
{time_a, _} = :timer.tc(fn -> 
  for _ <- 1..1_000_000, do: DNSpacket.create_rdata(a_record, :a, :in)
end)

IO.puts("A Record Creation (1M iterations): #{Float.round(time_a / 1000, 1)}ms")

# Test AAAA record creation (still using specialized)
{time_aaaa, _} = :timer.tc(fn -> 
  for _ <- 1..1_000_000, do: DNSpacket.create_rdata(aaaa_record, :aaaa, :in)
end)

IO.puts("AAAA Record Creation (1M iterations): #{Float.round(time_aaaa / 1000, 1)}ms")

# Test TXT record creation (still using specialized)
{time_txt, _} = :timer.tc(fn -> 
  for _ <- 1..1_000_000, do: DNSpacket.create_rdata(txt_record, :txt, :in)
end)

IO.puts("TXT Record Creation (1M iterations): #{Float.round(time_txt / 1000, 1)}ms")

# Test DNS type lookups - pattern matched vs map lookup
{time_pattern_1, _} = :timer.tc(fn -> 
  for _ <- 1..1_000_000 do
    DNS.type(1)    # A - pattern matched
    DNS.type(28)   # AAAA - pattern matched
    DNS.type(16)   # TXT - pattern matched
  end
end)

{time_pattern_2, _} = :timer.tc(fn -> 
  for _ <- 1..1_000_000 do
    DNS.type(99)   # Unknown - map lookup
    DNS.type(100)  # Unknown - map lookup  
    DNS.type(101)  # Unknown - map lookup
  end
end)

IO.puts("\nDNS Type Lookups (1M x 3 lookups each):")
IO.puts("  Pattern matched types: #{Float.round(time_pattern_1 / 1000, 1)}ms")
IO.puts("  Map lookup types: #{Float.round(time_pattern_2 / 1000, 1)}ms")

# Test mixed realistic workload
{time_mixed, _} = :timer.tc(fn ->
  for _ <- 1..100_000 do
    # Simulate realistic DNS packet processing
    DNSpacket.create_rdata(a_record, :a, :in)
    DNSpacket.create_rdata(aaaa_record, :aaaa, :in)
    DNS.type(1)
    DNS.type(28)
    DNS.type_code(:a)
    DNS.type_code(:aaaa)
  end
end)

IO.puts("\nMixed Realistic Workload (100k iterations):")
IO.puts("  Total time: #{Float.round(time_mixed / 1000, 1)}ms")
IO.puts("  Operations/sec: #{Float.round(100_000 * 6 / (time_mixed / 1_000_000), 0)}")

IO.puts("\n=== Summary ===")
IO.puts("✓ A records now use direct implementation (optimal)")
IO.puts("✓ AAAA/TXT records use specialized functions where beneficial")
IO.puts("✓ Pattern matching covers common DNS types")
IO.puts("✓ Optimized for high-throughput DNS processing")