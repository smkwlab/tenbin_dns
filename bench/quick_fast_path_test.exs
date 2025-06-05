defmodule QuickFastPathTest do
  @moduledoc """
  Quick performance test for A/AAAA fast paths
  """

  @ipv4_rdata <<192, 168, 1, 1>>
  @ipv6_rdata <<0x2001::16, 0x0db8::16, 0x1234::16, 0x0000::16, 
                0x0000::16, 0x0000::16, 0x0000::16, 0x0001::16>>

  def run_test do
    IO.puts("=== Quick A/AAAA Fast Path Performance Test ===\n")
    
    # Test correctness
    verify_correctness()
    
    # Simple performance measurement
    measure_performance()
  end

  defp verify_correctness do
    IO.puts("1. Verifying correctness:")
    
    # Test A record
    fast_a = DNSpacket.parse_a_fast(@ipv4_rdata)
    optimized_a = DNSpacket.parse_rdata(@ipv4_rdata, :a, :in, nil)
    IO.puts("  A record fast path: #{inspect(fast_a)}")
    IO.puts("  A record optimized: #{inspect(optimized_a)}")
    IO.puts("  Match: #{fast_a == optimized_a}")
    
    # Test AAAA record  
    fast_aaaa = DNSpacket.parse_aaaa_fast(@ipv6_rdata)
    optimized_aaaa = DNSpacket.parse_rdata(@ipv6_rdata, :aaaa, :in, nil)
    IO.puts("  AAAA record fast path: #{inspect(fast_aaaa)}")
    IO.puts("  AAAA record optimized: #{inspect(optimized_aaaa)}")
    IO.puts("  Match: #{fast_aaaa == optimized_aaaa}")
    
    IO.puts("")
  end

  defp measure_performance do
    IO.puts("2. Performance measurement (1M operations):")
    
    # A record performance
    {a_fast_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.parse_a_fast(@ipv4_rdata)
    end)
    
    {a_optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.parse_rdata(@ipv4_rdata, :a, :in, nil)
    end)
    
    # AAAA record performance
    {aaaa_fast_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.parse_aaaa_fast(@ipv6_rdata)
    end)
    
    {aaaa_optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.parse_rdata(@ipv6_rdata, :aaaa, :in, nil)
    end)
    
    IO.puts("  A record fast path:    #{a_fast_time}μs (#{Float.round(1_000_000 / a_fast_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  A record optimized:    #{a_optimized_time}μs (#{Float.round(1_000_000 / a_optimized_time * 1_000_000, 0)} ops/sec)")
    
    a_improvement = Float.round((a_optimized_time - a_fast_time) / a_optimized_time * 100, 1)
    IO.puts("  A record improvement:  #{a_improvement}%")
    
    IO.puts("")
    IO.puts("  AAAA record fast path: #{aaaa_fast_time}μs (#{Float.round(1_000_000 / aaaa_fast_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  AAAA record optimized: #{aaaa_optimized_time}μs (#{Float.round(1_000_000 / aaaa_optimized_time * 1_000_000, 0)} ops/sec)")
    
    aaaa_improvement = Float.round((aaaa_optimized_time - aaaa_fast_time) / aaaa_optimized_time * 100, 1)
    IO.puts("  AAAA record improvement: #{aaaa_improvement}%")
    
    IO.puts("\n3. Real-world impact estimation:")
    IO.puts("  For DNS server processing 1M A records/sec:")
    IO.puts("  - Fast path saves: #{Float.round((a_optimized_time - a_fast_time) / 1000, 1)}ms per million operations")
    IO.puts("  - Annual time saved: #{Float.round((a_optimized_time - a_fast_time) * 365 * 24 * 3600 / 1000 / 1000, 1)} seconds")
  end
end

QuickFastPathTest.run_test()