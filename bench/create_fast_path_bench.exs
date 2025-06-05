defmodule CreateFastPathBench do
  @moduledoc """
  Benchmark for A/AAAA record create fast path optimization
  """

  # Test data representing real DNS traffic patterns
  @ipv4_addr {192, 168, 1, 1}
  @ipv6_addr {0x2001, 0x0db8, 0x1234, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001}
  
  def run_test do
    IO.puts("=== A/AAAA Create Fast Path Performance Test ===\n")
    
    # Test correctness
    verify_correctness()
    
    # Simple performance measurement
    measure_performance()
  end

  defp verify_correctness do
    IO.puts("1. Verifying correctness:")
    
    # Test A record creation
    fast_a = DNSpacket.create_a_fast(@ipv4_addr)
    rdata_a = DNSpacket.create_rdata(%{addr: @ipv4_addr}, :a, :in)
    IO.puts("  A record fast path: #{inspect(fast_a)}")
    IO.puts("  A record via create_rdata: #{inspect(rdata_a)}")
    IO.puts("  Match: #{fast_a == rdata_a}")
    
    # Test AAAA record creation
    fast_aaaa = DNSpacket.create_aaaa_fast(@ipv6_addr)
    rdata_aaaa = DNSpacket.create_rdata(%{addr: @ipv6_addr}, :aaaa, :in)
    IO.puts("  AAAA record fast path: #{inspect(fast_aaaa)}")
    IO.puts("  AAAA record via create_rdata: #{inspect(rdata_aaaa)}")
    IO.puts("  Match: #{fast_aaaa == rdata_aaaa}")
    
    IO.puts("")
  end

  # Legacy create_rdata implementations for comparison
  defp create_rdata_legacy_a(%{addr: {a, b, c, d}}, :a, :in) do
    <<a::8, b::8, c::8, d::8>>
  end

  defp create_rdata_legacy_aaaa(%{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}, :aaaa, :in) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  defp measure_performance do
    IO.puts("2. Performance measurement (1M operations):")
    
    # A record performance
    {a_fast_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_a_fast(@ipv4_addr)
    end)
    
    {a_legacy_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: create_rdata_legacy_a(%{addr: @ipv4_addr}, :a, :in)
    end)
    
    {a_optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_rdata(%{addr: @ipv4_addr}, :a, :in)
    end)
    
    # AAAA record performance
    {aaaa_fast_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_aaaa_fast(@ipv6_addr)
    end)
    
    {aaaa_legacy_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: create_rdata_legacy_aaaa(%{addr: @ipv6_addr}, :aaaa, :in)
    end)
    
    {aaaa_optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_rdata(%{addr: @ipv6_addr}, :aaaa, :in)
    end)
    
    IO.puts("  A record fast path:      #{a_fast_time}μs (#{Float.round(1_000_000 / a_fast_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  A record legacy:         #{a_legacy_time}μs (#{Float.round(1_000_000 / a_legacy_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  A record optimized:      #{a_optimized_time}μs (#{Float.round(1_000_000 / a_optimized_time * 1_000_000, 0)} ops/sec)")
    
    a_improvement = Float.round((a_legacy_time - a_fast_time) / a_legacy_time * 100, 1)
    a_vs_optimized = Float.round((a_optimized_time - a_fast_time) / a_optimized_time * 100, 1)
    IO.puts("  A record vs legacy:      #{a_improvement}%")
    IO.puts("  A record vs optimized:   #{a_vs_optimized}%")
    
    IO.puts("")
    IO.puts("  AAAA record fast path:   #{aaaa_fast_time}μs (#{Float.round(1_000_000 / aaaa_fast_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  AAAA record legacy:      #{aaaa_legacy_time}μs (#{Float.round(1_000_000 / aaaa_legacy_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  AAAA record optimized:   #{aaaa_optimized_time}μs (#{Float.round(1_000_000 / aaaa_optimized_time * 1_000_000, 0)} ops/sec)")
    
    aaaa_improvement = Float.round((aaaa_legacy_time - aaaa_fast_time) / aaaa_legacy_time * 100, 1)
    aaaa_vs_optimized = Float.round((aaaa_optimized_time - aaaa_fast_time) / aaaa_optimized_time * 100, 1)
    IO.puts("  AAAA record vs legacy:   #{aaaa_improvement}%")
    IO.puts("  AAAA record vs optimized: #{aaaa_vs_optimized}%")
    
    IO.puts("\n3. Real-world impact estimation:")
    IO.puts("  For DNS server creating 1M A records/sec:")
    IO.puts("  - Fast path saves: #{Float.round((a_legacy_time - a_fast_time) / 1000, 1)}ms per million operations")
    IO.puts("  - Annual time saved: #{Float.round((a_legacy_time - a_fast_time) * 365 * 24 * 3600 / 1000 / 1000, 1)} seconds")
  end
end

CreateFastPathBench.run_test()