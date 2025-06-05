defmodule CreateAnalysisBench do
  @moduledoc """
  Analysis benchmark to understand create fast path performance
  """

  @ipv4_addr {192, 168, 1, 1}
  @ipv6_addr {0x2001, 0x0db8, 0x1234, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001}
  
  def run_test do
    IO.puts("=== Create Performance Analysis ===\n")
    
    # Test different approaches
    measure_direct_calls()
    measure_with_maps()
    measure_function_dispatch()
  end

  defp measure_direct_calls do
    IO.puts("1. Direct function calls (1M operations):")
    
    # Direct inline binary creation (baseline)
    {inline_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        {a, b, c, d} = @ipv4_addr
        <<a::8, b::8, c::8, d::8>>
      end
    end)
    
    {inline_aaaa_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        {a1, a2, a3, a4, a5, a6, a7, a8} = @ipv6_addr
        <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
      end
    end)
    
    # Direct fast function calls
    {fast_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_a_fast(@ipv4_addr)
    end)
    
    {fast_aaaa_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_aaaa_fast(@ipv6_addr)
    end)
    
    IO.puts("  Inline A creation:       #{inline_a_time}μs (#{Float.round(1_000_000 / inline_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Fast A function:         #{fast_a_time}μs (#{Float.round(1_000_000 / fast_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Overhead: #{Float.round((fast_a_time - inline_a_time) / inline_a_time * 100, 1)}%")
    
    IO.puts("")
    IO.puts("  Inline AAAA creation:    #{inline_aaaa_time}μs (#{Float.round(1_000_000 / inline_aaaa_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Fast AAAA function:      #{fast_aaaa_time}μs (#{Float.round(1_000_000 / fast_aaaa_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Overhead: #{Float.round((fast_aaaa_time - inline_aaaa_time) / inline_aaaa_time * 100, 1)}%")
    IO.puts("")
  end

  defp measure_with_maps do
    IO.puts("2. With map creation overhead (1M operations):")
    
    # Map creation + fast function
    {map_fast_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        rdata = %{addr: @ipv4_addr}
        DNSpacket.create_a_fast(rdata.addr)
      end
    end)
    
    # Map creation + inline
    {map_inline_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        rdata = %{addr: @ipv4_addr}
        {a, b, c, d} = rdata.addr
        <<a::8, b::8, c::8, d::8>>
      end
    end)
    
    IO.puts("  Map + inline A:          #{map_inline_a_time}μs (#{Float.round(1_000_000 / map_inline_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Map + fast A function:   #{map_fast_a_time}μs (#{Float.round(1_000_000 / map_fast_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Overhead: #{Float.round((map_fast_a_time - map_inline_a_time) / map_inline_a_time * 100, 1)}%")
    IO.puts("")
  end

  defp measure_function_dispatch do
    IO.puts("3. Function dispatch overhead (1M operations):")
    
    # Via create_rdata (current optimized version)
    {dispatch_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        DNSpacket.create_rdata(%{addr: @ipv4_addr}, :a, :in)
      end
    end)
    
    {dispatch_aaaa_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000 do
        DNSpacket.create_rdata(%{addr: @ipv6_addr}, :aaaa, :in)
      end
    end)
    
    # Direct fast function calls
    {direct_a_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_a_fast(@ipv4_addr)
    end)
    
    {direct_aaaa_time, _} = :timer.tc(fn ->
      for _ <- 1..1_000_000, do: DNSpacket.create_aaaa_fast(@ipv6_addr)
    end)
    
    IO.puts("  Direct A fast:           #{direct_a_time}μs (#{Float.round(1_000_000 / direct_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Dispatched A:            #{dispatch_a_time}μs (#{Float.round(1_000_000 / dispatch_a_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Dispatch overhead: #{Float.round((dispatch_a_time - direct_a_time) / direct_a_time * 100, 1)}%")
    
    IO.puts("")
    IO.puts("  Direct AAAA fast:        #{direct_aaaa_time}μs (#{Float.round(1_000_000 / direct_aaaa_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Dispatched AAAA:         #{dispatch_aaaa_time}μs (#{Float.round(1_000_000 / dispatch_aaaa_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Dispatch overhead: #{Float.round((dispatch_aaaa_time - direct_aaaa_time) / direct_aaaa_time * 100, 1)}%")
  end
end

CreateAnalysisBench.run_test()