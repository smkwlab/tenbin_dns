defmodule LightweightEdnsTest do
  @moduledoc """
  Test the lightweight EDNS optimization (empty additional section fast path)
  """

  def run_test do
    IO.puts("=== Lightweight EDNS Optimization Test ===\n")
    
    test_empty_additional_optimization()
    test_real_world_impact()
    test_no_regression()
  end

  defp test_empty_additional_optimization do
    IO.puts("1. Empty additional section optimization:")
    
    edns_cases = [
      {"Empty EDNS", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}},
      {"Simple EDNS", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, 
                       options: %{edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}}}},
      {"Complex EDNS", create_complex_edns()}
    ]
    
    iterations = 50_000
    
    Enum.each(edns_cases, fn {name, edns_info} ->
      # Test optimized version (current - fast path for empty additional)
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          merge_edns_optimized([], edns_info)
        end
      end)
      
      # Test legacy version (always uses Enum.reject)
      {legacy_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          merge_edns_legacy([], edns_info)
        end
      end)
      
      improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
      
      IO.puts("  #{name}:")
      IO.puts("    Legacy (with Enum.reject): #{legacy_time}μs (#{Float.round(iterations / legacy_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Optimized (fast path):     #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Improvement: #{improvement}%")
    end)
  end

  defp test_real_world_impact do
    IO.puts("\n\n2. Real-world packet creation impact:")
    
    # Most DNS packets have empty additional sections before EDNS
    test_packets = [
      {"Simple packet (no EDNS)", create_simple_packet()},
      {"EDNS packet (empty additional)", create_simple_edns_packet()},
      {"EDNS with existing additional", create_edns_with_additional_packet()}
    ]
    
    iterations = 30_000
    
    Enum.each(test_packets, fn {name, packet} ->
      {create_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create(packet)
      end)
      
      additional_count = length(packet.additional)
      edns_info = if packet.edns_info, do: " (EDNS)", else: ""
      
      IO.puts("  #{name}: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec) - #{additional_count} additional#{edns_info}")
    end)
    
    # Calculate EDNS overhead with optimization
    simple_packet = create_simple_packet()
    edns_packet = create_simple_edns_packet()
    
    {simple_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(simple_packet)
    end)
    
    {edns_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(edns_packet)
    end)
    
    overhead = Float.round((edns_time - simple_time) / simple_time * 100, 1)
    IO.puts("\n  EDNS overhead: #{overhead}% (target: reduce from 14.3%)")
  end

  defp test_no_regression do
    IO.puts("\n\n3. No regression test for non-empty additional sections:")
    
    # Test with various additional section sizes
    additional_sizes = [1, 2, 5]
    edns_info = %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}
    iterations = 20_000
    
    Enum.each(additional_sizes, fn size ->
      additional = create_additional_records(size)
      
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          merge_edns_optimized(additional, edns_info)
        end
      end)
      
      {legacy_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          merge_edns_legacy(additional, edns_info)
        end
      end)
      
      performance_change = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
      
      IO.puts("  Additional size #{size}:")
      IO.puts("    Performance change: #{performance_change}% (should be ~0%)")
    end)
  end

  # Helper functions
  defp merge_edns_optimized([], edns_info) do
    # Optimized: fast path for empty additional
    [create_edns_info_record_simple(edns_info)]
  end
  defp merge_edns_optimized(additional, edns_info) do
    # Standard path for non-empty additional
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = create_edns_info_record_simple(edns_info)
    [opt_record | non_opt_records]
  end

  defp merge_edns_legacy(additional, edns_info) do
    # Legacy: always uses Enum.reject even for empty additional
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = create_edns_info_record_simple(edns_info)
    [opt_record | non_opt_records]
  end

  defp create_edns_info_record_simple(%{} = edns_info) do
    payload_size = Map.get(edns_info, :payload_size, 1232)
    ex_rcode = Map.get(edns_info, :ex_rcode, 0)
    version = Map.get(edns_info, :version, 0)
    dnssec = Map.get(edns_info, :dnssec, 0)
    z = Map.get(edns_info, :z, 0)
    options = Map.get(edns_info, :options, %{})

    %{
      name: "",
      type: :opt,
      payload_size: payload_size,
      ex_rcode: ex_rcode,
      version: version,
      dnssec: dnssec,
      z: z,
      rdata: convert_options_simple(options)
    }
  end

  defp convert_options_simple(%{} = options) do
    # Simplified for testing
    Enum.map(options, fn {key, value} -> {key, value} end)
  end

  defp create_additional_records(count) do
    for i <- 1..count do
      %{name: "record#{i}.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, i}}}
    end
  end

  # Test data generators
  defp create_simple_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]
    }
  end

  defp create_simple_edns_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      edns_info: %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}
    }
  end

  defp create_edns_with_additional_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      additional: [%{name: "ns1.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, 1, 1}}}],
      edns_info: %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}
    }
  end

  defp create_complex_edns do
    %{
      payload_size: 4096,
      ex_rcode: 0,
      version: 0,
      dnssec: 1,
      z: 0,
      options: %{
        edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}
      }
    }
  end
end

LightweightEdnsTest.run_test()