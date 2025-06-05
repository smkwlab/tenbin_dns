defmodule EdnsOptimizationTest do
  @moduledoc """
  Test the effectiveness of EDNS processing optimization
  """

  def run_test do
    IO.puts("=== EDNS Processing Optimization Test ===\n")
    
    test_edns_processing_improvement()
    test_packet_creation_impact()
    test_edge_cases()
  end

  defp test_edns_processing_improvement do
    IO.puts("1. EDNS processing performance improvement:")
    
    test_cases = [
      {"Empty EDNS (most common)", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}},
      {"Simple EDNS option", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, 
                               options: %{edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}}}},
      {"Complex EDNS", create_complex_edns()}
    ]
    
    additional_cases = [
      {"Empty additional", []},
      {"Non-empty additional", [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]}
    ]
    
    iterations = 50_000
    
    Enum.each(additional_cases, fn {additional_name, additional} ->
      IO.puts("\n  With #{additional_name}:")
      
      Enum.each(test_cases, fn {edns_name, edns_info} ->
        # Test optimized version (current)
        {optimized_time, _} = :timer.tc(fn ->
          for _ <- 1..iterations do
            merge_edns_info_to_additional_optimized(additional, edns_info)
          end
        end)
        
        # Test legacy version (simulated)
        {legacy_time, _} = :timer.tc(fn ->
          for _ <- 1..iterations do
            merge_edns_info_to_additional_legacy(additional, edns_info)
          end
        end)
        
        improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
        
        IO.puts("    #{edns_name}:")
        IO.puts("      Legacy:    #{legacy_time}μs (#{Float.round(iterations / legacy_time * 1_000_000, 0)} ops/sec)")
        IO.puts("      Optimized: #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
        IO.puts("      Improvement: #{improvement}%")
      end)
    end)
  end

  defp test_packet_creation_impact do
    IO.puts("\n\n2. Full packet creation impact:")
    
    test_packets = [
      {"Simple packet (no EDNS)", create_simple_packet()},
      {"EDNS packet (empty options)", create_simple_edns_packet()},
      {"EDNS packet (with options)", create_complex_edns_packet()}
    ]
    
    iterations = 30_000
    
    Enum.each(test_packets, fn {name, packet} ->
      # Test optimized version (current)
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create(packet)
      end)
      
      edns_info = if packet.edns_info, do: " (EDNS optimized)", else: ""
      
      IO.puts("  #{name}: #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)#{edns_info}")
    end)
    
    # Compare with our baseline from previous analysis
    simple_packet = create_simple_packet()
    edns_packet = create_simple_edns_packet()
    
    {simple_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(simple_packet)
    end)
    
    {edns_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(edns_packet)
    end)
    
    overhead = Float.round((edns_time - simple_time) / simple_time * 100, 1)
    IO.puts("\n  EDNS overhead: #{overhead}% (was 14.3% before optimization)")
  end

  defp test_edge_cases do
    IO.puts("\n\n3. Edge case verification:")
    
    edge_cases = [
      {"Nil EDNS info", nil},
      {"Empty options map", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}},
      {"Missing fields", %{payload_size: 4096}},
      {"All defaults", %{}}
    ]
    
    Enum.each(edge_cases, fn {name, edns_info} ->
      # Test with empty additional (most common)
      result = merge_edns_info_to_additional_optimized([], edns_info)
      
      expected_count = if edns_info, do: 1, else: 0
      actual_count = length(result)
      
      IO.puts("  #{name}: #{actual_count} records (expected #{expected_count}) - #{if actual_count == expected_count, do: "✅", else: "❌"}")
      
      if edns_info && actual_count > 0 do
        opt_record = hd(result)
        IO.puts("    OPT record type: #{opt_record.type} - #{if opt_record.type == :opt, do: "✅", else: "❌"}")
      end
    end)
  end

  # Optimized version (current implementation)
  defp merge_edns_info_to_additional_optimized(additional, nil), do: additional
  defp merge_edns_info_to_additional_optimized([], edns_info) do
    [create_edns_info_record_optimized(edns_info)]
  end
  defp merge_edns_info_to_additional_optimized(additional, edns_info) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = create_edns_info_record_optimized(edns_info)
    [opt_record | non_opt_records]
  end

  # Legacy version (simulated old behavior)
  defp merge_edns_info_to_additional_legacy(additional, nil), do: additional
  defp merge_edns_info_to_additional_legacy(additional, edns_info) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = create_edns_info_record_legacy(edns_info)
    [opt_record | non_opt_records]
  end

  # Optimized EDNS record creation
  defp create_edns_info_record_optimized(%{} = edns_info) do
    payload_size = edns_info[:payload_size] || 1232
    ex_rcode = edns_info[:ex_rcode] || 0
    version = edns_info[:version] || 0
    dnssec = edns_info[:dnssec] || 0
    z = edns_info[:z] || 0
    options = edns_info[:options] || %{}

    %{
      name: "",
      type: :opt,
      payload_size: payload_size,
      ex_rcode: ex_rcode,
      version: version,
      dnssec: dnssec,
      z: z,
      rdata: if(map_size(options) == 0, do: [], else: convert_options_to_rdata_simple(options))
    }
  end

  # Legacy EDNS record creation (using Map.get)
  defp create_edns_info_record_legacy(%{} = edns_info) do
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
      rdata: convert_options_to_rdata_simple(options)
    }
  end

  defp convert_options_to_rdata_simple(%{} = options) do
    # Simplified for testing
    Enum.map(options, fn {key, value} -> {key, value} end)
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

  defp create_complex_edns_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      edns_info: create_complex_edns()
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

EdnsOptimizationTest.run_test()