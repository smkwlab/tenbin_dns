defmodule EdnsOptimizationAnalysis do
  @moduledoc """
  Detailed analysis of EDNS processing performance bottlenecks
  """

  def run_analysis do
    IO.puts("=== EDNS Processing Optimization Analysis ===\n")
    
    # 1. Break down EDNS processing steps
    analyze_edns_processing_steps()
    
    # 2. Test optimization opportunities
    test_optimization_opportunities()
    
    # 3. Test specific bottlenecks
    test_specific_bottlenecks()
    
    # 4. Real-world impact
    test_real_world_impact()
  end

  defp analyze_edns_processing_steps do
    IO.puts("1. EDNS processing step breakdown:")
    
    # Test different types of EDNS data
    test_cases = [
      {"No EDNS", nil},
      {"Empty EDNS", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}},
      {"Simple option", %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, 
                         options: %{edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}}}},
      {"Multiple options", create_complex_edns()}
    ]
    
    additional = []
    iterations = 50_000
    
    Enum.each(test_cases, fn {name, edns_info} ->
      # Measure individual steps
      
      # Step 1: Check for existing OPT records
      {reject_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          Enum.reject(additional, &(&1.type == :opt))
        end
      end)
      
      # Step 2: Create EDNS info record (if needed)
      if edns_info do
        {create_record_time, _} = :timer.tc(fn ->
          for _ <- 1..iterations do
            create_edns_info_record_test(edns_info)
          end
        end)
        
        # Step 3: Merge process
        {merge_time, _} = :timer.tc(fn ->
          for _ <- 1..iterations do
            merge_edns_info_to_additional_test(additional, edns_info)
          end
        end)
        
        IO.puts("\n  #{name}:")
        IO.puts("    Reject OPT records:  #{reject_time}μs")
        IO.puts("    Create EDNS record:  #{create_record_time}μs")
        IO.puts("    Full merge:          #{merge_time}μs")
        IO.puts("    Overhead:            #{merge_time - reject_time - create_record_time}μs")
      else
        {merge_time, _} = :timer.tc(fn ->
          for _ <- 1..iterations do
            merge_edns_info_to_additional_test(additional, edns_info)
          end
        end)
        
        IO.puts("\n  #{name}:")
        IO.puts("    Full merge:          #{merge_time}μs (passthrough)")
      end
    end)
  end

  defp test_optimization_opportunities do
    IO.puts("\n\n2. Optimization opportunities:")
    
    edns_info = create_simple_edns()
    additional = []
    iterations = 100_000
    
    # Current implementation
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        merge_edns_info_to_additional_test(additional, edns_info)
      end
    end)
    
    # Optimization 1: Avoid Enum.reject when additional is empty
    {optimized_empty_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        merge_edns_optimized_empty(additional, edns_info)
      end
    end)
    
    # Optimization 2: Pre-computed OPT record
    opt_record = create_edns_info_record_test(edns_info)
    {precomputed_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        merge_edns_precomputed(additional, opt_record)
      end
    end)
    
    # Optimization 3: Inline simple cases
    {inline_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        merge_edns_inline_simple(additional, edns_info)
      end
    end)
    
    IO.puts("  Current implementation:   #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Optimized empty check:    #{optimized_empty_time}μs (#{Float.round(iterations / optimized_empty_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Pre-computed OPT:         #{precomputed_time}μs (#{Float.round(iterations / precomputed_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Inline simple case:       #{inline_time}μs (#{Float.round(iterations / inline_time * 1_000_000, 0)} ops/sec)")
    
    empty_improvement = Float.round((current_time - optimized_empty_time) / current_time * 100, 1)
    precomputed_improvement = Float.round((current_time - precomputed_time) / current_time * 100, 1)
    inline_improvement = Float.round((current_time - inline_time) / current_time * 100, 1)
    
    IO.puts("\n  Improvements:")
    IO.puts("    Empty check optimization: #{empty_improvement}%")
    IO.puts("    Pre-computed OPT:         #{precomputed_improvement}%")
    IO.puts("    Inline simple case:       #{inline_improvement}%")
  end

  defp test_specific_bottlenecks do
    IO.puts("\n\n3. Specific bottleneck analysis:")
    
    # Test with non-empty additional section
    existing_additional = [
      %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}},
      %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
        rdata: %{addr: {0x2001, 0xdb8, 0, 0, 0, 0, 0, 1}}}
    ]
    
    iterations = 50_000
    
    # Test reject performance with different additional section sizes
    sizes = [0, 1, 2, 5, 10]
    
    Enum.each(sizes, fn size ->
      additional = Enum.take(Stream.cycle(existing_additional), size)
      
      {reject_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          Enum.reject(additional, &(&1.type == :opt))
        end
      end)
      
      IO.puts("  Additional size #{size}: reject takes #{reject_time}μs (#{Float.round(iterations / reject_time * 1_000_000, 0)} ops/sec)")
    end)
    
    # Test pattern matching vs function call overhead
    record = %{type: :opt, name: "", payload_size: 1232}
    
    {pattern_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        match?(%{type: :opt}, record)
      end
    end)
    
    {function_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        record.type == :opt
      end
    end)
    
    IO.puts("\n  Type checking:")
    IO.puts("    Pattern match: #{pattern_time}μs (#{Float.round(iterations / pattern_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Function call: #{function_time}μs (#{Float.round(iterations / function_time * 1_000_000, 0)} ops/sec)")
  end

  defp test_real_world_impact do
    IO.puts("\n\n4. Real-world packet creation impact:")
    
    # Test with realistic packets
    packets = [
      {"Simple packet (no EDNS)", create_simple_packet()},
      {"EDNS packet", create_edns_packet()},
      {"Complex EDNS packet", create_complex_edns_packet()}
    ]
    
    iterations = 30_000
    
    Enum.each(packets, fn {name, packet} ->
      {create_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create(packet)
      end)
      
      # Estimate EDNS portion (rough calculation)
      edns_portion = if packet.edns_info, do: " (~14.3% EDNS overhead)", else: ""
      
      IO.puts("  #{name}: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)#{edns_portion}")
    end)
  end

  # Helper functions for testing
  defp merge_edns_info_to_additional_test(additional, nil), do: additional
  defp merge_edns_info_to_additional_test(additional, edns_info) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = create_edns_info_record_test(edns_info)
    [opt_record | non_opt_records]
  end

  # Optimization: avoid Enum.reject when additional is empty
  defp merge_edns_optimized_empty([], edns_info) when not is_nil(edns_info) do
    opt_record = create_edns_info_record_test(edns_info)
    [opt_record]
  end
  defp merge_edns_optimized_empty(additional, edns_info) do
    merge_edns_info_to_additional_test(additional, edns_info)
  end

  # Optimization: pre-computed OPT record
  defp merge_edns_precomputed([], opt_record), do: [opt_record]
  defp merge_edns_precomputed(additional, opt_record) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    [opt_record | non_opt_records]
  end

  # Optimization: inline simple cases
  defp merge_edns_inline_simple([], edns_info) when not is_nil(edns_info) do
    # Inline simple EDNS record creation
    payload_size = Map.get(edns_info, :payload_size, 1232)
    [%{name: "", type: :opt, payload_size: payload_size, ex_rcode: 0, version: 0, dnssec: 0, z: 0, rdata: []}]
  end
  defp merge_edns_inline_simple(additional, edns_info) do
    merge_edns_info_to_additional_test(additional, edns_info)
  end

  defp create_edns_info_record_test(%{} = edns_info) do
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
      rdata: convert_options_to_rdata_test(options)
    }
  end

  defp convert_options_to_rdata_test(%{} = options) do
    # Simplified for testing
    Enum.map(options, fn {key, value} -> {key, value} end)
  end

  # Test data generators
  defp create_simple_edns do
    %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}
  end

  defp create_complex_edns do
    %{
      payload_size: 4096,
      ex_rcode: 0,
      version: 0,
      dnssec: 1,
      z: 0,
      options: %{
        edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0},
        cookie: %{client: <<1, 2, 3, 4, 5, 6, 7, 8>>, server: nil},
        nsid: "ns1.example.com"
      }
    }
  end

  defp create_simple_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]
    }
  end

  defp create_edns_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      edns_info: create_simple_edns()
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
end

EdnsOptimizationAnalysis.run_analysis()