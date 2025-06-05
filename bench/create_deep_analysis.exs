defmodule CreateDeepAnalysis do
  @moduledoc """
  Deep analysis of DNS packet creation to find real optimization opportunities
  """

  def run_analysis do
    IO.puts("=== Deep DNS Create Performance Analysis ===\n")
    
    # Focus on the real bottlenecks
    analyze_enum_overhead()
    analyze_function_call_overhead()
    analyze_length_calculation_overhead()
    analyze_edns_processing_overhead()
  end

  defp analyze_enum_overhead do
    IO.puts("1. Analyzing Enum processing overhead:")
    
    # Create test data
    packet = create_test_packet()
    iterations = 50_000
    
    # Test different ways to process lists
    
    # Current: Enum.map + IO.iodata_to_binary
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        packet.answer
        |> Enum.map(&DNSpacket.create_rr/1)
        |> IO.iodata_to_binary()
      end
    end)
    
    # Optimization 1: for comprehension + IO.iodata_to_binary
    {comprehension_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        IO.iodata_to_binary(for rr <- packet.answer, do: DNSpacket.create_rr(rr))
      end
    end)
    
    # Optimization 2: Reduce with binary concatenation
    {reduce_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.reduce(packet.answer, <<>>, fn rr, acc ->
          acc <> DNSpacket.create_rr(rr)
        end)
      end
    end)
    
    # Optimization 3: Tail-recursive builder
    {tail_rec_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        build_answer_tail_rec(packet.answer, <<>>)
      end
    end)
    
    IO.puts("  Current (Enum.map):     #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  For comprehension:      #{comprehension_time}μs (#{Float.round(iterations / comprehension_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Reduce concat:          #{reduce_time}μs (#{Float.round(iterations / reduce_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Tail recursive:         #{tail_rec_time}μs (#{Float.round(iterations / tail_rec_time * 1_000_000, 0)} ops/sec)")
    
    best_time = Enum.min([current_time, comprehension_time, reduce_time, tail_rec_time])
    improvement = Float.round((current_time - best_time) / current_time * 100, 1)
    IO.puts("  Best improvement: #{improvement}%")
    IO.puts("")
  end

  defp analyze_function_call_overhead do
    IO.puts("2. Analyzing function call overhead:")
    
    packet = create_test_packet()
    iterations = 30_000
    
    # Test inlining create_rr components
    
    # Current: Full function call
    {full_call_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.map(packet.answer, &DNSpacket.create_rr/1)
      end
    end)
    
    # Optimization: Inline create_rr logic
    {inline_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.map(packet.answer, fn rr ->
          DNSpacket.create_domain_name(rr.name) <>
          <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
          add_rdlength(DNSpacket.create_rdata(rr.rdata, rr.type, rr.class))
        end)
      end
    end)
    
    # Test domain name caching
    domain_cache = %{"example.com." => DNSpacket.create_domain_name("example.com.")}
    
    {cached_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.map(packet.answer, fn rr ->
          domain_bin = Map.get(domain_cache, rr.name, DNSpacket.create_domain_name(rr.name))
          domain_bin <>
          <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
          add_rdlength(DNSpacket.create_rdata(rr.rdata, rr.type, rr.class))
        end)
      end
    end)
    
    IO.puts("  Full function call:     #{full_call_time}μs (#{Float.round(iterations / full_call_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Inlined logic:          #{inline_time}μs (#{Float.round(iterations / inline_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  With domain caching:    #{cached_time}μs (#{Float.round(iterations / cached_time * 1_000_000, 0)} ops/sec)")
    
    inline_improvement = Float.round((full_call_time - inline_time) / full_call_time * 100, 1)
    cache_improvement = Float.round((full_call_time - cached_time) / full_call_time * 100, 1)
    
    IO.puts("  Inline improvement: #{inline_improvement}%")
    IO.puts("  Cache improvement:  #{cache_improvement}%")
    IO.puts("")
  end

  defp analyze_length_calculation_overhead do
    IO.puts("3. Analyzing length calculation overhead:")
    
    packet = create_test_packet()
    iterations = 100_000
    
    # Current: Multiple length() calls
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        length(packet.question) + length(packet.answer) + 
        length(packet.authority) + length(packet.additional)
      end
    end)
    
    # Optimization: Pre-calculate lengths
    question_len = length(packet.question)
    answer_len = length(packet.answer)
    authority_len = length(packet.authority)
    additional_len = length(packet.additional)
    
    {precalc_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        question_len + answer_len + authority_len + additional_len
      end
    end)
    
    # Test with Enum.count vs length
    {enum_count_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.count(packet.question) + Enum.count(packet.answer) + 
        Enum.count(packet.authority) + Enum.count(packet.additional)
      end
    end)
    
    IO.puts("  Multiple length() calls: #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Pre-calculated lengths:  #{precalc_time}μs (#{Float.round(iterations / precalc_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Enum.count calls:        #{enum_count_time}μs (#{Float.round(iterations / enum_count_time * 1_000_000, 0)} ops/sec)")
    
    improvement = Float.round((current_time - precalc_time) / current_time * 100, 1)
    IO.puts("  Pre-calc improvement: #{improvement}%")
    IO.puts("")
  end

  defp analyze_edns_processing_overhead do
    IO.puts("4. Analyzing EDNS processing overhead:")
    
    # Test with and without EDNS
    simple_packet = create_test_packet()
    edns_packet = %{simple_packet | edns_info: %{
      payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0,
      options: %{edns_client_subnet: %{family: 1, client_subnet: {192, 168, 1, 0}, source_prefix: 24, scope_prefix: 0}}
    }}
    
    iterations = 30_000
    
    {simple_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create(simple_packet)
      end
    end)
    
    {edns_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        DNSpacket.create(edns_packet)
      end
    end)
    
    # Test just the EDNS processing part
    {edns_only_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        merge_edns_info_to_additional(edns_packet.additional, edns_packet.edns_info)
      end
    end)
    
    overhead = edns_time - simple_time
    overhead_percent = Float.round(overhead / simple_time * 100, 1)
    
    IO.puts("  Simple packet:       #{simple_time}μs (#{Float.round(iterations / simple_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  EDNS packet:         #{edns_time}μs (#{Float.round(iterations / edns_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  EDNS processing only: #{edns_only_time}μs (#{Float.round(iterations / edns_only_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  EDNS overhead:       #{overhead}μs (#{overhead_percent}%)")
  end

  # Helper functions
  defp build_answer_tail_rec([], acc), do: acc
  defp build_answer_tail_rec([rr | rest], acc) do
    build_answer_tail_rec(rest, acc <> DNSpacket.create_rr(rr))
  end

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

  defp merge_edns_info_to_additional(additional, nil), do: additional
  defp merge_edns_info_to_additional(additional, edns_info) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = %{name: "", type: :opt, payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, rdata: []}
    [opt_record | non_opt_records]
  end

  defp create_test_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}}
      ],
      authority: [],
      additional: []
    }
  end
end

CreateDeepAnalysis.run_analysis()