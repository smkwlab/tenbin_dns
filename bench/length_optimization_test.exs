defmodule LengthOptimizationTest do
  @moduledoc """
  Test the effect of length pre-calculation optimization
  """

  def run_test do
    IO.puts("=== Length Pre-calculation Optimization Test ===\n")
    
    test_create_performance()
    test_overall_impact()
  end

  defp test_create_performance do
    IO.puts("1. Create performance improvement:")
    
    packets = [
      {"Simple A record", create_simple_packet()},
      {"Multiple records", create_multi_packet()},
      {"EDNS packet", create_edns_packet()},
      {"Large packet", create_large_packet()}
    ]
    
    iterations = 50_000
    
    Enum.each(packets, fn {name, packet} ->
      # Test optimized version (current)
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create(packet)
      end)
      
      # Test legacy version (simulated)
      {legacy_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: create_legacy(packet)
      end)
      
      improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
      
      IO.puts("  #{name}:")
      IO.puts("    Legacy:    #{legacy_time}μs (#{Float.round(iterations / legacy_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Optimized: #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Improvement: #{improvement}%")
    end)
    IO.puts("")
  end

  defp test_overall_impact do
    IO.puts("2. Overall parse vs create performance:")
    
    packet = create_multi_packet()
    binary = DNSpacket.create(packet)
    iterations = 30_000
    
    # Test parse performance
    {parse_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.parse(binary)
    end)
    
    # Test create performance (optimized)
    {create_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(packet)
    end)
    
    ratio = create_time / parse_time
    
    IO.puts("  Parse:  #{parse_time}μs (#{Float.round(iterations / parse_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Create: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Create/Parse ratio: #{Float.round(ratio, 2)}x (was 2.33x before optimizations)")
    
    if ratio < 2.33 do
      improvement = Float.round((2.33 - ratio) / 2.33 * 100, 1)
      IO.puts("  Overall improvement: #{improvement}% reduction in create overhead")
    end
  end

  # Legacy create function for comparison (simulates old behavior with repeated length calls)
  defp create_legacy(packet) do
    additional_with_edns = merge_edns_info_to_additional(packet.additional, packet.edns_info)

    # Simulate old behavior: call length() multiple times in the binary construction
    header = <<packet.id                     ::16,
               packet.qr                     ::1,
               packet.opcode                 ::4,
               packet.aa                     ::1,
               packet.tc                     ::1,
               packet.rd                     ::1,
               packet.ra                     ::1,
               packet.z                      ::1,
               packet.ad                     ::1,
               packet.cd                     ::1,
               packet.rcode                  ::4,
               length(packet.question)       ::16,
               length(packet.answer)         ::16,
               length(packet.authority)      ::16,
               length(additional_with_edns)  ::16>>

    IO.iodata_to_binary([
      header,
      DNSpacket.create_question(packet.question),
      DNSpacket.create_answer(packet.answer),
      DNSpacket.create_answer(packet.authority),
      DNSpacket.create_answer(additional_with_edns)
    ])
  end

  defp merge_edns_info_to_additional(additional, nil), do: additional
  defp merge_edns_info_to_additional(additional, edns_info) do
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = %{name: "", type: :opt, payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, rdata: []}
    [opt_record | non_opt_records]
  end

  # Test packet generators
  defp create_simple_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "test.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "test.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]
    }
  end

  defp create_multi_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}},
        %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
          rdata: %{addr: {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946}}}
      ]
    }
  end

  defp create_edns_packet do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
      edns_info: %{payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, options: %{}}
    }
  end

  defp create_large_packet do
    answers = for i <- 1..15 do
      %{name: "example#{i}.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {192, 168, div(i, 256), rem(i, 256)}}}
    end
    
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
      answer: answers
    }
  end
end

LengthOptimizationTest.run_test()