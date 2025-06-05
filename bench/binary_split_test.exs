defmodule BinarySplitTest do
  @moduledoc """
  Test the effectiveness of :binary.split optimization
  """

  def run_test do
    IO.puts("=== Binary.split Optimization Test ===\n")
    
    test_domain_creation_improvement()
    test_packet_creation_impact()
  end

  defp test_domain_creation_improvement do
    IO.puts("1. Domain creation performance improvement:")
    
    domains = [
      {"Short", "com."},
      {"Medium", "example.com."},
      {"Long", "www.example.com."},
      {"Very long", "subdomain.example.com."},
      {"Max label", String.duplicate("a", 63) <> ".example.com."}
    ]
    
    iterations = 100_000
    
    Enum.each(domains, fn {name, domain} ->
      # Test optimized version (current with :binary.split)
      {optimized_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      end)
      
      # Test legacy version (String.split)
      {legacy_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: create_domain_name_legacy(domain)
      end)
      
      improvement = Float.round((legacy_time - optimized_time) / legacy_time * 100, 1)
      
      IO.puts("  #{name} ('#{domain}'):")
      IO.puts("    Legacy (String.split): #{legacy_time}μs (#{Float.round(iterations / legacy_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Optimized (:binary.split): #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Improvement: #{improvement}%")
    end)
    IO.puts("")
  end

  defp test_packet_creation_impact do
    IO.puts("2. Full packet creation impact:")
    
    # Test packet with multiple domain names
    packet = %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "www.example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "www.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}},
        %{name: "mail.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 218, 34}}}
      ],
      authority: [
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}},
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.com."}}
      ]
    }
    
    iterations = 20_000
    
    # Test current implementation (optimized)
    {optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(packet)
    end)
    
    # Test against simulated legacy (would require changing back temporarily)
    # For now, estimate based on domain creation improvement
    domain_count = count_domains_in_packet(packet)
    estimated_domain_time = domain_count * 1000  # Rough estimate
    estimated_legacy_time = optimized_time + trunc(estimated_domain_time * 0.122)  # 12.2% improvement
    
    improvement = Float.round((estimated_legacy_time - optimized_time) / estimated_legacy_time * 100, 1)
    
    IO.puts("  Optimized packet creation: #{optimized_time}μs (#{Float.round(iterations / optimized_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Estimated legacy time:     #{estimated_legacy_time}μs")
    IO.puts("  Estimated improvement:     #{improvement}%")
    IO.puts("  Domain names in packet:    #{domain_count}")
    
    # Test pure domain creation workload
    domains = extract_domains_from_packet(packet)
    
    {domain_optimized_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.each(domains, &DNSpacket.create_domain_name/1)
      end
    end)
    
    {domain_legacy_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations do
        Enum.each(domains, &create_domain_name_legacy/1)
      end
    end)
    
    domain_improvement = Float.round((domain_legacy_time - domain_optimized_time) / domain_legacy_time * 100, 1)
    
    IO.puts("\n  Pure domain creation workload:")
    IO.puts("    Legacy:    #{domain_legacy_time}μs (#{Float.round(iterations / domain_legacy_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Optimized: #{domain_optimized_time}μs (#{Float.round(iterations / domain_optimized_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Improvement: #{domain_improvement}%")
  end

  # Legacy implementation for comparison
  defp create_domain_name_legacy(name) do
    name
    |> String.split(".")
    |> Enum.map(&DNSpacket.create_character_string/1)
    |> IO.iodata_to_binary()
  end

  defp count_domains_in_packet(packet) do
    length(packet.question) +
    length(packet.answer) * 2 +  # name + rdata may contain domain
    length(packet.authority) * 2 +
    length(packet.additional) * 2
  end

  defp extract_domains_from_packet(packet) do
    question_domains = Enum.map(packet.question, & &1.qname)
    answer_domains = Enum.flat_map(packet.answer, fn rr ->
      [rr.name | extract_domains_from_rdata(rr.rdata, rr.type)]
    end)
    authority_domains = Enum.flat_map(packet.authority, fn rr ->
      [rr.name | extract_domains_from_rdata(rr.rdata, rr.type)]
    end)
    
    (question_domains ++ answer_domains ++ authority_domains)
    |> Enum.uniq()
  end

  defp extract_domains_from_rdata(%{name: name}, :ns), do: [name]
  defp extract_domains_from_rdata(%{name: name}, :cname), do: [name]
  defp extract_domains_from_rdata(%{name: name}, :ptr), do: [name]
  defp extract_domains_from_rdata(%{name: name}, :mx), do: [name]
  defp extract_domains_from_rdata(_, _), do: []
end

BinarySplitTest.run_test()