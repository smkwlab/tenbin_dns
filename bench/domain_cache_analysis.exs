defmodule DomainCacheAnalysis do
  @moduledoc """
  Analyze potential for domain name caching optimization
  """

  def run_analysis do
    IO.puts("=== Domain Name Caching Analysis ===\n")
    
    # 1. Analyze typical domain name patterns in DNS packets
    analyze_domain_patterns()
    
    # 2. Test caching effectiveness
    test_caching_effectiveness()
    
    # 3. Test memory vs performance tradeoffs
    test_memory_impact()
  end

  defp analyze_domain_patterns do
    IO.puts("1. Domain name duplication patterns in typical DNS packets:")
    
    test_packets = create_test_packets()
    
    Enum.each(test_packets, fn {name, packet} ->
      domains = extract_all_domains(packet)
      unique_domains = Enum.uniq(domains)
      duplicates = length(domains) - length(unique_domains)
      duplicate_ratio = if length(domains) > 0, do: duplicates / length(domains) * 100, else: 0
      
      IO.puts("\n  #{name}:")
      IO.puts("    Total domains: #{length(domains)}")
      IO.puts("    Unique domains: #{length(unique_domains)}")
      IO.puts("    Duplicates: #{duplicates}")
      IO.puts("    Duplication ratio: #{Float.round(duplicate_ratio, 1)}%")
      
      if duplicates > 0 do
        domain_counts = Enum.frequencies(domains)
        duplicated_domains = Enum.filter(domain_counts, fn {_, count} -> count > 1 end)
        
        IO.puts("    Duplicated domains:")
        Enum.each(duplicated_domains, fn {domain, count} ->
          IO.puts("      '#{domain}': #{count} times")
        end)
      end
    end)
  end

  defp test_caching_effectiveness do
    IO.puts("\n\n2. Caching effectiveness test:")
    
    # Test with packets that have domain duplication
    packet = create_complex_packet_with_duplicates()
    iterations = 30_000
    
    # Current implementation (no caching)
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(packet)
    end)
    
    # With domain caching
    {cached_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_packet_with_cache(packet)
    end)
    
    improvement = Float.round((current_time - cached_time) / current_time * 100, 1)
    
    IO.puts("  Current (no cache): #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  With cache:         #{cached_time}μs (#{Float.round(iterations / cached_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Improvement:        #{improvement}%")
    
    # Verify correctness
    current_result = DNSpacket.create(packet)
    cached_result = create_packet_with_cache(packet)
    IO.puts("  Results match:      #{current_result == cached_result}")
  end

  defp test_memory_impact do
    IO.puts("\n\n3. Memory impact analysis:")
    
    domains = [
      "example.com.",
      "www.example.com.",
      "mail.example.com.",
      "ns1.example.com.",
      "ns2.example.com."
    ]
    
    # Calculate cache memory usage
    cache = Enum.reduce(domains, %{}, fn domain, acc ->
      Map.put(acc, domain, DNSpacket.create_domain_name(domain))
    end)
    
    # Estimate memory usage (rough calculation)
    cache_keys_size = Enum.reduce(domains, 0, fn domain, acc -> acc + byte_size(domain) end)
    cache_values_size = Enum.reduce(Map.values(cache), 0, fn binary, acc -> acc + byte_size(binary) end)
    total_cache_size = cache_keys_size + cache_values_size
    
    IO.puts("  Domains in cache: #{length(domains)}")
    IO.puts("  Cache keys size: #{cache_keys_size} bytes")
    IO.puts("  Cache values size: #{cache_values_size} bytes")
    IO.puts("  Total cache size: #{total_cache_size} bytes")
    IO.puts("  Average per domain: #{Float.round(total_cache_size / length(domains), 1)} bytes")
    
    # Test cache lookup vs creation
    domain = "www.example.com."
    cached_binary = DNSpacket.create_domain_name(domain)
    iterations = 100_000
    
    {lookup_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: Map.get(cache, domain)
    end)
    
    {creation_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
    end)
    
    lookup_improvement = Float.round((creation_time - lookup_time) / creation_time * 100, 1)
    
    IO.puts("\n  Cache lookup vs creation:")
    IO.puts("    Creation: #{creation_time}μs (#{Float.round(iterations / creation_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Lookup:   #{lookup_time}μs (#{Float.round(iterations / lookup_time * 1_000_000, 0)} ops/sec)")
    IO.puts("    Improvement: #{lookup_improvement}%")
  end

  # Create a packet with optimized domain caching
  defp create_packet_with_cache(packet) do
    # Build cache of unique domains in this packet
    all_domains = extract_all_domains(packet)
    unique_domains = Enum.uniq(all_domains)
    
    cache = Enum.reduce(unique_domains, %{}, fn domain, acc ->
      Map.put(acc, domain, DNSpacket.create_domain_name(domain))
    end)
    
    # Create packet using cache
    additional_with_edns = merge_edns_info_to_additional(packet.additional, packet.edns_info)
    
    # Pre-calculate section lengths for performance
    question_count = length(packet.question)
    answer_count = length(packet.answer)
    authority_count = length(packet.authority)
    additional_count = length(additional_with_edns)

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
               question_count                ::16,
               answer_count                  ::16,
               authority_count               ::16,
               additional_count              ::16>>

    IO.iodata_to_binary([
      header,
      create_question_with_cache(packet.question, cache),
      create_answer_with_cache(packet.answer, cache),
      create_answer_with_cache(packet.authority, cache),
      create_answer_with_cache(additional_with_edns, cache)
    ])
  end

  defp create_question_with_cache(question, cache) do
    question
    |> Enum.map(&create_question_item_with_cache(&1, cache))
    |> IO.iodata_to_binary()
  end

  defp create_question_item_with_cache(%{qname: qname, qtype: qtype, qclass: qclass}, cache) do
    domain_binary = Map.get(cache, qname, DNSpacket.create_domain_name(qname))
    domain_binary <> <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
  end

  defp create_answer_with_cache(answer, cache) do
    answer
    |> Enum.map(&create_rr_with_cache(&1, cache))
    |> IO.iodata_to_binary()
  end

  defp create_rr_with_cache(%{type: :opt} = rr, _cache) do
    # OPT records don't have domain names in the usual sense
    DNSpacket.create_rr(rr)
  end

  defp create_rr_with_cache(rr, cache) do
    domain_binary = Map.get(cache, rr.name, DNSpacket.create_domain_name(rr.name))
    rdata_binary = create_rdata_with_cache(rr.rdata, rr.type, rr.class, cache)
    
    domain_binary <>
    <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
    add_rdlength(rdata_binary)
  end

  defp create_rdata_with_cache(%{name: name}, type, class, cache) when type in [:ns, :cname, :ptr] do
    Map.get(cache, name, DNSpacket.create_domain_name(name))
  end

  defp create_rdata_with_cache(%{name: name, preference: pref}, :mx, _class, cache) do
    domain_binary = Map.get(cache, name, DNSpacket.create_domain_name(name))
    <<pref::16>> <> domain_binary
  end

  defp create_rdata_with_cache(rdata, type, class, _cache) do
    DNSpacket.create_rdata(rdata, type, class)
  end

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

  # Helper functions
  defp extract_all_domains(packet) do
    question_domains = Enum.map(packet.question, & &1.qname)
    answer_domains = Enum.flat_map(packet.answer, &extract_domains_from_rr/1)
    authority_domains = Enum.flat_map(packet.authority, &extract_domains_from_rr/1)
    additional_domains = Enum.flat_map(packet.additional, &extract_domains_from_rr/1)
    
    question_domains ++ answer_domains ++ authority_domains ++ additional_domains
  end

  defp extract_domains_from_rr(%{type: :opt}), do: []  # OPT records don't have normal domain names
  defp extract_domains_from_rr(rr) do
    name_domains = [rr.name]
    rdata_domains = case rr.type do
      :ns -> [rr.rdata.name]
      :cname -> [rr.rdata.name]
      :ptr -> [rr.rdata.name]
      :mx -> [rr.rdata.name]
      :soa -> [rr.rdata.mname, rr.rdata.rname]
      _ -> []
    end
    name_domains ++ rdata_domains
  end

  defp merge_edns_info_to_additional(additional, nil), do: additional
  defp merge_edns_info_to_additional(additional, edns_info) do
    # Simplified for testing
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))
    opt_record = %{name: "", type: :opt, payload_size: 1232, ex_rcode: 0, version: 0, dnssec: 0, z: 0, rdata: []}
    [opt_record | non_opt_records]
  end

  # Test packet generators
  defp create_test_packets do
    [
      {"Simple A record", %DNSpacket{
        id: 0x1234, qr: 1, rd: 1, ra: 1,
        question: [%{qname: "example.com.", qtype: :a, qclass: :in}],
        answer: [%{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}]
      }},
      
      {"NS record with duplication", %DNSpacket{
        id: 0x1234, qr: 1, rd: 1, ra: 1,
        question: [%{qname: "example.com.", qtype: :ns, qclass: :in}],
        answer: [
          %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}},
          %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.com."}}
        ]
      }},
      
      {"Complex with authority", %DNSpacket{
        id: 0x1234, qr: 1, rd: 1, ra: 1,
        question: [%{qname: "www.example.com.", qtype: :a, qclass: :in}],
        answer: [%{name: "www.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {1, 2, 3, 4}}}],
        authority: [
          %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}},
          %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.com."}}
        ]
      }}
    ]
  end

  defp create_complex_packet_with_duplicates do
    %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "example.com.", qtype: :any, qclass: :in}],
      answer: [
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :aaaa, class: :in, ttl: 300, 
          rdata: %{addr: {0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946}}},
        %{name: "example.com.", type: :mx, class: :in, ttl: 300, rdata: %{preference: 10, name: "mail.example.com."}},
        %{name: "example.com.", type: :mx, class: :in, ttl: 300, rdata: %{preference: 20, name: "mail2.example.com."}}
      ],
      authority: [
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}},
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns2.example.com."}},
        %{name: "example.com.", type: :soa, class: :in, ttl: 86400, 
          rdata: %{mname: "ns1.example.com.", rname: "admin.example.com.", 
                  serial: 1, refresh: 3600, retry: 1800, expire: 604800, minimum: 3600}}
      ]
    }
  end
end

DomainCacheAnalysis.run_analysis()