defmodule FastPathBench do
  @moduledoc """
  Benchmark for A/AAAA record fast path optimization
  """

  # Test data representing real DNS traffic patterns
  @ipv4_rdata <<192, 168, 1, 1>>
  @ipv6_rdata <<0x2001::16, 0x0db8::16, 0x1234::16, 0x0000::16, 
                0x0000::16, 0x0000::16, 0x0000::16, 0x0001::16>>
  
  # Legacy implementations for comparison (simulate old behavior)
  def parse_rdata_legacy_a(<<a1::8, a2::8, a3::8, a4::8>>, :a, :in, _) do
    %{addr: {a1, a2, a3, a4}}
  end

  def parse_rdata_legacy_aaaa(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>, :aaaa, :in, _) do
    %{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}
  end

  def run_benchmarks do
    IO.puts("=== A/AAAA Record Fast Path Performance Benchmark ===\n")
    
    verify_correctness()
    benchmark_individual_functions()
    benchmark_real_world_scenarios()
  end

  defp verify_correctness do
    IO.puts("1. Verifying correctness of fast path implementations...")
    
    # Test A record
    legacy_a = parse_rdata_legacy_a(@ipv4_rdata, :a, :in, nil)
    fast_a = DNSpacket.parse_a_fast(@ipv4_rdata)
    optimized_a = DNSpacket.parse_rdata(@ipv4_rdata, :a, :in, nil)
    
    assert legacy_a == fast_a, "A record fast path mismatch"
    assert legacy_a == optimized_a, "A record optimized path mismatch"
    
    # Test AAAA record
    legacy_aaaa = parse_rdata_legacy_aaaa(@ipv6_rdata, :aaaa, :in, nil)
    fast_aaaa = DNSpacket.parse_aaaa_fast(@ipv6_rdata)
    optimized_aaaa = DNSpacket.parse_rdata(@ipv6_rdata, :aaaa, :in, nil)
    
    assert legacy_aaaa == fast_aaaa, "AAAA record fast path mismatch"
    assert legacy_aaaa == optimized_aaaa, "AAAA record optimized path mismatch"
    
    IO.puts("✅ All correctness tests passed\n")
  end

  defp benchmark_individual_functions do
    IO.puts("2. Individual function performance comparison:")
    
    Benchee.run(%{
      # A record benchmarks
      "A record (legacy pattern)" => fn ->
        parse_rdata_legacy_a(@ipv4_rdata, :a, :in, nil)
      end,
      "A record (fast path)" => fn ->
        DNSpacket.parse_a_fast(@ipv4_rdata)
      end,
      "A record (optimized parse_rdata)" => fn ->
        DNSpacket.parse_rdata(@ipv4_rdata, :a, :in, nil)
      end,
      
      # AAAA record benchmarks
      "AAAA record (legacy pattern)" => fn ->
        parse_rdata_legacy_aaaa(@ipv6_rdata, :aaaa, :in, nil)
      end,
      "AAAA record (fast path)" => fn ->
        DNSpacket.parse_aaaa_fast(@ipv6_rdata)
      end,
      "AAAA record (optimized parse_rdata)" => fn ->
        DNSpacket.parse_rdata(@ipv6_rdata, :aaaa, :in, nil)
      end
    },
    time: 3,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console]
    )
  end

  defp benchmark_real_world_scenarios do
    IO.puts("\n3. Real-world DNS traffic simulation:")
    
    # Simulate realistic DNS response patterns
    # 70% A records, 20% AAAA records, 10% other
    a_records = for _ <- 1..70, do: {:a, generate_random_ipv4()}
    aaaa_records = for _ <- 1..20, do: {:aaaa, generate_random_ipv6()}
    other_records = [
      {:ns, "ns1.example.com."},
      {:mx, %{preference: 10, name: "mail.example.com."}},
      {:cname, "www.example.com."},
      {:txt, "v=spf1 include:_spf.example.com ~all"}
    ]
    
    mixed_records = Enum.shuffle(a_records ++ aaaa_records ++ other_records)
    
    Benchee.run(%{
      "Batch A record parsing (fast path)" => fn ->
        Enum.each(a_records, fn {:a, rdata} ->
          DNSpacket.parse_a_fast(rdata)
        end)
      end,
      
      "Batch AAAA record parsing (fast path)" => fn ->
        Enum.each(aaaa_records, fn {:aaaa, rdata} ->
          DNSpacket.parse_aaaa_fast(rdata)
        end)
      end,
      
      "Mixed traffic (optimized parse_rdata)" => fn ->
        Enum.each(mixed_records, fn
          {:a, rdata} -> DNSpacket.parse_rdata(rdata, :a, :in, nil)
          {:aaaa, rdata} -> DNSpacket.parse_rdata(rdata, :aaaa, :in, nil)
          {type, _} -> parse_other_record_type(type)
        end)
      end,
      
      "Heavy A record workload (1000 records)" => fn ->
        heavy_a_records = for _ <- 1..1000, do: generate_random_ipv4()
        Enum.each(heavy_a_records, &DNSpacket.parse_a_fast/1)
      end
    },
    time: 2,
    memory_time: 1,
    formatters: [Benchee.Formatters.Console]
    )
  end

  # Helper functions
  defp generate_random_ipv4 do
    <<:rand.uniform(255), :rand.uniform(255), :rand.uniform(255), :rand.uniform(255)>>
  end

  defp generate_random_ipv6 do
    <<:rand.uniform(65535)::16, :rand.uniform(65535)::16, :rand.uniform(65535)::16, :rand.uniform(65535)::16,
      :rand.uniform(65535)::16, :rand.uniform(65535)::16, :rand.uniform(65535)::16, :rand.uniform(65535)::16>>
  end

  defp parse_other_record_type(_type) do
    # Simulate parsing overhead for other record types
    :timer.sleep(0)  # Minimal overhead placeholder
    %{other: true}
  end

  defp assert(condition, message) do
    unless condition do
      raise "Assertion failed: #{message}"
    end
  end
end

# Run the benchmarks
FastPathBench.run_benchmarks()