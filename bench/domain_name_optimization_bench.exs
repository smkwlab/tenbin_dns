defmodule DomainNameOptimizationBench do
  @moduledoc """
  Deep analysis and optimization of domain name creation
  """

  def run_analysis do
    IO.puts("=== Domain Name Creation Optimization Analysis ===\n")
    
    # 1. Analyze current implementation bottlenecks
    analyze_current_implementation()
    
    # 2. Test alternative implementations
    test_alternatives()
    
    # 3. Test binary-level optimizations
    test_binary_optimizations()
    
    # 4. Real-world impact
    test_real_world_impact()
  end

  defp analyze_current_implementation do
    IO.puts("1. Current implementation breakdown:")
    
    domains = [
      "com.",
      "example.com.",
      "www.example.com.",
      "subdomain.example.com.",
      "deep.subdomain.example.com.",
      String.duplicate("a", 63) <> ".example.com."
    ]
    
    iterations = 50_000
    
    Enum.each(domains, fn domain ->
      labels = String.split(domain, ".")
      
      # Measure each step
      {split_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: String.split(domain, ".")
      end)
      
      {map_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations do
          Enum.map(labels, &DNSpacket.create_character_string/1)
        end
      end)
      
      {iodata_time, _} = :timer.tc(fn ->
        char_strings = Enum.map(labels, &DNSpacket.create_character_string/1)
        for _ <- 1..iterations do
          IO.iodata_to_binary(char_strings)
        end
      end)
      
      {full_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      end)
      
      IO.puts("\n  Domain: '#{domain}' (#{String.length(domain)} chars, #{length(labels)} labels)")
      IO.puts("    String.split:        #{split_time}μs (#{Float.round(split_time / full_time * 100, 1)}%)")
      IO.puts("    Enum.map:            #{map_time}μs (#{Float.round(map_time / full_time * 100, 1)}%)")
      IO.puts("    IO.iodata_to_binary: #{iodata_time}μs (#{Float.round(iodata_time / full_time * 100, 1)}%)")
      IO.puts("    Full operation:      #{full_time}μs (100%)")
      IO.puts("    Overhead:            #{Float.round((full_time - split_time - map_time - iodata_time) / full_time * 100, 1)}%")
    end)
  end

  defp test_alternatives do
    IO.puts("\n\n2. Alternative implementations:")
    
    domain = "www.example.com."
    iterations = 100_000
    
    # Current implementation
    {current_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
    end)
    
    # Alternative 1: Direct binary construction with :binary.split
    {binary_split_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_binary_split(domain)
    end)
    
    # Alternative 2: Recursive binary processing
    {recursive_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_recursive(domain)
    end)
    
    # Alternative 3: For comprehension
    {comprehension_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_comprehension(domain)
    end)
    
    # Alternative 4: Direct pattern matching
    {pattern_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_pattern(domain, <<>>)
    end)
    
    IO.puts("  Current (String.split):    #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Binary.split:              #{binary_split_time}μs (#{Float.round(iterations / binary_split_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Recursive:                 #{recursive_time}μs (#{Float.round(iterations / recursive_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  For comprehension:         #{comprehension_time}μs (#{Float.round(iterations / comprehension_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Pattern matching:          #{pattern_time}μs (#{Float.round(iterations / pattern_time * 1_000_000, 0)} ops/sec)")
    
    best_time = Enum.min([current_time, binary_split_time, recursive_time, comprehension_time, pattern_time])
    improvement = Float.round((current_time - best_time) / current_time * 100, 1)
    IO.puts("\n  Best improvement potential: #{improvement}%")
  end

  defp test_binary_optimizations do
    IO.puts("\n\n3. Binary-level optimizations:")
    
    iterations = 50_000
    
    # Test with pre-allocated binary
    domain = "www.example.com."
    
    {current_time, current_result} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      DNSpacket.create_domain_name(domain)
    end)
    
    # Test single-pass binary building
    {single_pass_time, single_pass_result} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_single_pass(domain)
      create_domain_name_single_pass(domain)
    end)
    
    # Verify correctness
    IO.puts("  Results match: #{current_result == single_pass_result}")
    IO.puts("  Current:     #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Single pass: #{single_pass_time}μs (#{Float.round(iterations / single_pass_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Improvement: #{Float.round((current_time - single_pass_time) / current_time * 100, 1)}%")
  end

  defp test_real_world_impact do
    IO.puts("\n\n4. Real-world packet creation impact:")
    
    packet = %DNSpacket{
      id: 0x1234, qr: 1, rd: 1, ra: 1,
      question: [%{qname: "www.example.com.", qtype: :a, qclass: :in}],
      answer: [
        %{name: "www.example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 216, 34}}},
        %{name: "example.com.", type: :a, class: :in, ttl: 300, rdata: %{addr: {93, 184, 217, 34}}}
      ],
      authority: [
        %{name: "example.com.", type: :ns, class: :in, ttl: 86400, rdata: %{name: "ns1.example.com."}}
      ]
    }
    
    iterations = 20_000
    
    {create_time, _} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create(packet)
    end)
    
    IO.puts("  Full packet creation: #{create_time}μs (#{Float.round(iterations / create_time * 1_000_000, 0)} ops/sec)")
    IO.puts("  Estimated domain name portion: ~30-40% of total time")
  end

  # Alternative implementations
  
  defp create_domain_name_binary_split(name) do
    name
    |> :binary.split(".", [:global])
    |> Enum.map(&create_character_string/1)
    |> IO.iodata_to_binary()
  end

  defp create_domain_name_recursive(name) do
    create_domain_name_recursive(name, [])
  end

  defp create_domain_name_recursive(<<>>, acc) do
    IO.iodata_to_binary(Enum.reverse(acc))
  end

  defp create_domain_name_recursive(name, acc) do
    case :binary.split(name, ".") do
      [label, rest] ->
        create_domain_name_recursive(rest, [create_character_string(label) | acc])
      [label] ->
        create_domain_name_recursive(<<>>, [create_character_string(label) | acc])
    end
  end

  defp create_domain_name_comprehension(name) do
    parts = for label <- String.split(name, "."), do: create_character_string(label)
    IO.iodata_to_binary(parts)
  end

  defp create_domain_name_pattern(<<>>, acc), do: acc
  defp create_domain_name_pattern(<<".", rest::binary>>, acc) do
    create_domain_name_pattern(rest, <<acc::binary, 0>>)
  end
  defp create_domain_name_pattern(name, acc) do
    case find_dot(name, 0) do
      nil ->
        size = byte_size(name)
        <<acc::binary, size, name::binary, 0>>
      pos ->
        <<label::binary-size(pos), ".", rest::binary>> = name
        create_domain_name_pattern(rest, <<acc::binary, pos, label::binary>>)
    end
  end

  defp find_dot(<<>>, _), do: nil
  defp find_dot(<<".", _::binary>>, pos), do: pos
  defp find_dot(<<_, rest::binary>>, pos), do: find_dot(rest, pos + 1)

  defp create_domain_name_single_pass(name) when is_binary(name) do
    build_domain_binary(name, 0, name, <<>>)
  end

  # Single-pass binary builder
  defp build_domain_binary(<<>>, _start, _full, acc), do: acc
  defp build_domain_binary(<<".", rest::binary>>, start, full, acc) do
    label_size = start
    if label_size > 0 do
      <<label::binary-size(label_size), _::binary>> = full
      new_acc = <<acc::binary, label_size, label::binary>>
      build_domain_binary(rest, 0, rest, new_acc)
    else
      build_domain_binary(rest, 0, rest, <<acc::binary, 0>>)
    end
  end
  defp build_domain_binary(<<_::utf8, rest::binary>>, start, full, acc) do
    build_domain_binary(rest, start + 1, full, acc)
  end

  defp create_character_string(txt), do: <<byte_size(txt)::8, txt::binary>>
end

DomainNameOptimizationBench.run_analysis()