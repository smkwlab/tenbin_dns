defmodule SinglePassDomainBench do
  @moduledoc """
  Test single-pass domain name creation algorithm
  """

  def run_test do
    IO.puts("=== Single-Pass Domain Name Creation Test ===\n")
    
    test_correctness()
    test_performance()
  end

  defp test_correctness do
    IO.puts("1. Correctness verification:")
    
    test_domains = [
      ".",
      "com.",
      "example.com.",
      "www.example.com.", 
      "subdomain.example.com.",
      "very.long.subdomain.example.com.",
      String.duplicate("a", 63) <> ".example.com."
    ]
    
    Enum.each(test_domains, fn domain ->
      current_result = DNSpacket.create_domain_name(domain)
      single_pass_result = create_domain_name_single_pass(domain)
      
      match = current_result == single_pass_result
      
      IO.puts("  '#{String.slice(domain, 0, 30)}#{if String.length(domain) > 30, do: "...", else: ""}': #{if match, do: "✅", else: "❌"}")
      
      unless match do
        IO.puts("    Current:     #{inspect(current_result)}")
        IO.puts("    Single-pass: #{inspect(single_pass_result)}")
      end
    end)
    IO.puts("")
  end

  defp test_performance do
    IO.puts("2. Performance comparison:")
    
    domains = [
      {"Short", "com."},
      {"Medium", "example.com."},
      {"Long", "www.example.com."},
      {"Very long", "subdomain.example.com."},
      {"Max label", String.duplicate("a", 63) <> ".example.com."}
    ]
    
    iterations = 100_000
    
    Enum.each(domains, fn {name, domain} ->
      # Current implementation
      {current_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      end)
      
      # Single-pass implementation
      {single_pass_time, _} = :timer.tc(fn ->
        for _ <- 1..iterations, do: create_domain_name_single_pass(domain)
      end)
      
      improvement = Float.round((current_time - single_pass_time) / current_time * 100, 1)
      
      IO.puts("  #{name} ('#{domain}'):")
      IO.puts("    Current:     #{current_time}μs (#{Float.round(iterations / current_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Single-pass: #{single_pass_time}μs (#{Float.round(iterations / single_pass_time * 1_000_000, 0)} ops/sec)")
      IO.puts("    Improvement: #{improvement}%")
    end)
  end

  # Improved single-pass implementation
  defp create_domain_name_single_pass(name) do
    build_domain_name(name, 0, <<>>)
  end

  # Build domain name in single pass
  defp build_domain_name(<<>>, _label_start, acc), do: acc
  
  defp build_domain_name(<<".", rest::binary>>, label_start, acc) when label_start == 0 do
    # Empty label (root domain or consecutive dots)
    build_domain_name(rest, 0, <<acc::binary, 0>>)
  end
  
  defp build_domain_name(<<".", rest::binary>>, label_start, acc) do
    # End of label - extract it and add length prefix
    label_size = label_start
    label = binary_part(acc, byte_size(acc) - label_size, label_size)
    # Remove the label from acc and add it with length prefix
    acc_without_label = binary_part(acc, 0, byte_size(acc) - label_size)
    new_acc = <<acc_without_label::binary, label_size, label::binary>>
    build_domain_name(rest, 0, new_acc)
  end
  
  defp build_domain_name(<<char::utf8, rest::binary>>, label_start, acc) do
    # Add character to current label
    build_domain_name(rest, label_start + 1, <<acc::binary, char::utf8>>)
  end

  # Alternative: Use a different approach with label accumulation
  defp create_domain_name_single_pass_v2(name) do
    name
    |> build_labels([], <<>>)
    |> build_final_binary()
  end

  defp build_labels(<<>>, labels, current_label) do
    # Add final label if not empty
    if byte_size(current_label) > 0 do
      [current_label | labels]
    else
      labels
    end
    |> Enum.reverse()
  end

  defp build_labels(<<".", rest::binary>>, labels, current_label) do
    # End of label
    new_labels = if byte_size(current_label) > 0 do
      [current_label | labels]
    else
      [<<>> | labels]  # Empty label
    end
    build_labels(rest, new_labels, <<>>)
  end

  defp build_labels(<<char::utf8, rest::binary>>, labels, current_label) do
    build_labels(rest, labels, <<current_label::binary, char::utf8>>)
  end

  defp build_final_binary(labels) do
    labels
    |> Enum.map(fn label -> <<byte_size(label)::8, label::binary>> end)
    |> IO.iodata_to_binary()
  end

  # Test the alternative approach
  def test_alternative do
    IO.puts("3. Testing alternative single-pass approach:")
    
    domain = "www.example.com."
    iterations = 100_000
    
    # Current
    {current_time, current_result} = :timer.tc(fn ->
      for _ <- 1..iterations, do: DNSpacket.create_domain_name(domain)
      DNSpacket.create_domain_name(domain)
    end)
    
    # Alternative
    {alt_time, alt_result} = :timer.tc(fn ->
      for _ <- 1..iterations, do: create_domain_name_single_pass_v2(domain)
      create_domain_name_single_pass_v2(domain)
    end)
    
    IO.puts("  Results match: #{current_result == alt_result}")
    IO.puts("  Current:     #{current_time}μs")
    IO.puts("  Alternative: #{alt_time}μs")
    IO.puts("  Improvement: #{Float.round((current_time - alt_time) / current_time * 100, 1)}%")
  end
end

SinglePassDomainBench.run_test()
SinglePassDomainBench.test_alternative()