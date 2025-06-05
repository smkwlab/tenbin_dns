defmodule EdnsUnknownOptionTest do
  @moduledoc """
  Test how different EDNS structures handle unknown options
  """

  def run_test do
    IO.puts("=== EDNS Unknown Option Handling Test ===\n")
    
    analyze_current_unknown_handling()
    test_flat_structure_unknown_handling()
    test_grouped_structure_unknown_handling()
    propose_hybrid_solution()
  end

  defp analyze_current_unknown_handling do
    IO.puts("1. Current unknown option handling:")
    
    # Test with unknown options
    current_with_unknown = create_current_with_unknown()
    IO.puts("  Current structure with unknown options:")
    IO.puts("    #{inspect(current_with_unknown, pretty: true, limit: :infinity)}")
    
    # Show how unknown options are preserved
    unknown_options = get_in(current_with_unknown, [:options, :unknown])
    IO.puts("\n  Unknown options preserved: #{inspect(unknown_options)}")
    IO.puts("  Benefits: Flexible, preserves all data")
    IO.puts("  Problems: Still complex to access known options")
  end

  defp test_flat_structure_unknown_handling do
    IO.puts("\n\n2. Flat structure unknown option handling:")
    
    IO.puts("  Option 1: Unknown options as list")
    flat_with_list = create_flat_with_unknown_list()
    IO.puts("    #{inspect(flat_with_list, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Option 2: Unknown options as map")
    flat_with_map = create_flat_with_unknown_map()
    IO.puts("    #{inspect(flat_with_map, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Option 3: Dynamic fields (unknown_option_123)")
    flat_with_dynamic = create_flat_with_dynamic_fields()
    IO.puts("    #{inspect(flat_with_dynamic, pretty: true, limit: :infinity)}")
    
    # Test access patterns
    IO.puts("\n  Access patterns:")
    IO.puts("    Known options: edns_info[:ecs_family] ✅")
    IO.puts("    Unknown list: edns_info[:unknown_options] ✅")
    IO.puts("    Unknown map: edns_info[:unknown_options][123] ✅")
    IO.puts("    Dynamic: edns_info[:unknown_option_123] ✅")
  end

  defp test_grouped_structure_unknown_handling do
    IO.puts("\n\n3. Grouped structure unknown option handling:")
    
    grouped_with_unknown = create_grouped_with_unknown()
    IO.puts("  Grouped structure:")
    IO.puts("    #{inspect(grouped_with_unknown, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Access patterns:")
    IO.puts("    Known options: edns_info[:ecs][:family] ✅")
    IO.puts("    Unknown options: edns_info[:unknown] ✅")
    IO.puts("    Benefits: Clean separation, known vs unknown")
  end

  defp propose_hybrid_solution do
    IO.puts("\n\n4. Proposed hybrid solution:")
    
    hybrid = create_hybrid_structure()
    IO.puts("  Hybrid structure (best of both worlds):")
    IO.puts("    #{inspect(hybrid, pretty: true, limit: :infinity)}")
    
    IO.puts("\n  Design principles:")
    IO.puts("    1. Flatten known, commonly-used options")
    IO.puts("    2. Preserve unknown options in separate field")
    IO.puts("    3. Keep raw options for backward compatibility")
    
    IO.puts("\n  Access examples:")
    test_hybrid_access(hybrid)
    
    IO.puts("\n  Benefits:")
    IO.puts("    ✅ Fast access to common options (ECS, Cookie, NSID)")
    IO.puts("    ✅ Preserves unknown options")
    IO.puts("    ✅ Backward compatibility via :raw_options")
    IO.puts("    ✅ Easy to extend with new known options")
  end

  defp test_hybrid_access(hybrid) do
    IO.puts("    # Easy access to common options")
    if hybrid[:ecs_family] do
      IO.puts("      ECS found: family=#{hybrid[:ecs_family]}, subnet=#{inspect(hybrid[:ecs_subnet])}")
    end
    
    if hybrid[:nsid] do
      IO.puts("      NSID found: #{hybrid[:nsid]}")
    end
    
    IO.puts("\n    # Handle unknown options")
    case hybrid[:unknown_options] do
      options when map_size(options) > 0 ->
        IO.puts("      Unknown options found: #{inspect(Map.keys(options))}")
        Enum.each(options, fn {code, data} ->
          IO.puts("        Option #{code}: #{inspect(data)}")
        end)
      _ ->
        IO.puts("      No unknown options")
    end
    
    IO.puts("\n    # Backward compatibility")
    IO.puts("      Raw options available: #{hybrid[:raw_options] != nil}")
  end

  # Test data generators
  
  defp create_current_with_unknown do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      options: %{
        edns_client_subnet: %{
          family: 1,
          client_subnet: {192, 168, 1, 0},
          source_prefix: 24,
          scope_prefix: 0
        },
        nsid: "ns1.example.com",
        unknown: [
          %{code: 123, data: <<1, 2, 3, 4>>},
          %{code: 456, data: <<5, 6, 7, 8>>}
        ]
      }
    }
  end

  defp create_flat_with_unknown_list do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # Known options flattened
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      nsid: "ns1.example.com",
      # Unknown options as list
      unknown_options: [
        %{code: 123, data: <<1, 2, 3, 4>>},
        %{code: 456, data: <<5, 6, 7, 8>>}
      ]
    }
  end

  defp create_flat_with_unknown_map do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # Known options flattened
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      nsid: "ns1.example.com",
      # Unknown options as map
      unknown_options: %{
        123 => <<1, 2, 3, 4>>,
        456 => <<5, 6, 7, 8>>
      }
    }
  end

  defp create_flat_with_dynamic_fields do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # Known options flattened
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      nsid: "ns1.example.com",
      # Unknown options as dynamic fields
      unknown_option_123: <<1, 2, 3, 4>>,
      unknown_option_456: <<5, 6, 7, 8>>
    }
  end

  defp create_grouped_with_unknown do
    %{
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      # Known options grouped
      ecs: %{
        family: 1,
        subnet: {192, 168, 1, 0},
        source_prefix: 24,
        scope_prefix: 0
      },
      nsid: "ns1.example.com",
      # Unknown options
      unknown: %{
        123 => <<1, 2, 3, 4>>,
        456 => <<5, 6, 7, 8>>
      }
    }
  end

  defp create_hybrid_structure do
    %{
      # Standard EDNS fields
      payload_size: 1232,
      ex_rcode: 0,
      version: 0,
      dnssec: 0,
      z: 0,
      
      # Flattened common options for fast access
      ecs_family: 1,
      ecs_subnet: {192, 168, 1, 0},
      ecs_source_prefix: 24,
      ecs_scope_prefix: 0,
      cookie_client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
      cookie_server: nil,
      nsid: "ns1.example.com",
      
      # Unknown options preserved
      unknown_options: %{
        123 => <<1, 2, 3, 4>>,
        456 => <<5, 6, 7, 8>>
      },
      
      # Backward compatibility (optional)
      raw_options: %{
        edns_client_subnet: %{
          family: 1,
          client_subnet: {192, 168, 1, 0},
          source_prefix: 24,
          scope_prefix: 0
        },
        cookie: %{
          client: <<1, 2, 3, 4, 5, 6, 7, 8>>,
          server: nil
        },
        nsid: "ns1.example.com",
        unknown: [
          %{code: 123, data: <<1, 2, 3, 4>>},
          %{code: 456, data: <<5, 6, 7, 8>>}
        ]
      }
    }
  end
end

EdnsUnknownOptionTest.run_test()