defmodule DNSpacket.EDNS do
  @moduledoc false
  # EDNS(0) option codec: all per-option wire-format knowledge lives here.
  # Each option appears as one clause in encode_option/1 and decode_option/2,
  # keeping the encode/decode pair for an option next to each other in spirit
  # and in @known_options for key dispatch.

  import Bitwise

  # Option keys encodable by encode_option/1 (kept in sync with its clauses)
  @known_options [
    :edns_client_subnet,
    :cookie,
    :nsid,
    :extended_dns_error,
    :edns_tcp_keepalive,
    :padding,
    :dau,
    :dhu,
    :n3u,
    :edns_expire,
    :chain,
    :edns_key_tag,
    :edns_client_tag,
    :edns_server_tag,
    :report_channel,
    :zoneversion,
    :update_lease,
    :llq,
    :umbrella_ident,
    :deviceid
  ]

  @doc false
  def encode_options(%{} = options) do
    options
    |> Enum.flat_map(&encode_option_entry/1)
    |> IO.iodata_to_binary()
  end

  @doc false
  def encode_options(_), do: <<>>

  defp encode_option_entry({:unknown, unknown_options}) when is_list(unknown_options) do
    Enum.map(unknown_options, &encode_option({:unknown, &1}))
  end

  defp encode_option_entry({key, _value} = option) when key in @known_options do
    [encode_option(option)]
  end

  # Unknown option keys are silently skipped
  defp encode_option_entry(_), do: []

  @doc false
  def encode_option(
        {:edns_client_subnet,
         %{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}}
      ) do
    addr_bytes = create_ecs_address_bytes(family, subnet, source)
    data = <<family::16, source::8, scope::8>> <> addr_bytes
    <<DNS.option_code(:edns_client_subnet)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:cookie, %{client: client, server: nil}}) do
    <<DNS.option_code(:cookie)::16, byte_size(client)::16>> <> client
  end

  def encode_option({:cookie, %{client: client, server: server}})
      when is_binary(server) do
    cookie_data = client <> server
    <<DNS.option_code(:cookie)::16, byte_size(cookie_data)::16>> <> cookie_data
  end

  def encode_option({:nsid, nsid_data}) when is_binary(nsid_data) do
    <<DNS.option_code(:nsid)::16, byte_size(nsid_data)::16>> <> nsid_data
  end

  def encode_option({:extended_dns_error, %{info_code: info_code, extra_text: extra_text}}) do
    data = <<info_code::16>> <> extra_text
    <<DNS.option_code(:extended_dns_error)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:edns_tcp_keepalive, %{timeout: nil}}) do
    <<DNS.option_code(:edns_tcp_keepalive)::16, 0::16>>
  end

  def encode_option({:edns_tcp_keepalive, %{timeout: timeout}})
      when is_integer(timeout) do
    data = <<timeout::16>>
    <<DNS.option_code(:edns_tcp_keepalive)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:padding, %{length: length}}) when is_integer(length) do
    padding_data = <<0::size(length * 8)>>
    <<DNS.option_code(:padding)::16, byte_size(padding_data)::16>> <> padding_data
  end

  def encode_option({:dau, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dau)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:dhu, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dhu)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:n3u, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:n3u)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:edns_expire, %{expire: nil}}) do
    <<DNS.option_code(:edns_expire)::16, 0::16>>
  end

  def encode_option({:edns_expire, %{expire: expire}}) when is_integer(expire) do
    data = <<expire::32>>
    <<DNS.option_code(:edns_expire)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:chain, %{closest_encloser: closest_encloser}})
      when is_binary(closest_encloser) do
    <<DNS.option_code(:chain)::16, byte_size(closest_encloser)::16>> <> closest_encloser
  end

  def encode_option({:edns_key_tag, %{key_tags: key_tags}}) when is_list(key_tags) do
    data = for tag <- key_tags, into: <<>>, do: <<tag::16>>
    <<DNS.option_code(:edns_key_tag)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:edns_client_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_client_tag)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:edns_server_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_server_tag)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:report_channel, %{agent_domain: agent_domain}})
      when is_binary(agent_domain) do
    <<DNS.option_code(:report_channel)::16, byte_size(agent_domain)::16>> <> agent_domain
  end

  def encode_option({:zoneversion, %{version: version}}) when is_integer(version) do
    data = <<version::64>>
    <<DNS.option_code(:zoneversion)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:update_lease, %{lease: lease}}) when is_integer(lease) do
    data = <<lease::32>>
    <<DNS.option_code(:update_lease)::16, byte_size(data)::16>> <> data
  end

  def encode_option(
        {:llq,
         %{
           version: version,
           llq_opcode: llq_opcode,
           error_code: error_code,
           llq_id: llq_id,
           lease_life: lease_life
         }}
      ) do
    data = <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
    <<DNS.option_code(:llq)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:umbrella_ident, %{ident: ident}}) when is_integer(ident) do
    data = <<ident::32>>
    <<DNS.option_code(:umbrella_ident)::16, byte_size(data)::16>> <> data
  end

  def encode_option({:deviceid, %{device_id: device_id}}) when is_binary(device_id) do
    <<DNS.option_code(:deviceid)::16, byte_size(device_id)::16>> <> device_id
  end

  def encode_option({:unknown, %{code: code, data: data}}) do
    option_code = DNS.option_code(code) || 0
    <<option_code::16, byte_size(data)::16>> <> data
  end

  defp create_ecs_address_bytes(1, {a, b, c, d}, source_prefix) do
    # IPv4 address - calculate how many bytes needed for the prefix
    bytes_needed = div(source_prefix + 7, 8)
    full_addr = <<a::8, b::8, c::8, d::8>>
    binary_part(full_addr, 0, min(bytes_needed, 4))
  end

  defp create_ecs_address_bytes(2, {a1, a2, a3, a4, a5, a6, a7, a8}, source_prefix) do
    # IPv6 address - calculate how many bytes needed for the prefix
    bytes_needed = div(source_prefix + 7, 8)
    full_addr = <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
    binary_part(full_addr, 0, min(bytes_needed, 16))
  end

  defp create_ecs_address_bytes(_, addr_bytes, _) when is_binary(addr_bytes) do
    # Unknown family, return as-is
    addr_bytes
  end

  # IPv4 EDNS Client Subnet - return structured data directly
  @doc false
  def decode_option(:edns_client_subnet, <<1::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 4)
    <<a::8, b::8, c::8, d::8>> = padded
    masked_addr = apply_prefix_mask({a, b, c, d}, source, 32)

    {:edns_client_subnet,
     %{
       family: 1,
       client_subnet: masked_addr,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  # IPv6 EDNS Client Subnet - return structured data directly
  def decode_option(:edns_client_subnet, <<2::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 16)
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>> = padded
    masked_addr = apply_prefix_mask({a1, a2, a3, a4, a5, a6, a7, a8}, source, 128)

    {:edns_client_subnet,
     %{
       family: 2,
       client_subnet: masked_addr,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  # Unknown family EDNS Client Subnet - return structured data directly
  def decode_option(:edns_client_subnet, <<family::16, source::8, scope::8, address::binary>>) do
    {:edns_client_subnet,
     %{
       family: family,
       client_subnet: address,
       source_prefix: source,
       scope_prefix: scope
     }}
  end

  def decode_option(:extended_dns_error, <<info_code::16, txt::binary>>) do
    {:extended_dns_error, %{info_code: info_code, extra_text: txt}}
  end

  def decode_option(:cookie, cookie) do
    parsed_cookie =
      case byte_size(cookie) do
        8 ->
          %{client: cookie, server: nil}

        size when size >= 16 and size <= 40 ->
          <<client::binary-size(8), server::binary>> = cookie
          %{client: client, server: server}

        _ ->
          %{client: cookie, server: nil}
      end

    {:cookie, parsed_cookie}
  end

  def decode_option(:dau, <<algorithms::binary>>) do
    {:dau, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  def decode_option(:dhu, <<algorithms::binary>>) do
    {:dhu, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  def decode_option(:n3u, <<algorithms::binary>>) do
    {:n3u, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  def decode_option(:edns_expire, <<expire::32>>) do
    {:edns_expire, %{expire: expire}}
  end

  def decode_option(:edns_expire, <<>>) do
    {:edns_expire, %{expire: nil}}
  end

  def decode_option(:chain, closest_encloser) do
    {:chain, %{closest_encloser: closest_encloser}}
  end

  def decode_option(:edns_key_tag, key_tags) do
    tags = for <<tag::16 <- key_tags>>, do: tag
    {:edns_key_tag, %{key_tags: tags}}
  end

  def decode_option(:edns_client_tag, <<tag::16>>) do
    {:edns_client_tag, %{tag: tag}}
  end

  def decode_option(:edns_server_tag, <<tag::16>>) do
    {:edns_server_tag, %{tag: tag}}
  end

  def decode_option(:report_channel, agent_domain) do
    {:report_channel, %{agent_domain: agent_domain}}
  end

  def decode_option(:zoneversion, <<version::64>>) do
    {:zoneversion, %{version: version}}
  end

  def decode_option(:update_lease, <<lease::32>>) do
    {:update_lease, %{lease: lease}}
  end

  def decode_option(
        :llq,
        <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
      ) do
    {:llq,
     %{
       version: version,
       llq_opcode: llq_opcode,
       error_code: error_code,
       llq_id: llq_id,
       lease_life: lease_life
     }}
  end

  def decode_option(:umbrella_ident, <<ident::32>>) do
    {:umbrella_ident, %{ident: ident}}
  end

  def decode_option(:deviceid, device_id) do
    {:deviceid, %{device_id: device_id}}
  end

  def decode_option(:nsid, nsid_data) do
    # NSID is typically ASCII text
    parsed_nsid =
      case String.valid?(nsid_data) do
        true -> nsid_data
        false -> Base.encode16(nsid_data, case: :lower)
      end

    {:nsid, parsed_nsid}
  end

  def decode_option(:edns_tcp_keepalive, data) do
    parsed_keepalive =
      case byte_size(data) do
        0 ->
          %{timeout: nil}

        2 ->
          <<timeout::16>> = data
          %{timeout: timeout}

        _ ->
          %{timeout: nil, raw_data: data}
      end

    {:edns_tcp_keepalive, parsed_keepalive}
  end

  def decode_option(:padding, data) do
    {:padding, %{length: byte_size(data)}}
  end

  def decode_option(code, data) do
    {:unknown, %{code: code, data: data}}
  end

  defp pad_address(addr_bytes, target_size) do
    current_size = byte_size(addr_bytes)

    if current_size < target_size do
      addr_bytes <> <<0::size((target_size - current_size) * 8)>>
    else
      binary_part(addr_bytes, 0, target_size)
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) when prefix_len >= max_bits do
    addr_tuple
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, _max_bits) when prefix_len <= 0 do
    # Return zeroed address for prefix length 0 or negative
    case tuple_size(addr_tuple) do
      4 -> {0, 0, 0, 0}
      8 -> {0, 0, 0, 0, 0, 0, 0, 0}
      _ -> addr_tuple
    end
  end

  defp apply_prefix_mask(addr_tuple, prefix_len, max_bits) do
    # Apply prefix mask by zeroing bits beyond prefix length
    addr_list = Tuple.to_list(addr_tuple)
    element_bits = div(max_bits, length(addr_list))

    {masked_list, _} =
      Enum.map_reduce(addr_list, prefix_len, fn element, remaining_bits ->
        cond do
          remaining_bits <= 0 ->
            {0, 0}

          min(remaining_bits, element_bits) >= element_bits ->
            {element, remaining_bits - element_bits}

          true ->
            bits_to_keep = min(remaining_bits, element_bits)
            mask = bnot((1 <<< (element_bits - bits_to_keep)) - 1)
            {element &&& mask, 0}
        end
      end)

    List.to_tuple(masked_list)
  end
end
