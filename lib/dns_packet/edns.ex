defmodule DNSpacket.EDNS do
  @moduledoc false
  # EDNS(0) option codec: all per-option wire-format knowledge lives here.
  # Each option appears as one clause in encode_option/1 and decode_option/2,
  # keeping the encode/decode pair for an option next to each other in spirit
  # and in @known_options for key dispatch.
  #
  # The def (public) functions exist for cross-module calls from DNSpacket
  # (create_rr/parse_opt_rr/create_edns_info_record) and for the consistency
  # tests — they are not part of the library's public API, hence
  # @moduledoc false and @doc false throughout.

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

  # Exposed so tests can verify that every known option has matching
  # encode_option/decode_option/flatten_option/prepend_option clauses
  # (see test/dns_packet_edns_consistency_test.exs).
  @doc false
  def known_options, do: @known_options

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

  # Unknown options keep their raw numeric code from the wire. Codes outside
  # the 16-bit option-code field fail fast instead of being truncated.
  def encode_option({:unknown, %{code: code, data: data}})
      when is_integer(code) and code in 0..65_535 do
    <<code::16, byte_size(data)::16>> <> data
  end

  # Atom-named codes are still reachable via the public create_edns_options/1
  # input shape (%{unknown: [%{code: :atom, data: ...}]}); unresolvable atoms
  # encode as code 0
  def encode_option({:unknown, %{code: code, data: data}}) when is_atom(code) do
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

  # Convert a flattened (hybrid) edns_info map back into the option list used
  # as OPT record rdata. One prepend_option/3 clause per option.
  #
  # The emitted order is wire-format relevant: the prepend chain runs in
  # reverse, so options appear as ECS first ... deviceid last, with unknown
  # options appended last in reversed map-enumeration order. The chain is
  # inlined (see @compile below) to keep the hot create path allocation-free
  # apart from the option list itself. prepend_option/3 (rather than
  # unflatten/1) is the inline target: every call site passes a literal key,
  # so inlining lets the compiler drop the non-matching clauses per site.
  @compile {:inline, prepend_option: 3}

  @doc false
  def unflatten(edns_info) do
    edns_info
    |> collect_unknown()
    |> prepend_option(:deviceid, edns_info)
    |> prepend_option(:umbrella_ident, edns_info)
    |> prepend_option(:llq, edns_info)
    |> prepend_option(:update_lease, edns_info)
    |> prepend_option(:zoneversion, edns_info)
    |> prepend_option(:report_channel, edns_info)
    |> prepend_option(:edns_server_tag, edns_info)
    |> prepend_option(:edns_client_tag, edns_info)
    |> prepend_option(:edns_key_tag, edns_info)
    |> prepend_option(:chain, edns_info)
    |> prepend_option(:edns_expire, edns_info)
    |> prepend_option(:n3u, edns_info)
    |> prepend_option(:dhu, edns_info)
    |> prepend_option(:dau, edns_info)
    |> prepend_option(:padding, edns_info)
    |> prepend_option(:edns_tcp_keepalive, edns_info)
    |> prepend_option(:extended_dns_error, edns_info)
    |> prepend_option(:nsid, edns_info)
    |> prepend_option(:cookie, edns_info)
    |> prepend_option(:edns_client_subnet, edns_info)
  end

  defp prepend_option(acc, :edns_client_subnet, edns_info) do
    case {Map.get(edns_info, :ecs_family), Map.get(edns_info, :ecs_subnet)} do
      {nil, _} ->
        acc

      {_, nil} ->
        acc

      {family, subnet} ->
        [
          {:edns_client_subnet,
           %{
             family: family,
             client_subnet: subnet,
             source_prefix: Map.get(edns_info, :ecs_source_prefix),
             scope_prefix: Map.get(edns_info, :ecs_scope_prefix)
           }}
          | acc
        ]
    end
  end

  defp prepend_option(acc, :cookie, edns_info) do
    case Map.get(edns_info, :cookie_client) do
      nil ->
        acc

      client ->
        [{:cookie, %{client: client, server: Map.get(edns_info, :cookie_server)}} | acc]
    end
  end

  defp prepend_option(acc, :nsid, edns_info) do
    case Map.get(edns_info, :nsid) do
      nil -> acc
      nsid -> [{:nsid, nsid} | acc]
    end
  end

  defp prepend_option(acc, :extended_dns_error, edns_info) do
    case Map.get(edns_info, :extended_dns_error_info_code) do
      nil ->
        acc

      info_code ->
        [
          {:extended_dns_error,
           %{
             info_code: info_code,
             extra_text: Map.get(edns_info, :extended_dns_error_extra_text)
           }}
          | acc
        ]
    end
  end

  # TCP keepalive is collected on key presence (a nil timeout is still encoded)
  defp prepend_option(acc, :edns_tcp_keepalive, edns_info) do
    if Map.has_key?(edns_info, :edns_tcp_keepalive_timeout) do
      [
        {:edns_tcp_keepalive,
         %{
           timeout: Map.get(edns_info, :edns_tcp_keepalive_timeout),
           raw_data: Map.get(edns_info, :edns_tcp_keepalive_raw_data)
         }}
        | acc
      ]
    else
      acc
    end
  end

  defp prepend_option(acc, :padding, edns_info) do
    case Map.get(edns_info, :padding_length) do
      nil -> acc
      length -> [{:padding, %{length: length}} | acc]
    end
  end

  defp prepend_option(acc, :dau, edns_info) do
    case Map.get(edns_info, :dau_algorithms) do
      nil -> acc
      algorithms -> [{:dau, %{algorithms: algorithms}} | acc]
    end
  end

  defp prepend_option(acc, :dhu, edns_info) do
    case Map.get(edns_info, :dhu_algorithms) do
      nil -> acc
      algorithms -> [{:dhu, %{algorithms: algorithms}} | acc]
    end
  end

  defp prepend_option(acc, :n3u, edns_info) do
    case Map.get(edns_info, :n3u_algorithms) do
      nil -> acc
      algorithms -> [{:n3u, %{algorithms: algorithms}} | acc]
    end
  end

  defp prepend_option(acc, :edns_expire, edns_info) do
    case Map.get(edns_info, :edns_expire_expire) do
      nil -> acc
      expire -> [{:edns_expire, %{expire: expire}} | acc]
    end
  end

  defp prepend_option(acc, :chain, edns_info) do
    case Map.get(edns_info, :chain_closest_encloser) do
      nil -> acc
      closest_encloser -> [{:chain, %{closest_encloser: closest_encloser}} | acc]
    end
  end

  defp prepend_option(acc, :edns_key_tag, edns_info) do
    case Map.get(edns_info, :edns_key_tag_key_tags) do
      nil -> acc
      key_tags -> [{:edns_key_tag, %{key_tags: key_tags}} | acc]
    end
  end

  defp prepend_option(acc, :edns_client_tag, edns_info) do
    case Map.get(edns_info, :edns_client_tag_tag) do
      nil -> acc
      tag -> [{:edns_client_tag, %{tag: tag}} | acc]
    end
  end

  defp prepend_option(acc, :edns_server_tag, edns_info) do
    case Map.get(edns_info, :edns_server_tag_tag) do
      nil -> acc
      tag -> [{:edns_server_tag, %{tag: tag}} | acc]
    end
  end

  defp prepend_option(acc, :report_channel, edns_info) do
    case Map.get(edns_info, :report_channel_agent_domain) do
      nil -> acc
      agent_domain -> [{:report_channel, %{agent_domain: agent_domain}} | acc]
    end
  end

  defp prepend_option(acc, :zoneversion, edns_info) do
    case Map.get(edns_info, :zoneversion_version) do
      nil -> acc
      version -> [{:zoneversion, %{version: version}} | acc]
    end
  end

  defp prepend_option(acc, :update_lease, edns_info) do
    case Map.get(edns_info, :update_lease_lease) do
      nil -> acc
      lease -> [{:update_lease, %{lease: lease}} | acc]
    end
  end

  defp prepend_option(acc, :llq, edns_info) do
    case Map.get(edns_info, :llq_version) do
      nil ->
        acc

      version ->
        [
          {:llq,
           %{
             version: version,
             llq_opcode: Map.get(edns_info, :llq_llq_opcode),
             error_code: Map.get(edns_info, :llq_error_code),
             llq_id: Map.get(edns_info, :llq_llq_id),
             lease_life: Map.get(edns_info, :llq_lease_life)
           }}
          | acc
        ]
    end
  end

  defp prepend_option(acc, :umbrella_ident, edns_info) do
    case Map.get(edns_info, :umbrella_ident_ident) do
      nil -> acc
      ident -> [{:umbrella_ident, %{ident: ident}} | acc]
    end
  end

  defp prepend_option(acc, :deviceid, edns_info) do
    case Map.get(edns_info, :deviceid_device_id) do
      nil -> acc
      device_id -> [{:deviceid, %{device_id: device_id}} | acc]
    end
  end

  defp collect_unknown(edns_info) do
    case Map.get(edns_info, :unknown_options) do
      unknown when is_map(unknown) and map_size(unknown) > 0 ->
        unknown
        |> Enum.map(fn {code, data} -> {:unknown, %{code: code, data: data}} end)
        |> Enum.reverse()

      _ ->
        []
    end
  end

  # Flatten a parsed option map into the hybrid edns_info representation.
  # One flatten_option/3 clause per option; values that do not match an
  # option's expected shape fall through to the unknown handling clauses.
  @doc false
  def flatten(options) do
    Enum.reduce(options, {%{}, %{}}, fn {key, value}, acc ->
      flatten_option(key, value, acc)
    end)
  end

  defp flatten_option(:edns_client_subnet, value, {flat, unknown}) when is_map(value) do
    flat_updates = %{
      ecs_family: Map.get(value, :family),
      ecs_subnet: Map.get(value, :client_subnet),
      ecs_source_prefix: Map.get(value, :source_prefix),
      ecs_scope_prefix: Map.get(value, :scope_prefix)
    }

    {Map.merge(flat, flat_updates), unknown}
  end

  defp flatten_option(:cookie, value, {flat, unknown}) when is_map(value) do
    flat_updates = %{
      cookie_client: Map.get(value, :client),
      cookie_server: Map.get(value, :server)
    }

    {Map.merge(flat, flat_updates), unknown}
  end

  defp flatten_option(:nsid, value, {flat, unknown}) when is_binary(value) do
    {Map.put(flat, :nsid, value), unknown}
  end

  defp flatten_option(:extended_dns_error, value, {flat, unknown}) when is_map(value) do
    flat_updates = %{
      extended_dns_error_info_code: Map.get(value, :info_code),
      extended_dns_error_extra_text: Map.get(value, :extra_text)
    }

    {Map.merge(flat, flat_updates), unknown}
  end

  defp flatten_option(:edns_tcp_keepalive, value, {flat, unknown}) when is_map(value) do
    flat_updates = %{
      edns_tcp_keepalive_timeout: Map.get(value, :timeout),
      edns_tcp_keepalive_raw_data: Map.get(value, :raw_data)
    }

    {Map.merge(flat, flat_updates), unknown}
  end

  defp flatten_option(:padding, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :padding_length, Map.get(value, :length)), unknown}
  end

  defp flatten_option(:dau, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :dau_algorithms, Map.get(value, :algorithms)), unknown}
  end

  defp flatten_option(:dhu, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :dhu_algorithms, Map.get(value, :algorithms)), unknown}
  end

  defp flatten_option(:n3u, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :n3u_algorithms, Map.get(value, :algorithms)), unknown}
  end

  defp flatten_option(:edns_expire, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :edns_expire_expire, Map.get(value, :expire)), unknown}
  end

  defp flatten_option(:chain, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :chain_closest_encloser, Map.get(value, :closest_encloser)), unknown}
  end

  defp flatten_option(:edns_key_tag, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :edns_key_tag_key_tags, Map.get(value, :key_tags)), unknown}
  end

  defp flatten_option(:edns_client_tag, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :edns_client_tag_tag, Map.get(value, :tag)), unknown}
  end

  defp flatten_option(:edns_server_tag, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :edns_server_tag_tag, Map.get(value, :tag)), unknown}
  end

  defp flatten_option(:report_channel, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :report_channel_agent_domain, Map.get(value, :agent_domain)), unknown}
  end

  defp flatten_option(:zoneversion, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :zoneversion_version, Map.get(value, :version)), unknown}
  end

  defp flatten_option(:update_lease, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :update_lease_lease, Map.get(value, :lease)), unknown}
  end

  defp flatten_option(:llq, value, {flat, unknown}) when is_map(value) do
    flat_updates = %{
      llq_version: Map.get(value, :version),
      llq_llq_opcode: Map.get(value, :llq_opcode),
      llq_error_code: Map.get(value, :error_code),
      llq_llq_id: Map.get(value, :llq_id),
      llq_lease_life: Map.get(value, :lease_life)
    }

    {Map.merge(flat, flat_updates), unknown}
  end

  defp flatten_option(:umbrella_ident, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :umbrella_ident_ident, Map.get(value, :ident)), unknown}
  end

  defp flatten_option(:deviceid, value, {flat, unknown}) when is_map(value) do
    {Map.put(flat, :deviceid_device_id, Map.get(value, :device_id)), unknown}
  end

  defp flatten_option(:unknown, value, {flat, unknown}) when is_list(value) do
    unknown_map =
      Enum.reduce(value, unknown, fn
        %{code: code, data: data}, acc -> Map.put(acc, code, data)
        _, acc -> acc
      end)

    {flat, unknown_map}
  end

  # All other options go to unknown when they carry a raw code/data payload
  defp flatten_option(_key, %{code: code, data: data}, {flat, unknown}) do
    {flat, Map.put(unknown, code, data)}
  end

  defp flatten_option(_key, _value, acc), do: acc

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
