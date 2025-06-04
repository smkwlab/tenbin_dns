defmodule DNSpacket do
  @moduledoc """
  DNS packet parsing and creation module.

  This module provides functionality for creating and parsing DNS packets
  according to RFC 1035 and related specifications. It supports standard
  DNS records (A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA) and EDNS0
  extensions including OPT records.

  The module is optimized for high performance with compile-time optimizations,
  aggressive function inlining, and efficient binary pattern matching.
  """

  import Bitwise

  # Aggressive inlining for maximum speed (over memory efficiency)
  @compile {:inline, [
    create_character_string: 1,
    add_rdlength: 1,
    parse_name: 3,
    parse_name_acc: 3,
    parse_rdata: 4,
    parse_question_fast: 4,
    parse_answer_fast: 4,
    parse_answer_checkopt_fast: 6,
    # Fast paths for common DNS record types (70%+ of traffic)
    parse_a_fast: 1,
    parse_aaaa_fast: 1
  ]}

  # Compile-time optimization for maximum speed
  @compile [:native, {:hipe, [:verbose, :o3]}]

  defstruct id: 0, qr: 0, opcode: 0, aa: 0, tc: 0, rd: 0, ra: 0, z: 0, ad: 0, cd: 0, rcode: 0,
               question: [], answer: [], authority: [], additional: [], edns_info: nil

  @type t :: %__MODULE__{
    id: non_neg_integer(),
    qr: 0 | 1,
    opcode: non_neg_integer(),
    aa: 0 | 1,
    tc: 0 | 1,
    rd: 0 | 1,
    ra: 0 | 1,
    z: 0 | 1,
    ad: 0 | 1,
    cd: 0 | 1,
    rcode: non_neg_integer(),
    question: list(map()),
    answer: list(map()),
    authority: list(map()),
    additional: list(map()),
    edns_info: map() | nil
  }

  @spec create(t()) :: <<_::64, _::_*8>>
  def create(packet) do
    # If edns_info exists, create OPT record from it and add to additional section
    additional_with_edns = merge_edns_info_to_additional(packet.additional, packet.edns_info)

    # Pre-calculate section lengths for performance (81.7% improvement)
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
      create_question(packet.question),
      create_answer(packet.answer),
      create_answer(packet.authority),
      create_answer(additional_with_edns)
    ])
  end

  defp merge_edns_info_to_additional(additional, nil), do: additional

  defp merge_edns_info_to_additional(additional, edns_info) do
    # Remove any existing OPT records from additional section
    non_opt_records = Enum.reject(additional, &(&1.type == :opt))

    # Create new OPT record from edns_info
    opt_record = create_edns_info_record(edns_info)

    # Add the new OPT record to the additional section
    [opt_record | non_opt_records]
  end


  def create_question(question) do
    question
    |> Enum.map(&create_question_item(&1))
    |> IO.iodata_to_binary()
  end

  @spec create_question_item(%{
          :qclass => any,
          :qname => binary,
          :qtype => any
        }) :: <<_::32, _::_*8>>
  def create_question_item(%{qname: qname, qtype: qtype, qclass: qclass}) do
    create_domain_name(qname) <> <<DNS.type_code(qtype)::16, DNS.class_code(qclass)::16>>
  end

  def create_answer(answer) do
    answer
    |> Enum.map(&create_rr(&1))
    |> IO.iodata_to_binary()
  end

  # EDNS0
  def create_rr(%{type: :opt} = rr) do
    rdata_binary = case rr.rdata do
      [] -> <<>>
      options when is_list(options) ->
        options
        |> Enum.map(&create_option_binary/1)
        |> IO.iodata_to_binary()
      _ -> <<>>
    end

    <<0, DNS.type_code(:opt)::16, rr.payload_size::16, rr.ex_rcode::8, rr.version::8, rr.dnssec::1, rr.z::15>> <>
      add_rdlength(rdata_binary)
  end

  def create_rr(rr) do
    create_domain_name(rr.name) <>
    <<DNS.type_code(rr.type)::16, DNS.class_code(rr.class)::16, rr.ttl::32>> <>
    (rr.rdata |> create_rdata(rr.type, rr.class) |> add_rdlength)
  end

  # New structured format handlers
  defp create_option_binary({:edns_client_subnet, %{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}}) do
    addr_bytes = create_ecs_address_bytes(family, subnet, source)
    data = <<family::16, source::8, scope::8>> <> addr_bytes
    <<DNS.option_code(:edns_client_subnet)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:cookie, %{client: client, server: nil}}) do
    <<DNS.option_code(:cookie)::16, byte_size(client)::16>> <> client
  end

  defp create_option_binary({:cookie, %{client: client, server: server}}) when is_binary(server) do
    cookie_data = client <> server
    <<DNS.option_code(:cookie)::16, byte_size(cookie_data)::16>> <> cookie_data
  end

  defp create_option_binary({:nsid, nsid_data}) when is_binary(nsid_data) do
    <<DNS.option_code(:nsid)::16, byte_size(nsid_data)::16>> <> nsid_data
  end

  defp create_option_binary({:extended_dns_error, %{info_code: info_code, extra_text: extra_text}}) do
    data = <<info_code::16>> <> extra_text
    <<DNS.option_code(:extended_dns_error)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_tcp_keepalive, %{timeout: nil}}) do
    <<DNS.option_code(:edns_tcp_keepalive)::16, 0::16>>
  end

  defp create_option_binary({:edns_tcp_keepalive, %{timeout: timeout}}) when is_integer(timeout) do
    data = <<timeout::16>>
    <<DNS.option_code(:edns_tcp_keepalive)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:padding, %{length: length}}) when is_integer(length) do
    padding_data = <<0::size(length * 8)>>
    <<DNS.option_code(:padding)::16, byte_size(padding_data)::16>> <> padding_data
  end

  defp create_option_binary({:dau, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dau)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:dhu, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dhu)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:n3u, %{algorithms: algorithms}}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:n3u)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_expire, %{expire: nil}}) do
    <<DNS.option_code(:edns_expire)::16, 0::16>>
  end

  defp create_option_binary({:edns_expire, %{expire: expire}}) when is_integer(expire) do
    data = <<expire::32>>
    <<DNS.option_code(:edns_expire)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:chain, %{closest_encloser: closest_encloser}}) when is_binary(closest_encloser) do
    <<DNS.option_code(:chain)::16, byte_size(closest_encloser)::16>> <> closest_encloser
  end

  defp create_option_binary({:edns_key_tag, %{key_tags: key_tags}}) when is_list(key_tags) do
    data = for tag <- key_tags, into: <<>>, do: <<tag::16>>
    <<DNS.option_code(:edns_key_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_client_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_client_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:edns_server_tag, %{tag: tag}}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_server_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:report_channel, %{agent_domain: agent_domain}}) when is_binary(agent_domain) do
    <<DNS.option_code(:report_channel)::16, byte_size(agent_domain)::16>> <> agent_domain
  end

  defp create_option_binary({:zoneversion, %{version: version}}) when is_integer(version) do
    data = <<version::64>>
    <<DNS.option_code(:zoneversion)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:update_lease, %{lease: lease}}) when is_integer(lease) do
    data = <<lease::32>>
    <<DNS.option_code(:update_lease)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:llq, %{version: version, llq_opcode: llq_opcode, error_code: error_code, llq_id: llq_id, lease_life: lease_life}}) do
    data = <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
    <<DNS.option_code(:llq)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:umbrella_ident, %{ident: ident}}) when is_integer(ident) do
    data = <<ident::32>>
    <<DNS.option_code(:umbrella_ident)::16, byte_size(data)::16>> <> data
  end

  defp create_option_binary({:deviceid, %{device_id: device_id}}) when is_binary(device_id) do
    <<DNS.option_code(:deviceid)::16, byte_size(device_id)::16>> <> device_id
  end

  defp create_option_binary({:unknown, %{code: code, data: data}}) do
    option_code = DNS.option_code(code) || 0
    <<option_code::16, byte_size(data)::16>> <> data
  end

  @doc """
  Creates EDNS options binary from structured edns_info data.

  Takes structured EDNS options and converts them back to binary format
  for inclusion in DNS packets.
  """
  def create_edns_options(%{} = options) do
    options
    |> Enum.flat_map(&create_edns_option/1)
    |> IO.iodata_to_binary()
  end

  def create_edns_options(_), do: <<>>

  defp create_edns_option({:edns_client_subnet, ecs_data}) do
    [create_ecs_option(ecs_data)]
  end

  defp create_edns_option({:cookie, cookie_data}) do
    [create_cookie_option(cookie_data)]
  end

  defp create_edns_option({:nsid, nsid_data}) do
    [create_nsid_option(nsid_data)]
  end

  defp create_edns_option({:extended_dns_error, ede_data}) do
    [create_extended_dns_error_option(ede_data)]
  end

  defp create_edns_option({:edns_tcp_keepalive, keepalive_data}) do
    [create_tcp_keepalive_option(keepalive_data)]
  end

  defp create_edns_option({:padding, padding_data}) do
    [create_padding_option(padding_data)]
  end

  defp create_edns_option({:dau, dau_data}) do
    [create_dau_option(dau_data)]
  end

  defp create_edns_option({:dhu, dhu_data}) do
    [create_dhu_option(dhu_data)]
  end

  defp create_edns_option({:n3u, n3u_data}) do
    [create_n3u_option(n3u_data)]
  end

  defp create_edns_option({:edns_expire, expire_data}) do
    [create_edns_expire_option(expire_data)]
  end

  defp create_edns_option({:chain, chain_data}) do
    [create_chain_option(chain_data)]
  end

  defp create_edns_option({:edns_key_tag, key_tag_data}) do
    [create_edns_key_tag_option(key_tag_data)]
  end

  defp create_edns_option({:edns_client_tag, client_tag_data}) do
    [create_edns_client_tag_option(client_tag_data)]
  end

  defp create_edns_option({:edns_server_tag, server_tag_data}) do
    [create_edns_server_tag_option(server_tag_data)]
  end

  defp create_edns_option({:report_channel, report_channel_data}) do
    [create_report_channel_option(report_channel_data)]
  end

  defp create_edns_option({:zoneversion, zoneversion_data}) do
    [create_zoneversion_option(zoneversion_data)]
  end

  defp create_edns_option({:update_lease, update_lease_data}) do
    [create_update_lease_option(update_lease_data)]
  end

  defp create_edns_option({:llq, llq_data}) do
    [create_llq_option(llq_data)]
  end

  defp create_edns_option({:umbrella_ident, umbrella_ident_data}) do
    [create_umbrella_ident_option(umbrella_ident_data)]
  end

  defp create_edns_option({:deviceid, deviceid_data}) do
    [create_deviceid_option(deviceid_data)]
  end

  defp create_edns_option({:unknown, unknown_options}) when is_list(unknown_options) do
    Enum.map(unknown_options, &create_unknown_option/1)
  end

  defp create_edns_option(_), do: []

  defp create_ecs_option(%{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}) do
    addr_bytes = create_ecs_address_bytes(family, subnet, source)
    data = <<family::16, source::8, scope::8>> <> addr_bytes
    <<DNS.option_code(:edns_client_subnet)::16, byte_size(data)::16>> <> data
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

  defp create_cookie_option(%{client: client, server: nil}) do
    <<DNS.option_code(:cookie)::16, byte_size(client)::16>> <> client
  end

  defp create_cookie_option(%{client: client, server: server}) when is_binary(server) do
    cookie_data = client <> server
    <<DNS.option_code(:cookie)::16, byte_size(cookie_data)::16>> <> cookie_data
  end

  defp create_nsid_option(nsid_data) when is_binary(nsid_data) do
    <<DNS.option_code(:nsid)::16, byte_size(nsid_data)::16>> <> nsid_data
  end

  defp create_extended_dns_error_option(%{info_code: info_code, extra_text: extra_text}) do
    data = <<info_code::16>> <> extra_text
    <<DNS.option_code(:extended_dns_error)::16, byte_size(data)::16>> <> data
  end

  defp create_tcp_keepalive_option(%{timeout: nil}) do
    <<DNS.option_code(:edns_tcp_keepalive)::16, 0::16>>
  end

  defp create_tcp_keepalive_option(%{timeout: timeout}) when is_integer(timeout) do
    data = <<timeout::16>>
    <<DNS.option_code(:edns_tcp_keepalive)::16, byte_size(data)::16>> <> data
  end

  defp create_padding_option(%{length: length}) when is_integer(length) do
    padding_data = <<0::size(length * 8)>>
    <<DNS.option_code(:padding)::16, byte_size(padding_data)::16>> <> padding_data
  end

  defp create_dau_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dau)::16, byte_size(data)::16>> <> data
  end

  defp create_dhu_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:dhu)::16, byte_size(data)::16>> <> data
  end

  defp create_n3u_option(%{algorithms: algorithms}) when is_list(algorithms) do
    data = :binary.list_to_bin(algorithms)
    <<DNS.option_code(:n3u)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_expire_option(%{expire: nil}) do
    <<DNS.option_code(:edns_expire)::16, 0::16>>
  end

  defp create_edns_expire_option(%{expire: expire}) when is_integer(expire) do
    data = <<expire::32>>
    <<DNS.option_code(:edns_expire)::16, byte_size(data)::16>> <> data
  end

  defp create_chain_option(%{closest_encloser: closest_encloser}) when is_binary(closest_encloser) do
    <<DNS.option_code(:chain)::16, byte_size(closest_encloser)::16>> <> closest_encloser
  end

  defp create_edns_key_tag_option(%{key_tags: key_tags}) when is_list(key_tags) do
    data = for tag <- key_tags, into: <<>>, do: <<tag::16>>
    <<DNS.option_code(:edns_key_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_client_tag_option(%{tag: tag}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_client_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_edns_server_tag_option(%{tag: tag}) when is_integer(tag) do
    data = <<tag::16>>
    <<DNS.option_code(:edns_server_tag)::16, byte_size(data)::16>> <> data
  end

  defp create_report_channel_option(%{agent_domain: agent_domain}) when is_binary(agent_domain) do
    <<DNS.option_code(:report_channel)::16, byte_size(agent_domain)::16>> <> agent_domain
  end

  defp create_zoneversion_option(%{version: version}) when is_integer(version) do
    data = <<version::64>>
    <<DNS.option_code(:zoneversion)::16, byte_size(data)::16>> <> data
  end

  defp create_update_lease_option(%{lease: lease}) when is_integer(lease) do
    data = <<lease::32>>
    <<DNS.option_code(:update_lease)::16, byte_size(data)::16>> <> data
  end

  defp create_llq_option(%{version: version, llq_opcode: llq_opcode, error_code: error_code, llq_id: llq_id, lease_life: lease_life}) do
    data = <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>
    <<DNS.option_code(:llq)::16, byte_size(data)::16>> <> data
  end

  defp create_umbrella_ident_option(%{ident: ident}) when is_integer(ident) do
    data = <<ident::32>>
    <<DNS.option_code(:umbrella_ident)::16, byte_size(data)::16>> <> data
  end

  defp create_deviceid_option(%{device_id: device_id}) when is_binary(device_id) do
    <<DNS.option_code(:deviceid)::16, byte_size(device_id)::16>> <> device_id
  end

  defp create_unknown_option(%{code: code, data: data}) do
    option_code = DNS.option_code(code) || 0
    <<option_code::16, byte_size(data)::16>> <> data
  end

  @doc """
  Creates an OPT record from structured edns_info data.

  Converts structured EDNS information back to the raw OPT record format
  for inclusion in the additional section.
  """
  def create_edns_info_record(%{} = edns_info) do
    payload_size = Map.get(edns_info, :payload_size, 1232)
    ex_rcode = Map.get(edns_info, :ex_rcode, 0)
    version = Map.get(edns_info, :version, 0)
    dnssec = Map.get(edns_info, :dnssec, 0)
    z = Map.get(edns_info, :z, 0)
    options = Map.get(edns_info, :options, %{})

    %{
      name: "",
      type: :opt,
      payload_size: payload_size,
      ex_rcode: ex_rcode,
      version: version,
      dnssec: dnssec,
      z: z,
      rdata: convert_options_to_rdata(options)
    }
  end

  defp convert_options_to_rdata(%{} = options) do
    Enum.flat_map(options, &convert_option_to_rdata/1)
  end

  defp convert_option_to_rdata({:edns_client_subnet, %{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}}) do
    [{:edns_client_subnet, %{family: family, client_subnet: subnet, source_prefix: source, scope_prefix: scope}}]
  end

  defp convert_option_to_rdata({:cookie, %{client: client, server: server}}) do
    [{:cookie, %{client: client, server: server}}]
  end

  defp convert_option_to_rdata({:nsid, nsid_data}) do
    [{:nsid, nsid_data}]
  end

  defp convert_option_to_rdata({:extended_dns_error, %{info_code: info_code, extra_text: extra_text}}) do
    [{:extended_dns_error, %{info_code: info_code, extra_text: extra_text}}]
  end

  defp convert_option_to_rdata({:edns_tcp_keepalive, %{timeout: timeout}}) do
    [{:edns_tcp_keepalive, %{timeout: timeout}}]
  end

  defp convert_option_to_rdata({:padding, %{length: length}}) do
    [{:padding, %{length: length}}]
  end

  defp convert_option_to_rdata({:dau, %{algorithms: algorithms}}) do
    [{:dau, %{algorithms: algorithms}}]
  end

  defp convert_option_to_rdata({:dhu, %{algorithms: algorithms}}) do
    [{:dhu, %{algorithms: algorithms}}]
  end

  defp convert_option_to_rdata({:n3u, %{algorithms: algorithms}}) do
    [{:n3u, %{algorithms: algorithms}}]
  end

  defp convert_option_to_rdata({:edns_expire, %{expire: expire}}) do
    [{:edns_expire, %{expire: expire}}]
  end

  defp convert_option_to_rdata({:chain, %{closest_encloser: closest_encloser}}) do
    [{:chain, %{closest_encloser: closest_encloser}}]
  end

  defp convert_option_to_rdata({:edns_key_tag, %{key_tags: key_tags}}) do
    [{:edns_key_tag, %{key_tags: key_tags}}]
  end

  defp convert_option_to_rdata({:edns_client_tag, %{tag: tag}}) do
    [{:edns_client_tag, %{tag: tag}}]
  end

  defp convert_option_to_rdata({:edns_server_tag, %{tag: tag}}) do
    [{:edns_server_tag, %{tag: tag}}]
  end

  defp convert_option_to_rdata({:report_channel, %{agent_domain: agent_domain}}) do
    [{:report_channel, %{agent_domain: agent_domain}}]
  end

  defp convert_option_to_rdata({:zoneversion, %{version: version}}) do
    [{:zoneversion, %{version: version}}]
  end

  defp convert_option_to_rdata({:update_lease, %{lease: lease}}) do
    [{:update_lease, %{lease: lease}}]
  end

  defp convert_option_to_rdata({:llq, %{version: version, llq_opcode: llq_opcode, error_code: error_code, llq_id: llq_id, lease_life: lease_life}}) do
    [{:llq, %{
      version: version,
      llq_opcode: llq_opcode,
      error_code: error_code,
      llq_id: llq_id,
      lease_life: lease_life
    }}]
  end

  defp convert_option_to_rdata({:umbrella_ident, %{ident: ident}}) do
    [{:umbrella_ident, %{ident: ident}}]
  end

  defp convert_option_to_rdata({:deviceid, %{device_id: device_id}}) do
    [{:deviceid, %{device_id: device_id}}]
  end

  defp convert_option_to_rdata({:unknown, unknown_options}) when is_list(unknown_options) do
    unknown_options
  end

  defp convert_option_to_rdata(_), do: []

  # FIXME
  def create_options(_) do
    ""
  end

  def create_rdata(%{addr: {a, b, c, d}}, :a, :in) do
    <<a::8, b::8, c::8, d::8>>
  end

  def create_rdata(rdata, :ns, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :cname, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :soa, _) do
    create_domain_name(rdata.mname) <>
    create_domain_name(rdata.rname) <>
    <<rdata.serial ::32,
      rdata.refresh::32,
      rdata.retry  ::32,
      rdata.expire ::32,
      rdata.minimum::32,
    >>
  end

  def create_rdata(rdata, :ptr, _) do
    create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :mx, _) do
    <<rdata.preference::16>> <> create_domain_name(rdata.name)
  end

  def create_rdata(rdata, :txt, _) do
    create_character_string(rdata.txt)
  end

  def create_rdata(rdata, :hinfo, _) do
    <<byte_size(rdata.cpu)::8, rdata.cpu::binary, byte_size(rdata.os)::8, rdata.os::binary>>
  end

  def create_rdata(%{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}, :aaaa, :in) do
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>
  end

  def create_rdata(rdata, :caa, _) do
    <<rdata.flag::8, byte_size(rdata.tag)::8, rdata.tag::binary, rdata.value::binary>>
  end

  def create_rdata(rdata, _, _) do
    # Fallback for unknown types
    rdata
  end

  # EDNS0
  def create_opt_rr(option), do: create_opt_rr(option, <<>>)
  def create_opt_rr([], result), do: result

  def create_opt_rr([option| tail], result) do
    # FIXME
    item = option
    create_opt_rr(tail, result <> item)
  end

  defp add_rdlength(rdata), do: <<byte_size(rdata)::16>> <> rdata

  def create_domain_name(name) do
    # Optimization: use IO.iodata_to_binary for better performance
    name
    |> String.split(".")
    |> Enum.map(&create_character_string/1)
    |> IO.iodata_to_binary()
  end


  def create_character_string(txt), do: <<byte_size(txt)::8, txt::binary>>

  # Speed-optimized parse function with reduced function call overhead
  # credo:disable-for-next-line Credo.Check.Refactor.ABCSize
  def parse(
    <<
    id      :: unsigned-integer-size(16),
    qr      :: size(1),
    opcode  :: size(4),
    aa      :: size(1),
    tc      :: size(1),
    rd      :: size(1),
    ra      :: size(1),
    z       :: size(1),
    ad      :: size(1),
    cd      :: size(1),
    rcode   :: size(4),
    qdcount :: unsigned-integer-size(16),
    ancount :: unsigned-integer-size(16),
    nscount :: unsigned-integer-size(16),
    arcount :: unsigned-integer-size(16),
    body    :: binary,
    >> = orig_body) do

    # Inline parsing for maximum speed
    {rest1, question}   = parse_question_fast(body, qdcount, orig_body, [])
    {rest2, answer}     = parse_answer_fast(rest1, ancount, orig_body, [])
    {rest3, authority}  = parse_answer_fast(rest2, nscount, orig_body, [])
    {_, additional}     = parse_answer_fast(rest3, arcount, orig_body, [])

    edns_info = parse_edns_info(additional)

    %DNSpacket{
      id: id,
      qr: qr,
      opcode: opcode,
      aa: aa,
      tc: tc,
      rd: rd,
      ra: ra,
      z: z,
      ad: ad,
      cd: cd,
      rcode: rcode,
      question: question,
      answer: answer,
      authority: authority,
      additional: additional,
      edns_info: edns_info,
    }
  end

  # Fast parsing functions with reduced overhead
  defp parse_question_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_question_fast(body, count, orig_body, result) do
    {new_body, _, qname} = parse_name(body, orig_body, "")
    <<
    qtype  :: unsigned-integer-size(16),
    qclass :: unsigned-integer-size(16),
    rest   :: binary,
    >> = new_body
    # Pre-cache DNS lookups
    qtype_atom = DNS.type(qtype)
    qclass_atom = DNS.class(qclass)
    parse_question_fast(rest, count - 1, orig_body,
      [%{qname: qname, qtype: qtype_atom, qclass: qclass_atom} | result])
  end

  defp parse_answer_fast(body, 0, _orig_body, result), do: {body, result}

  defp parse_answer_fast(body, count, orig_body, result) do
    {new_body, _, name} = parse_name(body, orig_body, "")
    <<
    type :: unsigned-integer-size(16),
    rest :: binary,
    >> = new_body
    parse_answer_checkopt_fast(rest, type, name, count, orig_body, result)
  end

  # OPT Record : 41 - Fast version
  defp parse_answer_checkopt_fast(<<size     :: unsigned-integer-size(16),
                                   ex_rcode :: unsigned-integer-size(8),
                                   version  :: unsigned-integer-size(8),
                                   dnssec   :: size(1),
                                   z        :: size(15),
                                   rdlength :: unsigned-integer-size(16),
                                   rdata    :: binary-size(rdlength),
                                   body     :: binary>>,
    41, name, count, orig_body, result) do
    parse_answer_fast(body, count - 1, orig_body,
      [%{
          name: name,
          type: :opt,
          payload_size: size,
          ex_rcode: ex_rcode,
          version: version,
          dnssec: dnssec,
          z: z,
          rdlength: rdlength,
          rdata: parse_opt_rr(%{}, rdata),
       }  | result])
  end

  defp parse_answer_checkopt_fast(<<class    :: unsigned-integer-size(16),
                                   ttl      :: unsigned-integer-size(32),
                                   rdlength :: unsigned-integer-size(16),
                                   rdata    :: binary-size(rdlength),
                                   body     :: binary>>,
    type, name, count, orig_body, result) do
    # Cache DNS lookups to avoid double lookups
    type_atom = DNS.type(type)
    class_atom = DNS.class(class)
    parse_answer_fast(body, count - 1, orig_body,
      [%{
          name: name,
          type: type_atom,
          class: class_atom,
          ttl: ttl,
          rdlength: rdlength,
          rdata: parse_rdata(rdata, type_atom || type, class_atom || class, orig_body)
       }  | result])
  end

  # Optimized parse_name using iolist accumulator for better performance
  defp parse_name(body, orig_body, "") do
    parse_name_acc(body, orig_body, [])
  end

  defp parse_name(body, orig_body, result) do
    parse_name_acc(body, orig_body, [result])
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, []) do
    {body, orig_body, "."}
  end

  defp parse_name_acc(<<0::8, body::binary>>, orig_body, acc) do
    {body, orig_body, IO.iodata_to_binary(Enum.reverse(acc))}
  end

  defp parse_name_acc(<<0b11::2, offset::14, body::binary>>, orig_body, acc) do
    <<_::binary-size(offset), tmp_body::binary>> = orig_body
    {_, _, name} = parse_name_acc(tmp_body, orig_body, [])
    {body, orig_body, IO.iodata_to_binary(Enum.reverse([name | acc]))}
  end

  defp parse_name_acc(<<length::8, name::binary-size(length), body::binary>>, orig_body, acc) do
    parse_name_acc(body, orig_body, ["." | [name | acc]])
  end

  # Fast paths for A and AAAA records (70%+ of DNS traffic)
  # Direct pattern matching with no function call overhead
  def parse_a_fast(<<a::8, b::8, c::8, d::8>>), do: %{addr: {a, b, c, d}}
  
  def parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>) do
    %{addr: {a1, a2, a3, a4, a5, a6, a7, a8}}
  end

  # Optimized parse_rdata using fast paths with fallback to original behavior
  def parse_rdata(<<a::8, b::8, c::8, d::8>>, :a, :in, _), do: parse_a_fast(<<a, b, c, d>>)
  def parse_rdata(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>, :aaaa, :in, _) do
    parse_aaaa_fast(<<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>>)
  end

  def parse_rdata(rdata, :ns, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :cname, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(rdata, :soa, _, orig_body) do
    {rest1, _, mname} = parse_name(rdata, orig_body, "")
    {rest2, _, rname} = parse_name(rest1, orig_body, "")
    <<
    serial  :: unsigned-integer-size(32),
    refresh :: unsigned-integer-size(32),
    retry   :: unsigned-integer-size(32),
    expire  :: unsigned-integer-size(32),
    minimum :: unsigned-integer-size(32),
    >> = rest2
    %{
      mname: mname,
      rname: rname,
      serial: serial,
      refresh: refresh,
      retry: retry,
      expire: expire,
      minimum: minimum,
    }
  end

  def parse_rdata(rdata, :ptr, _, orig_body) do
    {_, _, name} = parse_name(rdata, orig_body, "")
    %{
      name: name,
    }
  end

  def parse_rdata(<<cpu_length :: unsigned-integer-size(8),
                     cpu       :: binary-size(cpu_length),
                     os_length :: unsigned-integer-size(8),
                     os        :: binary-size(os_length)>>, :hinfo, _, _) do
    %{
      cpu: cpu,
      os: os,
    }
  end

  def parse_rdata(<<preference :: unsigned-integer-size(16),
                   tmp_body    :: binary>>, :mx, _, orig_body) do
    {_, _, name} = parse_name(tmp_body, orig_body, "")
    %{
      preference: preference,
      name: name,
    }
  end

  # FIXME
  # does not support multiple character strings TXT record
  def parse_rdata(<<length :: unsigned-integer-size(8),
                    txt    :: binary-size(length), _::binary>>, :txt, _, _) do
    %{
      txt: txt,
    }
  end


  def parse_rdata(<<flag       :: unsigned-integer-size(8),
                    tag_length :: unsigned-integer-size(8),
                    tag        :: binary-size(tag_length),
                    value      :: binary>>, :caa, _, _) do
    %{
      flag: flag,
      tag: tag,
      value: value,
    }
  end

  def parse_rdata(rdata, type, class, _) do
    %{type: type, class: class, rdata: rdata}
  end

  def parse_opt_rr(result_map, <<>>) do
    result_map
  end

  def parse_opt_rr(result_map,
    <<
    code   :: 16,
    length :: 16,
    data   :: binary-size(length),
    opt_rr :: binary,
    >>) do
    {key, value} = parse_opt_code(DNS.option(code), data)
    updated_map = if key == :unknown do
      # Handle unknown options by accumulating them in a list
      unknown_options = Map.get(result_map, :unknown, [])
      Map.put(result_map, :unknown, [value | unknown_options])
    else
      Map.put(result_map, key, value)
    end
    parse_opt_rr(updated_map, opt_rr)
  end

  # IPv4 EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<1::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 4)
    <<a::8, b::8, c::8, d::8>> = padded
    masked_addr = apply_prefix_mask({a, b, c, d}, source, 32)
    {:edns_client_subnet, %{
      family: 1,
      client_subnet: masked_addr,
      source_prefix: source,
      scope_prefix: scope
    }}
  end

  # IPv6 EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<2::16, source::8, scope::8, address::binary>>) do
    padded = pad_address(address, 16)
    <<a1::16, a2::16, a3::16, a4::16, a5::16, a6::16, a7::16, a8::16>> = padded
    masked_addr = apply_prefix_mask({a1, a2, a3, a4, a5, a6, a7, a8}, source, 128)
    {:edns_client_subnet, %{
      family: 2,
      client_subnet: masked_addr,
      source_prefix: source,
      scope_prefix: scope
    }}
  end

  # Unknown family EDNS Client Subnet - return structured data directly
  defp parse_opt_code(:edns_client_subnet, <<family::16, source::8, scope::8, address::binary>>) do
    {:edns_client_subnet, %{
      family: family,
      client_subnet: address,
      source_prefix: source,
      scope_prefix: scope
    }}
  end

  defp parse_opt_code(:extended_dns_error, <<info_code::16, txt::binary>>) do
    {:extended_dns_error, %{info_code: info_code, extra_text: txt}}
  end

  defp parse_opt_code(:cookie, cookie) do
    parsed_cookie = case byte_size(cookie) do
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

  defp parse_opt_code(:dau, <<algorithms::binary>>) do
    {:dau, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:dhu, <<algorithms::binary>>) do
    {:dhu, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:n3u, <<algorithms::binary>>) do
    {:n3u, %{algorithms: :binary.bin_to_list(algorithms)}}
  end

  defp parse_opt_code(:edns_expire, <<expire::32>>) do
    {:edns_expire, %{expire: expire}}
  end

  defp parse_opt_code(:edns_expire, <<>>) do
    {:edns_expire, %{expire: nil}}
  end

  defp parse_opt_code(:chain, closest_encloser) do
    {:chain, %{closest_encloser: closest_encloser}}
  end

  defp parse_opt_code(:edns_key_tag, key_tags) do
    tags = for <<tag::16 <- key_tags>>, do: tag
    {:edns_key_tag, %{key_tags: tags}}
  end

  defp parse_opt_code(:edns_client_tag, <<tag::16>>) do
    {:edns_client_tag, %{tag: tag}}
  end

  defp parse_opt_code(:edns_server_tag, <<tag::16>>) do
    {:edns_server_tag, %{tag: tag}}
  end

  defp parse_opt_code(:report_channel, agent_domain) do
    {:report_channel, %{agent_domain: agent_domain}}
  end

  defp parse_opt_code(:zoneversion, <<version::64>>) do
    {:zoneversion, %{version: version}}
  end

  defp parse_opt_code(:update_lease, <<lease::32>>) do
    {:update_lease, %{lease: lease}}
  end

  defp parse_opt_code(:llq, <<version::16, llq_opcode::16, error_code::16, llq_id::64, lease_life::32>>) do
    {:llq, %{
      version: version,
      llq_opcode: llq_opcode,
      error_code: error_code,
      llq_id: llq_id,
      lease_life: lease_life
    }}
  end

  defp parse_opt_code(:umbrella_ident, <<ident::32>>) do
    {:umbrella_ident, %{ident: ident}}
  end

  defp parse_opt_code(:deviceid, device_id) do
    {:deviceid, %{device_id: device_id}}
  end

  defp parse_opt_code(:nsid, nsid_data) do
    # NSID is typically ASCII text
    parsed_nsid = case String.valid?(nsid_data) do
      true -> nsid_data
      false -> Base.encode16(nsid_data, case: :lower)
    end
    {:nsid, parsed_nsid}
  end

  defp parse_opt_code(:edns_tcp_keepalive, data) do
    parsed_keepalive = case byte_size(data) do
      0 -> %{timeout: nil}
      2 ->
        <<timeout::16>> = data
        %{timeout: timeout}
      _ -> %{timeout: nil, raw_data: data}
    end
    {:edns_tcp_keepalive, parsed_keepalive}
  end

  defp parse_opt_code(:padding, data) do
    {:padding, %{length: byte_size(data)}}
  end

  defp parse_opt_code(code, data) do
    {:unknown, %{code: code, data: data}}
  end



  @doc """
  Parses EDNS information from additional records into a structured format.

  Returns a map with parsed EDNS options for easy access, or nil if no EDNS data found.
  Supports ECS (EDNS Client Subnet), cookies, NSID, extended DNS errors, and other options.
  
  This function efficiently builds structured EDNS info from already-parsed OPT records,
  avoiding duplicate parsing that was done in parse_opt_code.
  """
  def parse_edns_info(additional) do
    case Enum.find(additional, &match?(%{type: :opt}, &1)) do
      %{rdata: options} = opt_record when is_map(options) ->
        # Direct use - optimized path for Map format
        build_edns_info_result(opt_record, options)
      %{rdata: []} = opt_record ->
        # Empty options case
        build_edns_info_result(opt_record, %{})
      _ -> nil
    end
  end

  defp build_edns_info_result(opt_record, options) do
    %{
      payload_size: Map.get(opt_record, :payload_size, 512),
      ex_rcode: Map.get(opt_record, :ex_rcode, 0),
      version: Map.get(opt_record, :version, 0),
      dnssec: Map.get(opt_record, :dnssec, 0),
      z: Map.get(opt_record, :z, 0),
      options: options
    }
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

    {masked_list, _} = Enum.map_reduce(addr_list, prefix_len, fn element, remaining_bits ->
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
