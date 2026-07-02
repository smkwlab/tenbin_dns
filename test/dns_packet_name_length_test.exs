defmodule DNSpacketNameLengthTest do
  @moduledoc """
  RFC 1035 §3.1 total-name-length cap in name decompression (#119).

  A domain name is limited to 255 wire octets. `parse_name_acc/5` refuses a
  label that would push the assembled name past that limit, threading the
  running octet count through the compression-pointer recursion so the bound
  holds across pointer jumps. This closes the O(n²) decompression
  amplification: a pointer chain that appends a label at every backward hop can
  no longer grow the reassembled name without bound. Over-long names raise in
  `parse/1` and become `{:error, :malformed}` in `parse_safe/1`, mirroring the
  #116 pointer-loop rejection.

  These tests build crafted binaries against `parse/1` / `parse_safe/1`, in the
  same spirit as dns_packet_pointer_loop_test.exs.
  """
  use ExUnit.Case, async: true

  # 12-byte header, QDCOUNT = 1; the question name starts at offset 12.
  defp header, do: <<0x1234::16, 0x0100::16, 1::16, 0::16, 0::16, 0::16>>

  # Build a message whose single QNAME is a depth-`depth` chain of backward
  # compression pointers, each hop prepending a one-octet label ("a"). Every
  # hop strictly decreases the offset, so #116 loop protection accepts it; only
  # the length cap can reject it. node_i = <<1, ?a, ptr->node_{i-1}>>, node_0 =
  # <<1, ?a, 0>>, QNAME = ptr->node_d.
  defp deep_name_packet(depth) do
    node_off = fn
      0 -> 18
      i -> 18 + 3 + 4 * (i - 1)
    end

    qname = <<0b11::2, node_off.(depth)::14>>
    q_tail = <<1::16, 1::16>>

    chain =
      Enum.reduce(1..depth, <<1, ?a, 0>>, fn i, acc ->
        acc <> <<1, ?a, 0b11::2, node_off.(i - 1)::14>>
      end)

    header() <> qname <> q_tail <> chain
  end

  describe "over-long names are rejected (RFC 1035 255-octet cap, #119)" do
    test "a name longer than 255 wire octets is malformed, not accepted" do
      # depth 200 => ~200 two-octet labels, far past the 255-octet limit.
      packet = deep_name_packet(200)
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
      assert_raise FunctionClauseError, fn -> DNSpacket.parse(packet) end
    end

    @tag timeout: 2_000
    test "the O(n^2) amplification packet is rejected quickly, not processed" do
      # A depth-4000 chain would previously cost seconds of CPU; with the cap it
      # is rejected after ~127 labels. The short timeout fails loudly if the
      # quadratic work ever returns.
      packet = deep_name_packet(4000)
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end

    test "a single over-long label is capped too" do
      # One 200-octet label already leaves <255 room for nothing else; two of
      # them exceed the limit. Here: label(200) + label(200) + root.
      big = <<200, String.duplicate("a", 200)::binary>>
      packet = header() <> big <> big <> <<0>> <> <<1::16, 1::16>>
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end
  end

  describe "legitimate names still parse" do
    test "a normal name round-trips through create |> parse" do
      packet =
        DNSpacket.create(%DNSpacket{
          id: 1,
          question: [%{qname: "www.example.com.", qtype: :a, qclass: :in}]
        })

      assert {:ok, parsed} = DNSpacket.parse_safe(packet)
      assert hd(parsed.question).qname == "www.example.com."
    end

    test "a maximal-length name (<=255 wire octets) is accepted" do
      # Three 63-octet labels (64 wire octets each = 192) + a short label, well
      # within 255 including the root octet.
      labels = [
        String.duplicate("a", 63),
        String.duplicate("b", 63),
        String.duplicate("c", 63),
        "dd"
      ]

      name = Enum.join(labels, ".") <> "."
      wire_octets = Enum.reduce(labels, 1, fn l, acc -> acc + byte_size(l) + 1 end)
      assert wire_octets <= 255

      packet =
        DNSpacket.create(%DNSpacket{id: 2, question: [%{qname: name, qtype: :a, qclass: :in}]})

      assert {:ok, parsed} = DNSpacket.parse_safe(packet)
      assert hd(parsed.question).qname == name
    end

    test "a name of exactly 255 wire octets is accepted; 256 is rejected" do
      # RFC 1035 §3.1 caps the wire name (label + length octets + root) at 255.
      # Labels 63+63+63+61 => (64+64+64+62) = 254 label octets + 1 root = 255.
      name_255 =
        <<63, String.duplicate("a", 63)::binary, 63, String.duplicate("b", 63)::binary, 63,
          String.duplicate("c", 63)::binary, 61, String.duplicate("d", 61)::binary, 0>>

      assert byte_size(name_255) == 255
      packet_255 = header() <> name_255 <> <<1::16, 1::16>>
      assert {:ok, parsed} = DNSpacket.parse_safe(packet_255)

      assert hd(parsed.question).qname ==
               String.duplicate("a", 63) <>
                 "." <>
                 String.duplicate("b", 63) <>
                 "." <>
                 String.duplicate("c", 63) <>
                 "." <>
                 String.duplicate("d", 61) <> "."

      # One octet over the limit (last label 62 => wire name 256) is rejected.
      name_256 =
        <<63, String.duplicate("a", 63)::binary, 63, String.duplicate("b", 63)::binary, 63,
          String.duplicate("c", 63)::binary, 62, String.duplicate("d", 62)::binary, 0>>

      assert byte_size(name_256) == 256
      packet_256 = header() <> name_256 <> <<1::16, 1::16>>
      assert DNSpacket.parse_safe(packet_256) == {:error, :malformed}
    end

    test "the 255-octet cap is enforced across a compression pointer" do
      # Outer name = one 100-octet label (101 wire octets) then a pointer to a
      # target. Because `len` is threaded into the pointer recursion, the
      # target's labels are bounded by the *combined* running total, so a name
      # assembled across a pointer jump is capped just like a flat name. This is
      # the scenario "some labels, then jump to a long name": it must NOT slip
      # past the limit.
      #
      # layout: header(12) | outer label(101) @12 | pointer @113 | qtype/qclass
      #         | target @119
      outer = <<100, String.duplicate("a", 100)::binary>>
      target_off = 12 + byte_size(outer) + 2 + 4
      ptr = <<0b11::2, target_off::14>>
      q = header() <> outer <> ptr <> <<1::16, 1::16>>

      # Combined = 101 (outer) + 153 (target label 152 + len octet) + 1 root =
      # 255: accepted, and the pointer resolves to the full "a...b..." name.
      target_ok = <<152, String.duplicate("b", 152)::binary, 0>>
      assert {:ok, parsed} = DNSpacket.parse_safe(q <> target_ok)

      assert hd(parsed.question).qname ==
               String.duplicate("a", 100) <> "." <> String.duplicate("b", 152) <> "."

      # One octet more in the target (label 153) makes the combined name 256:
      # rejected, even though neither the outer name nor the target alone is
      # over the limit.
      target_over = <<153, String.duplicate("b", 153)::binary, 0>>
      assert DNSpacket.parse_safe(q <> target_over) == {:error, :malformed}
    end

    test "legitimate backward compression still decodes" do
      # Two questions where the second name is a pointer to the first (the
      # common compression case) must still parse.
      hdr = <<0x1234::16, 0x0100::16, 2::16, 0::16, 0::16, 0::16>>
      # q1: name <3,"www",7,"example",3,"com",0> at offset 12, then qtype/qclass
      q1 = <<3, "www", 7, "example", 3, "com", 0>> <> <<1::16, 1::16>>
      # q2: name is a pointer back to offset 12, then qtype/qclass
      q2 = <<0b11::2, 12::14>> <> <<1::16, 1::16>>
      packet = hdr <> q1 <> q2

      assert {:ok, parsed} = DNSpacket.parse_safe(packet)
      names = Enum.map(parsed.question, & &1.qname)
      assert names == ["www.example.com.", "www.example.com."]
    end
  end
end
