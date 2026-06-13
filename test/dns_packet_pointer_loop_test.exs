defmodule DNSpacketPointerLoopTest do
  @moduledoc """
  Compression-pointer loop protection (#116).

  Name compression pointers must point strictly backward (RFC 1035
  §4.1.4). A pointer that cycles (self-reference, a 2-cycle, or any
  forward jump that re-enters) must be rejected rather than followed
  forever: `parse/1` raises and `parse_safe/1` returns `{:error, :malformed}`.
  Legitimate backward compression must still decode.

  The loop cases carry a short `@tag timeout:` so that, before the fix,
  the infinite loop fails as a timeout instead of hanging the suite.
  """
  use ExUnit.Case, async: true

  # 12-byte header with QDCOUNT = 1; the question name starts at offset 12
  defp header(qd \\ 1, an \\ 0) do
    <<0x1234::16, 0::16, qd::16, an::16, 0::16, 0::16>>
  end

  describe "pointer loops are rejected, not followed" do
    @tag timeout: 2_000
    test "self-referential pointer (offset 12 -> 12)" do
      packet = header() <> <<0xC0, 0x0C>>
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
      assert_raise FunctionClauseError, fn -> DNSpacket.parse(packet) end
    end

    @tag timeout: 2_000
    test "two-pointer cycle (12 -> 14 -> 12)" do
      # offset 12: pointer to 14; offset 14: pointer to 12
      packet = header() <> <<0xC0, 0x0E, 0xC0, 0x0C>>
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end

    @tag timeout: 2_000
    test "forward pointer that re-enters (12 -> 14, 14 -> 14)" do
      packet = header() <> <<0xC0, 0x0E, 0xC0, 0x0E>>
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end

    test "a pointer to exactly the message end (offset == byte_size) is rejected" do
      # packet is 14 bytes; the pointer at offset 12 targets offset 14.
      # The guard is offset < ceiling, and ceiling only ever decreases from
      # its initial byte_size(orig_body), so offset == byte_size can never
      # pass — it is rejected before the inner slice could match an empty
      # tmp_body.
      packet = header() <> <<0xC0, 0x0E>>
      assert byte_size(packet) == 14
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end

    test "a pointer past the message end (offset > byte_size) is rejected" do
      packet = header() <> <<0xC0, 0x64>>
      assert DNSpacket.parse_safe(packet) == {:error, :malformed}
    end
  end

  describe "legitimate backward compression still decodes" do
    test "an answer name pointing back to the question name resolves" do
      # Question "a." at offset 12; answer name is a pointer to offset 12.
      question = <<1, ?a, 0, 0x00, 0x01, 0x00, 0x01>>

      answer =
        <<0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2, 1>>

      packet = header(1, 1) <> question <> answer

      assert {:ok, parsed} = DNSpacket.parse_safe(packet)
      assert hd(parsed.question).qname == "a."
      assert hd(parsed.answer).name == "a."
      assert hd(parsed.answer).rdata == %{addr: {192, 0, 2, 1}}
    end

    test "a chained pointer (label then pointer, pointed-to by another pointer) decodes" do
      # Exercises the strictly-decreasing chain the review asked about:
      # answer2's name is a pointer to answer1's name (offset 21), whose
      # own name is the label "z" followed by a pointer to the question
      # name "x.y." at offset 12. Resolving answer2 jumps 21 -> 12, each
      # strictly smaller, yielding "z.x.y." — a legitimate two-hop chain.
      question = <<1, ?x, 1, ?y, 0, 0x00, 0x01, 0x00, 0x01>>
      rr_tail = <<0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 192, 0, 2, 1>>
      answer1 = <<1, ?z, 0xC0, 0x0C>> <> rr_tail
      answer2 = <<0xC0, 0x15>> <> rr_tail
      packet = header(1, 2) <> question <> answer1 <> answer2

      assert {:ok, parsed} = DNSpacket.parse_safe(packet)
      assert Enum.map(parsed.answer, & &1.name) == ["z.x.y.", "z.x.y."]
    end
  end
end
