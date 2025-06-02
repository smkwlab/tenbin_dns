defmodule DNSTest do
  use ExUnit.Case

  describe "type functions" do
    test "type/1 returns correct atom for valid type codes" do
      assert DNS.type(1) == :a
      assert DNS.type(2) == :ns
      assert DNS.type(5) == :cname
      assert DNS.type(15) == :mx
      assert DNS.type(16) == :txt
      assert DNS.type(28) == :aaaa
      assert DNS.type(255) == :any
      assert DNS.type(257) == :caa
    end

    test "type/1 returns nil for invalid type codes" do
      assert DNS.type(999) == nil
      assert DNS.type(0) == nil
      assert DNS.type(-1) == nil
    end

    test "type_code/1 returns correct code for valid atoms" do
      assert DNS.type_code(:a) == 1
      assert DNS.type_code(:ns) == 2
      assert DNS.type_code(:cname) == 5
      assert DNS.type_code(:mx) == 15
      assert DNS.type_code(:txt) == 16
      assert DNS.type_code(:aaaa) == 28
      assert DNS.type_code(:any) == 255
      assert DNS.type_code(:caa) == 257
    end

    test "type_code/1 returns nil for invalid atoms" do
      assert DNS.type_code(:invalid) == nil
      assert DNS.type_code(:unknown) == nil
    end
  end

  describe "class functions" do
    test "class/1 returns correct atom for valid class codes" do
      assert DNS.class(1) == :in
      assert DNS.class(2) == :cs
      assert DNS.class(3) == :ch
      assert DNS.class(4) == :hs
      assert DNS.class(255) == :any
    end

    test "class/1 returns nil for invalid class codes" do
      assert DNS.class(999) == nil
      assert DNS.class(0) == nil
    end

    test "class_code/1 returns correct code for valid atoms" do
      assert DNS.class_code(:in) == 1
      assert DNS.class_code(:cs) == 2
      assert DNS.class_code(:ch) == 3
      assert DNS.class_code(:hs) == 4
      assert DNS.class_code(:any) == 255
    end

    test "class_code/1 returns nil for invalid atoms" do
      assert DNS.class_code(:invalid) == nil
    end
  end

  describe "rcode functions" do
    test "rcode/1 returns correct atom for valid rcode values" do
      assert DNS.rcode(0) == :noerror
      assert DNS.rcode(1) == :formerr
      assert DNS.rcode(2) == :servfail
      assert DNS.rcode(3) == :nxdomain
      assert DNS.rcode(4) == :notimp
      assert DNS.rcode(5) == :refused
    end

    test "rcode/1 returns nil for invalid rcode values" do
      assert DNS.rcode(999) == nil
    end

    test "rcode_code/1 returns correct code for valid atoms" do
      assert DNS.rcode_code(:noerror) == 0
      assert DNS.rcode_code(:formerr) == 1
      assert DNS.rcode_code(:servfail) == 2
      assert DNS.rcode_code(:nxdomain) == 3
      assert DNS.rcode_code(:notimp) == 4
      assert DNS.rcode_code(:refused) == 5
    end

    test "rcode_code/1 returns nil for invalid atoms" do
      assert DNS.rcode_code(:invalid) == nil
    end
  end

  describe "option functions" do
    test "option/1 returns correct atom for valid option codes" do
      assert DNS.option(0) == :reserved0
      assert DNS.option(8) == :edns_client_subnet
      assert DNS.option(10) == :cookie
      assert DNS.option(15) == :extended_dns_error
    end

    test "option/1 returns nil for invalid option codes" do
      assert DNS.option(999) == nil
    end

    test "option_code/1 returns correct code for valid atoms" do
      assert DNS.option_code(:reserved0) == 0
      assert DNS.option_code(:edns_client_subnet) == 8
      assert DNS.option_code(:cookie) == 10
      assert DNS.option_code(:extended_dns_error) == 15
    end

    test "option_code/1 returns nil for invalid atoms" do
      assert DNS.option_code(:invalid) == nil
    end
  end

  describe "constants" do
    test "port/0 returns default DNS port" do
      assert DNS.port() == 53
    end

    test "service/0 returns default service name" do
      assert DNS.service() == "domain"
    end

    test "edns_max_udpsize/0 returns EDNS max UDP size" do
      assert DNS.edns_max_udpsize() == 1232
    end
  end

  describe "rcode_text/0" do
    test "returns map with human-readable rcode descriptions" do
      rcode_text = DNS.rcode_text()
      
      assert is_map(rcode_text)
      assert rcode_text[:noerror] == "No Error"
      assert rcode_text[:formerr] == "Format Error"
      assert rcode_text[:servfail] == "Server Failure"
      assert rcode_text[:nxdomain] == "Non-Existent Domain"
      assert rcode_text[:notimp] == "Not Implemented"
      assert rcode_text[:refused] == "Query Refused"
    end
  end
end