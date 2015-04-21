# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule PCITest do
  use ExUnit.Case, async: true

  test "new returns correct IPv4 PCI using binary arguments" do
    assert PCI.IP.new(<<192,0,2,1>>, <<192,0,2,4>>) ==
      %PCI.IPv4{src: <<192,0,2,1>>, dst: <<192,0,2,4>>}
  end

  test "new returns correct IPv6 using binary arguments" do
    assert PCI.IP.new(<<0xfe,0x80,0::104,1>>, <<0xfe,0x80,0::104,4>>) ==
      %PCI.IPv6{src: <<0xfe,0x80,0::104,1>>, dst: <<0xfe,0x80,0::104,4>>}
  end

  test "new returns correct ICMP using binary arguments" do
    assert PCI.ICMP.new(<<8>>, <<0>>) == %PCI.ICMP{type: <<8>>, code: <<0>>}
  end
  test "new fails for ICMP with giant binary type" do
    assert_raise ArgumentError, fn ->
      PCI.ICMP.new(<<0xffff::16>>, <<0>>)
    end
  end
  test "new fails for ICMP with giant binary code" do
    assert_raise ArgumentError, fn ->
      PCI.ICMP.new(<<8>>, <<0xffff::16>>)
    end
  end
  test "new fails for ICMP with runt binary type" do
    assert_raise ArgumentError, fn ->
      PCI.ICMP.new(<<8::4>>, <<0>>)
    end
  end
  test "new fails for ICMP with runt binary code" do
    assert_raise ArgumentError, fn ->
      PCI.ICMP.new(<<8>>, <<0::4>>)
    end
  end

  test "new returns correct TCP PCI using binary arguments" do
    assert PCI.TCP.new(<<0xffff::16>>, <<0::16>>) ==
      %PCI.TCP{src: <<0xffff::16>>, dst: <<0::16>>}
  end
  test "new fails for TCP with giant binary source" do
    assert_raise ArgumentError, fn ->
      PCI.TCP.new(<<0x10000::17>>, <<0::16>>)
    end
  end
  test "new fails for TCP with giant binary destination" do
    assert_raise ArgumentError, fn ->
      PCI.TCP.new(<<0::16>>, <<0x10000::17>>)
    end
  end
  test "new fails for TCP with runt binary source" do
    assert_raise ArgumentError, fn ->
      PCI.TCP.new(<<0xff>>, <<0::16>>)
    end
  end
  test "new fails for TCP with runt binary destination" do
    assert_raise ArgumentError, fn ->
      PCI.TCP.new(<<0::16>>, <<0xff>>)
    end
  end

  test "new returns correct UDP PCI using binary arguments" do
    assert PCI.UDP.new(<<0xffff::16>>, <<0::16>>) ==
      %PCI.UDP{src: <<0xffff::16>>, dst: <<0::16>>}
  end
  test "new fails for UDP with giant binary source" do
    assert_raise ArgumentError, fn ->
      PCI.UDP.new(<<0x10000::17>>, <<0::16>>)
    end
  end
  test "new fails for UDP with giant binary destination" do
    assert_raise ArgumentError, fn ->
      PCI.UDP.new(<<0::16>>, <<0x10000::17>>)
    end
  end
  test "new fails for UDP with runt binary source" do
    assert_raise ArgumentError, fn ->
      PCI.UDP.new(<<0xff>>, <<0::16>>)
    end
  end
  test "new fails for UDP with runt binary destination" do
    assert_raise ArgumentError, fn ->
      PCI.UDP.new(<<0::16>>, <<0xff>>)
    end
  end

  test "equal? returns true for same ICMP struct" do
    test_icmp = %PCI.ICMP{type: <<0::16>>, code: <<0xffff::16>>}

    assert PCIProto.equal?(test_icmp, test_icmp) == true
  end

  test "match? returns true for same ICMP struct with full mask" do
    test_icmp = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    icmp_mask = %PCI.ICMP{type: <<0xff>>, code: <<0xff>>}

    assert PCIProto.match?(test_icmp, test_icmp, icmp_mask) == true
  end
  test "match? returns true for same ICMP struct with partial mask" do
    test_icmp = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    icmp_mask = %PCI.ICMP{type: <<0xf0>>, code: <<0xf0>>}

    assert PCIProto.match?(test_icmp, test_icmp, icmp_mask) == true
  end
  test "match? returns true for different ICMP source with partial mask" do
    test_icmp1 = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    test_icmp2 = %PCI.ICMP{type: <<3>>, code: <<0xff>>}
    icmp_mask = %PCI.ICMP{type: <<0xf0>>, code: <<0xf0>>}

    assert PCIProto.match?(test_icmp1, test_icmp2, icmp_mask) == true
  end
  test "match? returns true for different ICMP destination with partial mask" do
    test_icmp1 = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    test_icmp2 = %PCI.ICMP{type: <<0>>, code: <<0xf3>>}
    icmp_mask = %PCI.ICMP{type: <<0xf0>>, code: <<0xf0>>}

    assert PCIProto.match?(test_icmp1, test_icmp2, icmp_mask) == true
  end
  test "match? returns false for different ICMP source with partial mask" do
    test_icmp1 = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    test_icmp2 = %PCI.ICMP{type: <<0x10>>, code: <<0xff>>}
    icmp_mask = %PCI.ICMP{type: <<0xf0>>, code: <<0xf0>>}

    assert PCIProto.match?(test_icmp1, test_icmp2, icmp_mask) == false
  end
  test "match? returns false for different ICMP destination with partial mask" do
    test_icmp1 = %PCI.ICMP{type: <<0>>, code: <<0xff>>}
    test_icmp2 = %PCI.ICMP{type: <<0>>, code: <<0xef>>}
    icmp_mask = %PCI.ICMP{type: <<0xf0>>, code: <<0xf0>>}

    assert PCIProto.match?(test_icmp1, test_icmp2, icmp_mask) == false
  end

  test "equal? returns true for same TCP struct" do
    test_tcp = %PCI.TCP{src: <<0>>, dst: <<0xffff>>}

    assert PCIProto.equal?(test_tcp, test_tcp) == true
  end

  test "match? returns true for same TCP struct with full mask" do
    test_tcp = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    tcp_mask = %PCI.TCP{src: <<0xffff::16>>, dst: <<0xffff::16>>}

    assert PCIProto.match?(test_tcp, test_tcp, tcp_mask) == true
  end
  test "match? returns true for same TCP struct with partial mask" do
    test_tcp = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    tcp_mask = %PCI.TCP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_tcp, test_tcp, tcp_mask) == true
  end
  test "match? returns true for different TCP source with partial mask" do
    test_tcp1 = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_tcp2 = %PCI.TCP{src: <<3::16>>, dst: <<0xffff::16>>}
    tcp_mask = %PCI.TCP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_tcp1, test_tcp2, tcp_mask) == true
  end
  test "match? returns true for different TCP destination with partial mask" do
    test_tcp1 = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_tcp2 = %PCI.TCP{src: <<0::16>>, dst: <<0xfff3::16>>}
    tcp_mask = %PCI.TCP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_tcp1, test_tcp2, tcp_mask) == true
  end
  test "match? returns false for different TCP source with partial mask" do
    test_tcp1 = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_tcp2 = %PCI.TCP{src: <<0x10::16>>, dst: <<0xffff::16>>}
    tcp_mask = %PCI.TCP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_tcp1, test_tcp2, tcp_mask) == false
  end
  test "match? returns false for different TCP destination with partial mask" do
    test_tcp1 = %PCI.TCP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_tcp2 = %PCI.TCP{src: <<0::16>>, dst: <<0xffef::16>>}
    tcp_mask = %PCI.TCP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_tcp1, test_tcp2, tcp_mask) == false
  end

  test "equal? returns true for same UDP struct" do
    test_udp = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}

    assert PCIProto.equal?(test_udp, test_udp) == true
  end

  test "match? returns true for same UDP struct with full mask" do
    test_udp = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    udp_mask = %PCI.UDP{src: <<0xffff::16>>, dst: <<0xffff::16>>}

    assert PCIProto.match?(test_udp, test_udp, udp_mask) == true
  end
  test "match? returns true for same UDP struct with partial mask" do
    test_udp = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    udp_mask = %PCI.UDP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_udp, test_udp, udp_mask) == true
  end
  test "match? returns true for different UDP source with partial mask" do
    test_udp1 = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_udp2 = %PCI.UDP{src: <<3::16>>, dst: <<0xffff::16>>}
    udp_mask = %PCI.UDP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_udp1, test_udp2, udp_mask) == true
  end
  test "match? returns true for different UDP destination with partial mask" do
    test_udp1 = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_udp2 = %PCI.UDP{src: <<0::16>>, dst: <<0xfff3::16>>}
    udp_mask = %PCI.UDP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_udp1, test_udp2, udp_mask) == true
  end
  test "match? returns false for different UDP source with partial mask" do
    test_udp1 = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_udp2 = %PCI.UDP{src: <<0x10::16>>, dst: <<0xffff::16>>}
    udp_mask = %PCI.UDP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_udp1, test_udp2, udp_mask) == false
  end
  test "match? returns false for different UDP destination with partial mask" do
    test_udp1 = %PCI.UDP{src: <<0::16>>, dst: <<0xffff::16>>}
    test_udp2 = %PCI.UDP{src: <<0::16>>, dst: <<0xffef::16>>}
    udp_mask = %PCI.UDP{src: <<0xfff0::16>>, dst: <<0xfff0::16>>}

    assert PCIProto.match?(test_udp1, test_udp2, udp_mask) == false
  end
end
