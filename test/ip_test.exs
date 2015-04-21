# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule IPTest do
  use ExUnit.Case, async: true

  test "is_ip_string returns true for valid, unshortened IPv6" do
    assert IP.IPv6Addr.is_ip_string("fe80:0:0:0:0:0:0:1") == true
  end
  test "is_ip_string returns true for valid, shortened IPv6" do
    assert IP.IPv6Addr.is_ip_string("fe80::1") == true
  end
  test "is_ip_string returns false for empty string" do
    assert IP.IPv6Addr.is_ip_string("") == false
  end
  test "is_ip_string returns false for shortened IPv6 with bad characters" do
    assert IP.IPv6Addr.is_ip_string("fe8g::1") == false
  end
  test "is_ip_string returns false for unshortened IPv6 with bad characters" do
    assert IP.IPv6Addr.is_ip_string("fe8g:0:0:0:0:0:0:1") == false
  end
  test "is_ip_string returns false for unshortened IPv6 with too few words" do
    assert IP.IPv6Addr.is_ip_string("fe80:0:0:0:0:0:1") == false
  end
  test "is_ip_string returns false for incorrectly shortened IPv6" do
    assert IP.IPv6Addr.is_ip_string("fe80::2::") == false
  end
  test "is_ip_string returns false for truncated IPv6" do
    assert IP.IPv6Addr.is_ip_string("fe80:0:0:0:0:0:0:") == false
  end
  test "is_ip_string returns false for IPv6 with giant word" do
    assert IP.IPv6Addr.is_ip_string("afe80::") == false
  end

  test "expand_ip_string returns valid, unshortened IPv6 string unchanged" do
    assert IP.IPv6Addr.expand_ip_string("fe80:0:0:0:0:0:0:1") == "fe80:0:0:0:0:0:0:1"
  end
  test "expand_ip_string expands valid, shortened IPv6 string" do
    assert IP.IPv6Addr.expand_ip_string("fe80::1") == "fe80:0:0:0:0:0:0:1"
  end
  test "expand_ip_string expands a different valid, shortened IPv6 string" do
    assert IP.IPv6Addr.expand_ip_string("fe80:e800:11::2:0") == "fe80:e800:11:0:0:0:2:0"
  end
  test "expand_ip_string expands valid, shortened IPv6 string with last word as zero" do
    assert IP.IPv6Addr.expand_ip_string("fe80::") == "fe80:0:0:0:0:0:0:0"
  end
  test "expand_ip_string returns incorrectly shortened IPv6 string unchanged" do
    assert IP.IPv6Addr.expand_ip_string("fe80::2::") == "fe80::2::"
  end

  test "string_to_ip correctly parses valid, shortened IPv6 string" do
    assert IP.IPv6Addr.string_to_ip("fe80::2:1") == {:ok, <<0xfe, 0x80, 2 :: 12 * 8, 0, 1>>}
  end
  test "string_to_ip correctly parses valid, unshortened IPv6 string" do
    assert IP.IPv6Addr.string_to_ip("fe80:0:0:0:0:0:2:1") == {:ok, <<0xfe, 0x80, 2:: 12 * 8, 0, 1>>}
  end
  test "string_to_ip fails for empty string" do
    assert IP.IPv6Addr.string_to_ip("") == {:error, :badarg}
  end
  test "string_to_ip fails for shortened IPv6 with bad characters" do
    assert IP.IPv6Addr.string_to_ip("fe8g::1") == {:error, :badarg}
  end
  test "string_to_ip fails for unshortened IPv6 with bad characters" do
    assert IP.IPv6Addr.string_to_ip("fe8g:0:0:0:0:0:0:1") == {:error, :badarg}
  end
  test "string_to_ip fails for unshortened IPv6 with too few words" do
    assert IP.IPv6Addr.string_to_ip("fe80:0:0:0:0:0:1") == {:error, :badarg}
  end
  test "string_to_ip fails for incorrectly shortened IPv6" do
    assert IP.IPv6Addr.string_to_ip("fe80::2::") == {:error, :badarg}
  end
  test "string_to_ip fails for truncated IPv6" do
    assert IP.IPv6Addr.string_to_ip("fe80:0:0:0:0:0:0:") == {:error, :badarg}
  end
  test "string_to_ip fails for IPv6 with giant word" do
    assert IP.IPv6Addr.string_to_ip("afe80::") == {:error, :badarg}
  end

  test "is_ip_string returns true for valid IPv4" do
    assert IP.IPv4Addr.is_ip_string("192.0.2.1") == true
  end
  test "is_ip_string returns false for empty IPv4 string" do
    assert IP.IPv4Addr.is_ip_string("") == false
  end
  test "is_ip_string returns false for IPv4 with bad characters" do
    assert IP.IPv4Addr.is_ip_string("192.0.2.a") == false
  end
  test "is_ip_string returns false for IPv4 with too few octets" do
    assert IP.IPv4Addr.is_ip_string("192.0.2") == false
  end
  test "is_ip_string returns false for truncated IPv4" do
    assert IP.IPv4Addr.is_ip_string("192.0.2.") == false
  end
  test "is_ip_string returns false for IPv4 with giant octet" do
    assert IP.IPv4Addr.is_ip_string("192.0.2.256") == false
  end

  test "string_to_ip correctly parses valid IPv4" do
    assert IP.IPv4Addr.string_to_ip("192.0.2.0") == {:ok, <<192, 0, 2, 0>>}
  end
  test "string_to_ip fails for empty IPv4 string" do
    assert IP.IPv4Addr.string_to_ip("") == {:error, :badarg}
  end
  test "string_to_ip fails for IPv4 with bad characters" do
    assert IP.IPv4Addr.string_to_ip("192.0.2.a") == {:error, :badarg}
  end
  test "string_to_ip fails for IPv4 with too few octets" do
    assert IP.IPv4Addr.string_to_ip("192.0.2") == {:error, :badarg}
  end
  test "string_to_ip fails for truncated IPv4" do
    assert IP.IPv4Addr.string_to_ip("192.0.2.") == {:error, :badarg}
  end
  test "string_to_ip fails for IPv4 with giant octet" do
    assert IP.IPv4Addr.string_to_ip("192.0.2.256") == {:error, :badarg}
  end

  test "new returns correct IPv4Addr for binary arguments" do
    assert IP.IPv4Addr.new(<<192,0,2,1>>) == %IP.IPv4Addr{addr: <<192,0,2,1>>}
  end
  test "new returns correct IPv4Addr using IP string" do
    assert IP.IPv4Addr.new("192.0.2.1") == %IP.IPv4Addr{addr: <<192,0,2,1>>}
  end
  test "new returns correct IPv4Addr using integer" do
    assert IP.IPv4Addr.new(26) == %IP.IPv4Addr{addr: <<255,255,255,192>>}
  end
  test "new fails for giant IPv4 binary" do
    assert_raise ArgumentError, fn ->
      IP.IPv4Addr.new(<<255,255,255,255,1>>)
    end
  end
  test "new fails for baby giant IPv4 binary" do
    assert_raise ArgumentError, fn ->
      IP.IPv4Addr.new(<<255,255,255,255::9>>)
    end
  end

  test "new returns correct IPv6Addr for binary arguments" do
    assert IP.IPv6Addr.new(<<0xfe,0x80,0::104,1>>) ==
      %IP.IPv6Addr{addr: <<0xfe,0x80,0::104,1>>}
  end
  test "new returns correct IPv6Addr using IP string" do
    assert IP.IPv6Addr.new("fe80::1") ==
      %IP.IPv6Addr{addr: <<0xfe,0x80,0::104,1>>}
  end
  test "new returns correct IPv6Addr using integer" do
    assert IP.IPv6Addr.new(60) ==
      %IP.IPv6Addr{addr: <<0xffffffffffffffffff0::64,0::64>>}
  end
  test "new fails for giant IPv6 binary" do
    assert_raise ArgumentError, fn ->
      IP.IPv6Addr.new(<<0xfe,0x80,0::112,1>>)
    end
  end
  test "new fails for baby giant IPv6 binary" do
    assert_raise ArgumentError, fn ->
      IP.IPv6Addr.new(<<0xfe,0x80,0::113>>)
    end
  end
  test "new returns correct IPv6Addr using 128-bit IPv6 string" do
    assert IP.IPv6Addr.new("fe80:100:100::12") ==
      %IP.IPv6Addr{addr: <<0xfe,0x80,0x01,0x00,0x01,0x00,0::72,0x12>>}
  end

  test "new returns correct IPv4Addrs using IPv4 prefix" do
    assert IP.prefix_to_ip("192.0.2.0/24") ==
      {%IP.IPv4Addr{addr: <<192,0,2,0>>}, %IP.IPv4Addr{addr: <<255,255,255,0>>}}
  end

  test "new returns correct IPv6Addrs using IPv6 prefix" do
    assert IP.prefix_to_ip("fe80::/44") ==
      {%IP.IPv6Addr{addr: <<0xfe,0x80,0::112>>}, %IP.IPv6Addr{addr: <<0xfffffffffff::44,0::84>>}}
  end

  test "integer_to_binary_mask returns correct mask for mask_size at byte boundary" do
    assert IP.integer_to_binary_mask(40, 128) == <<0xffffffffff::40, 0::88>>
  end
  test "integer_to_binary_mask fails for non-integer mask" do
    assert_raise ArgumentError, fn ->
      IP.integer_to_binary_mask("a", 128)
    end
  end
  test "integer_to_binary_mask fails for non-integer mask_size" do
    assert_raise ArgumentError, fn ->
      IP.integer_to_binary_mask(1, "a")
    end
  end
  test "integer_to_binary_mask fails for mask_size not at byte boundary" do
    assert_raise ArgumentError, fn ->
      IP.integer_to_binary_mask(40, 127)
    end
  end
end
