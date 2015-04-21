# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule ACLTest do
  use ExUnit.Case, async: true
  use ACL

  test "to_string returns correct string from ACL" do
    test_acl = ACL.new(4, "Test ACL")
      |> permit(:tcp, "192.0.2.0/24", host("192.0.2.4"), eq(443))
      |> deny(:icmp, host("192.0.2.1"), host("192.0.2.4"))
  
    assert to_string(test_acl) == ("""
    ip access-list extended test_acl
      permit tcp 192.0.2.0 0.0.0.255 192.0.2.4 0.0.0.0 eq 443
      deny icmp 192.0.2.1 0.0.0.0 192.0.2.4 0.0.0.0
    """)
  end

  test "append returns correct ACL" do
    test_acl = ACL.new(4, "Test ACL")
    test_ace = ACE.icmp(4, :permit, "192.0.2.1/32", "192.0.2.4/32", :any, :any)
    result = test_acl
      |> ACL.append(test_ace)
      |> ACL.aces

    assert result == [test_ace]
  end
  test "append fails for ACL/ACE with mismatched IP version" do
    test_acl = ACL.new(4, "Test ACL")
    test_ace = ACE.icmp(6, :permit, "fe80::1/128", "fe80::4/128", :any, :any)

    assert_raise ArgumentError, fn ->
      test_acl |> ACL.append(test_ace)
    end
  end

  test "concat returns ACL with correct ACEs" do
    test_ace = ACE.tcp(4, :permit, "192.0.2.0/24", :any, "192.0.2.4/32", 443)
    test_acl1 = ACL.new(4, "Test ACL 1", [test_ace])
    test_acl2 = ACL.new(4, "Test ACL 2", [test_ace])
    result = test_acl1
      |> ACL.concat(test_acl2)
      |> ACL.aces

    assert result == [test_ace, test_ace]
  end
  test "concat fails for ACLs with mismatched IP versions" do
    test_acl1 = ACL.new(4, "Test ACL 1")
    test_acl2 = ACL.new(6, "Test ACL 2")

    assert_raise ArgumentError, fn ->
      ACL.concat(test_acl1, test_acl2)
    end
  end

  test "interleave returns ACL with correct ACEs" do
    test_ace1 = ACE.tcp(4, :permit, "192.0.2.0/24", :any, "192.0.2.4/32", 443)
    test_ace2 = ACE.icmp(4, :deny, "192.0.2.1/32", "192.0.2.4/32", :any, :any)
    test_acl1 = ACL.new(4, "Test ACL 1", [test_ace1, test_ace1])
    test_acl2 = ACL.new(4, "Test ACL 2", [test_ace2])
    result = test_acl1
      |> ACL.interleave(test_acl2)
      |> ACL.aces

    assert result == [test_ace1, test_ace2, test_ace1]
  end
  test "interleave fails for ACLs with mismatched IP versions" do
    test_acl1 = ACL.new(4, "Test ACL 1")
    test_acl2 = ACL.new(6, "Test ACL 2")

    assert_raise ArgumentError, fn ->
      ACL.interleave(test_acl1, test_acl2)
    end
  end
end
