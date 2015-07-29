defmodule ACETest do
  use ExUnit.Case

  test "produces an ACE permitting ICMP Echo from client to server from an ACE permitting ICMP Echo-Reply from server to client" do
    initial = %ACL{
      ip_version: 4,
      name: "",
      aces: [
        %ACE{
          action: :permit,
          ip_proto: :icmp,
          ip_version: 4,
          values: [
            %PCI.IPv4{src: <<192, 0, 2, 1>>, dst: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<0>>}
          ],
          masks: [
            %PCI.IPv4{src: <<255, 255, 255, 255>>, dst: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<255>>, type: <<255>>}
          ]
        }
      ]
    }

    result = %ACL{
      ip_version: 4,
      name: "",
      aces: [
        %ACE{
          action: :permit,
          ip_proto: :icmp,
          ip_version: 4,
          values: [
            %PCI.IPv4{dst: <<192, 0, 2, 1>>, src: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<8>>}
          ],
          masks: [
            %PCI.IPv4{dst: <<255, 255, 255, 255>>, src: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<255>>, type: <<255>>}
          ]
        }
      ]
    }

    assert ACL.reflect(initial) == result
  end

  test "produces an ACE permitting ICMP Echo-Reply from server to client from an ACE permitting ICMP Echo from client to server" do
    initial = %ACL{
      ip_version: 4,
      name: "",
      aces: [
        %ACE{
          action: :permit,
          ip_proto: :icmp,
          ip_version: 4,
          values: [
            %PCI.IPv4{dst: <<192, 0, 2, 1>>, src: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<0>>}
          ],
          masks: [
            %PCI.IPv4{dst: <<255, 255, 255, 255>>, src: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<0>>}
          ]
        }
      ]
    }

    result = %ACL{
      ip_version: 4,
      name: "",
      aces: [
        %ACE{
          action: :permit,
          ip_proto: :icmp,
          ip_version: 4,
          values: [
            %PCI.IPv4{src: <<192, 0, 2, 1>>, dst: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<0>>}
          ],
          masks: [
            %PCI.IPv4{src: <<255, 255, 255, 255>>, dst: <<0, 0, 0, 0>>},
            %PCI.ICMP{code: <<0>>, type: <<0>>}
          ]
        }
      ]
    }

    assert ACL.reflect(initial) == result
  end
end
