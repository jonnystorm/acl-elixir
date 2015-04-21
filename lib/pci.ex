# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule PCI do
  defmodule IPv4 do
    defstruct src: nil, dst: nil
    @type t :: %IPv4{src: <<_ :: 4 * 8>>, dst: <<_ :: 4 * 8>>}
  end

  defmodule IPv6 do
    defstruct src: nil, dst: nil
    @type t :: %IPv6{src: <<_ :: 16 * 8>>, dst: <<_ :: 16 * 8>>}
  end

  defmodule IP do
    def new(source, destination)
        when bit_size(source) == 32 and bit_size(destination) == 32 do
      %IPv4{src: source, dst: destination}
    end
    def new(source, destination)
        when bit_size(source) == 128 and bit_size(destination) == 128 do
      %IPv6{src: source, dst: destination}
    end

    def source(pci), do: pci.src
    def destination(pci), do: pci.dst
  end

  defmodule ICMP do
    defstruct type: <<0>>, code: <<0>>
    @type t :: %ICMP{type: <<_ :: 8>>, code: <<_ :: 8>>}

    def new(type, code) when bit_size(type) == 8 and bit_size(code) == 8 do
      %ICMP{type: type, code: code}
    end
    def new(_source, _destination) do
      raise ArgumentError, message: "unable to create new PCI.ICMP struct"
    end

    @spec type(ICMP.t) :: non_neg_integer
    def type(pci), do: pci.type

    @spec code(ICMP.t) :: non_neg_integer
    def code(pci), do: pci.code
  end

  defmodule TCP do
    defstruct src: <<0::16>>, dst: <<0::16>>
    @type t :: %TCP{src: <<_::16>>, dst: <<_::16>>}

    def new(source, destination)
        when bit_size(source) == 16 and bit_size(destination) == 16 do
      %TCP{src: source, dst: destination}
    end
    def new(_source, _destination) do
      raise ArgumentError, message: "unable to create new PCI.TCP struct"
    end

    @spec source(TCP.t) :: non_neg_integer
    def source(pci), do: pci.src

    @spec destination(TCP.t) :: non_neg_integer
    def destination(pci), do: pci.dst
  end

  defmodule UDP do
    defstruct src: <<0::16>>, dst: <<0::16>>
    @type t :: %UDP{src: <<_::16>>, dst: <<_::16>>}

    def new(source, destination)
        when bit_size(source) == 16 and bit_size(destination) == 16 do
      %UDP{src: source, dst: destination}
    end
    def new(_source, _destination) do
      raise ArgumentError, message: "unable to create new PCI.UDP struct"
    end

    @spec source(UDP.t) :: non_neg_integer
    def source(pci), do: pci.src

    @spec destination(UDP.t) :: non_neg_integer
    def destination(pci), do: pci.dst
  end

  def bits_to_integer(binary) do
    binary
      |> :binary.bin_to_list
      |> Enum.reverse
      |> Enum.with_index
      |> Enum.map(fn {x, n} -> x * trunc(:math.pow(256, n)) end)
      |> Enum.sum
  end
end

defprotocol PCIProto do
  def and_mask(resource, mask)
  def equal?(resource, resource)
  def match?(resource, resource, mask)
  def reflect(resource)
end

defimpl PCIProto, for: PCI.IPv4 do
  @spec and_mask(PCI.IPv4.t, PCI.IPv4.t) :: PCI.IPv4.t
  def and_mask(ip, ip_mask) do
    PCI.IPv4.new(
      Vector.bit_and(PCI.IP.source(ip), PCI.IP.source(ip_mask)),
      Vector.bit_and(PCI.IP.destination(ip), PCI.IP.destination(ip_mask))
    )
  end

  @spec equal?(PCI.IPv4.t, PCI.IPv4.t) :: boolean
  def equal?(ip1, ip2) do
    PCI.IP.source(ip1) == PCI.IP.source(ip2)
      && PCI.IP.destination(ip1) == PCI.IP.destination(ip2)
  end

  @spec match?(PCI.IPv4.t, PCI.IPv4.t, PCI.IPv4.t) :: boolean
  def match?(ip1, ip2, ip_mask) do
    and_mask(ip1, ip_mask) |> equal? and_mask(ip2, ip_mask)
  end

  @spec reflect(IPv4.t) :: IPv4.t
  def reflect(pci) do
    PCI.IP.new(PCI.IP.destination(pci), PCI.IP.source(pci))
  end
end

defimpl PCIProto, for: PCI.IPv6 do
  @spec and_mask(PCI.IPv6.t, PCI.IPv6.t) :: PCI.IPv6.t
  def and_mask(ip, ip_mask) do
    PCI.IPv6.new(
      Vector.bit_and(PCI.IP.source(ip), PCI.IP.source(ip_mask)),
      Vector.bit_and(PCI.IP.destination(ip), PCI.IP.destination(ip_mask))
    )
  end

  @spec equal?(PCI.IPv6.t, PCI.IPv6.t) :: boolean
  def equal?(ip1, ip2) do
    PCI.IP.source(ip1) == PCI.IP.source(ip2)
      && PCI.IP.destination(ip1) == PCI.IP.destination(ip2)
  end

  @spec match?(PCI.IPv6.t, PCI.IPv6.t, PCI.IPv6.t) :: boolean
  def match?(ip1, ip2, ip_mask) do
    and_mask(ip1, ip_mask) |> equal? and_mask(ip2, ip_mask)
  end

  @spec reflect(IPv6.t) :: IPv6.t
  def reflect(pci) do
    PCI.IP.new(PCI.IP.destination(pci), PCI.IP.source(pci))
  end
end

defimpl PCIProto, for: PCI.ICMP do
  @spec and_mask(PCI.ICMP.t, PCI.ICMP.t) :: PCI.ICMP.t
  def and_mask(icmp, icmp_mask) do
    PCI.ICMP.new(
      Vector.bit_and(PCI.ICMP.type(icmp), PCI.ICMP.type(icmp_mask)),
      Vector.bit_and(PCI.ICMP.code(icmp), PCI.ICMP.code(icmp_mask))
    )
  end

  @spec equal?(PCI.ICMP.t, PCI.ICMP.t) :: boolean
  def equal?(icmp1, icmp2) do
    PCI.ICMP.type(icmp1) == PCI.ICMP.type(icmp2)
      && PCI.ICMP.code(icmp1) == PCI.ICMP.code(icmp2)
  end

  @spec match?(PCI.ICMP.t, PCI.ICMP.t, PCI.ICMP.t) :: boolean
  def match?(icmp1, icmp2, icmp_mask) do
    and_mask(icmp1, icmp_mask) |> equal? and_mask(icmp2, icmp_mask)
  end

  @spec reflect(ICMP.t) :: ICMP.t
  def reflect(pci) do
    case PCI.ICMP.type(pci) do
      <<0>> ->
        PCI.ICMP.new(<<8>>, <<0>>)
      <<3>> ->
        PCI.ICMP.new(<<8>>, <<0>>)
      <<8>> ->
        PCI.ICMP.new(<<0>>, <<0>>)
      _ ->
        pci
    end
  end
end

defimpl PCIProto, for: PCI.TCP do
  @spec and_mask(PCI.TCP.t, PCI.TCP.t) :: PCI.TCP.t
  def and_mask(tcp, tcp_mask) do
    PCI.TCP.new(
      Vector.bit_and(PCI.TCP.source(tcp), PCI.TCP.source(tcp_mask)),
      Vector.bit_and(PCI.TCP.destination(tcp), PCI.TCP.destination(tcp_mask))
    )
  end

  @spec equal?(PCI.TCP.t, PCI.TCP.t) :: boolean
  def equal?(tcp1, tcp2) do
    PCI.TCP.source(tcp1) == PCI.TCP.source(tcp2)
      && PCI.TCP.destination(tcp1) == PCI.TCP.destination(tcp2)
  end

  @spec match?(PCI.TCP.t, PCI.TCP.t, PCI.TCP.t) :: boolean
  def match?(tcp1, tcp2, tcp_mask) do
    and_mask(tcp1, tcp_mask) |> equal? and_mask(tcp2, tcp_mask)
  end

  @spec reflect(TCP.t) :: TCP.t
  def reflect(pci) do
    PCI.TCP.new(PCI.TCP.destination(pci), PCI.TCP.source(pci))
  end
end

defimpl PCIProto, for: PCI.UDP do
  @spec and_mask(PCI.UDP.t, PCI.UDP.t) :: PCI.UDP.t
  def and_mask(udp, udp_mask) do
    PCI.UDP.new(
      Vector.bit_and(PCI.UDP.source(udp), PCI.UDP.source(udp_mask)),
      Vector.bit_and(PCI.UDP.destination(udp), PCI.UDP.destination(udp_mask))
    )
  end

  @spec equal?(PCI.UDP.t, PCI.UDP.t) :: boolean
  def equal?(udp1, udp2) do
    PCI.UDP.source(udp1) == PCI.UDP.source(udp2)
      && PCI.UDP.destination(udp1) == PCI.UDP.destination(udp2)
  end

  @spec match?(PCI.UDP.t, PCI.UDP.t, PCI.UDP.t) :: boolean
  def match?(udp1, udp2, udp_mask) do
    and_mask(udp1, udp_mask) |> equal? and_mask(udp2, udp_mask)
  end

  @spec reflect(UDP.t) :: UDP.t
  def reflect(pci) do
    PCI.UDP.new(PCI.UDP.destination(pci), PCI.UDP.source(pci))
  end
end

