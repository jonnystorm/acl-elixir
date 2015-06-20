# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule ACE do
  defstruct ip_version: nil, action: nil, ip_proto: nil, values: [], masks: []
  @type t :: %ACE{
    ip_version: 4 | 6,
    action: :permit | :deny,
    ip_proto: atom,
    values: list,
    masks: list
  }

  def new(ip_version, action, ip_protocol, values, masks) do
    %ACE{
      ip_version: ip_version,
      action: action,
      ip_proto: ip_protocol,
      values: values,
      masks: masks
    }
  end

  def ip_version(ace) do
    ace.ip_version
  end

  def action(ace) do
    ace.action
  end
  def action(ace, new_action) when new_action in [:permit, :deny] do
    %ACE{ace|action: new_action}
  end

  def ip_protocol(ace) do
    ace.ip_proto
  end

  def values(ace) do
    ace.values
  end
  
  def masks(ace) do
    ace.masks
  end

  def icmp(ip_version, action, src, dst, type, code) do
    {src, src_mask} = IP.prefix_to_binary(src)
    {dst, dst_mask} = IP.prefix_to_binary(dst)

    type_mask = <<0xff>>
    code_mask = <<0xff>>

    if type == :any do
      type = 0
      type_mask = <<0>>
    end

    if code == :any do
      code = 0
      code_mask = <<0>>
    end

    type = <<type>>
    code = <<code>>

    ACE.new(ip_version, action, :icmp,
      [PCI.IP.new(src, dst), PCI.ICMP.new(type, code)],
      [PCI.IP.new(src_mask, dst_mask), PCI.ICMP.new(type_mask, code_mask)]
    )
  end

  def tcp(ip_version, action, src, src_port, dst, dst_port) do
    {src, src_mask} = IP.prefix_to_binary(src)
    {dst, dst_mask} = IP.prefix_to_binary(dst)
    
    if src_port == :any do
      src_port = 0
      spt_mask = <<0::16>>
    else
      spt_mask = <<0xffff::16>>
    end

    if dst_port == :any do
      dst_port = 0
      dpt_mask = <<0::16>>
    else
      dpt_mask = <<0xffff::16>>
    end

    src_port = <<src_port::16>>
    dst_port = <<dst_port::16>>

    ACE.new(ip_version, action, :tcp,
      [PCI.IP.new(src, dst), PCI.TCP.new(src_port, dst_port)],
      [PCI.IP.new(src_mask, dst_mask), PCI.TCP.new(spt_mask, dpt_mask)]
    )
  end

  def udp(ip_version, action, src, src_port, dst, dst_port) do
    {src, src_mask} = IP.prefix_to_binary(src)
    {dst, dst_mask} = IP.prefix_to_binary(dst)

    if src_port == :any do
      src_port = 0
      spt_mask = <<0::16>>
    else
      spt_mask = <<0xffff::16>>
    end

    if dst_port == :any do
      dst_port = 0
      dpt_mask = <<0::16>>
    else
      dpt_mask = <<0xffff::16>>
    end

    src_port = <<src_port::16>>
    dst_port = <<dst_port::16>>

    ACE.new(ip_version, action, :udp,
      [PCI.IP.new(src, dst), PCI.UDP.new(src_port, dst_port)],
      [PCI.IP.new(src_mask, dst_mask), PCI.UDP.new(spt_mask, dpt_mask)]
    )
  end

  @spec reflect(ACE.t) :: ACE.t
  def reflect(ace) do
    [ip_value, ip_proto_value] = values(ace)
    [ip_mask, ip_proto_mask] = masks(ace)

    ACE.new(ip_version(ace), action(ace), ip_protocol(ace),
      [PCIProto.reflect(ip_value), PCIProto.reflect(ip_proto_value)],
      [PCIProto.reflect(ip_mask), PCIProto.reflect(ip_proto_mask)]
    )
  end
end

defimpl String.Chars, for: ACE do
  import Kernel, except: [to_string: 1]

  @doc """
  Fix this awful mess.
  """
  def to_string(ace) do
    action = ACE.action(ace)
    [ip_values, ip_masks, l4_values, l4_masks] = ACE.values(ace)
    |> Enum.zip(ACE.masks ace)
    |> Enum.map(&(Tuple.to_list &1))
    |> List.flatten
    src = ip_values
    |> PCI.IP.source
    |> IP.IPv4Addr.new
    dst = ip_values
    |> PCI.IP.destination
    |> IP.IPv4Addr.new
    smask = ip_masks
    |> PCI.IP.source
    |> IP.invert_mask
    |> IP.IPv4Addr.new
    dmask = ip_masks
    |> PCI.IP.destination
    |> IP.invert_mask
    |> IP.IPv4Addr.new

    case ACE.ip_protocol(ace) do
      :icmp ->
        type = l4_values
        |> PCI.ICMP.type
        |> PCI.bits_to_integer
        code = l4_values
        |> PCI.ICMP.code
        |> PCI.bits_to_integer
        tmask = l4_masks
        |> PCI.ICMP.type
        |> PCI.bits_to_integer
        cmask = l4_masks
        |> PCI.ICMP.code
        |> PCI.bits_to_integer
        
        case tmask do
          0x0 ->
            "#{action} icmp #{src} #{smask} #{dst} #{dmask}"
          0xff ->
            case cmask do
              0x0 ->
                "#{action} icmp #{src} #{smask} #{dst} #{dmask} #{type}"
              0xff ->
                "#{action} icmp #{src} #{smask} #{dst} #{dmask} #{type} #{code}"
            end
        end
      :tcp ->
        spt = l4_values
        |> PCI.TCP.source
        |> PCI.bits_to_integer
        dpt = l4_values
        |> PCI.TCP.destination
        |> PCI.bits_to_integer
        sptmask = l4_masks
        |> PCI.TCP.source
        |> PCI.bits_to_integer
        dptmask = l4_masks
        |> PCI.TCP.destination
        |> PCI.bits_to_integer

        case sptmask do
          0x0 ->
            case dptmask do
              0x0 ->
                "#{action} tcp #{src} #{smask} #{dst} #{dmask}"
              0xffff ->
                "#{action} tcp #{src} #{smask} #{dst} #{dmask} eq #{dpt}"
            end
          0xffff ->
            case dptmask do
              0x0 ->
                "#{action} tcp #{src} #{smask} eq #{spt} #{dst} #{dmask}"
              0xffff ->
                "#{action} tcp #{src} #{smask} eq #{spt} #{dst} #{dmask} eq #{dpt}"
            end
        end
      :udp ->
        spt = l4_values
        |> PCI.UDP.source
        |> PCI.bits_to_integer
        dpt = l4_values
        |> PCI.UDP.destination
        |> PCI.bits_to_integer
        sptmask = l4_masks
        |> PCI.UDP.source
        |> PCI.bits_to_integer
        dptmask = l4_masks
        |> PCI.UDP.destination
        |> PCI.bits_to_integer

        case sptmask do
          0x0 ->
            case dptmask do
              0x0 ->
                "#{action} udp #{src} #{smask} #{dst} #{dmask}"
              0xffff ->
                "#{action} udp #{src} #{smask} #{dst} #{dmask} eq #{dpt}"
            end
          0xffff ->
            case dptmask do
              0x0 ->
                "#{action} udp #{src} #{smask} eq #{spt} #{dst} #{dmask}"
              0xffff ->
                "#{action} udp #{src} #{smask} eq #{spt} #{dst} #{dmask} eq #{dpt}"
            end
        end
      _ ->
        ""
    end
  end
end

