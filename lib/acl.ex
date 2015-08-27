# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule ACL do
  defmacro __using__(_opts) do
    quote do
      import ACL
    end
  end

  defmacro host(host) do
    quote do
      unquote(host) <> "/32"
    end
  end

  defmacro eq(port) do
    quote do
      [eq: unquote(port)]
    end
  end

  defstruct ip_version: nil, name: nil, aces: []
  @type t :: %ACL{ip_version: 4 | 6, name: String.t, aces: list}

  @spec new(4 | 6) :: ACL.t
  @spec new(4 | 6, String.t) :: ACL.t
  @spec new(4 | 6, String.t, [ACE.t]) :: ACL.t
  def new(4) do
    %ACL{ip_version: 4, name: ""}
  end
  def new(6) do
    %ACL{ip_version: 6, name: ""}
  end
  def new(4, name) when is_binary(name) do
    %ACL{ip_version: 4, name: name}
  end
  def new(6, name) when is_binary(name) do
    %ACL{ip_version: 6, name: name}
  end
  def new(4, name, aces) when is_binary(name) and is_list(aces) do
    %ACL{ip_version: 4, name: name, aces: aces}
  end
  def new(6, name, aces) when is_binary(name) and is_list(aces) do
    %ACL{ip_version: 6, name: name, aces: aces}
  end

  def aces(acl) do
    acl.aces
  end
  def aces(acl, aces) when is_list(aces) do
    %ACL{acl|aces: aces}
  end

  def name(acl) do
    acl.name
  end
  def name(acl, new_name) when is_binary(new_name) do
    %ACL{acl|name: new_name}
  end

  def ip_version(acl) do
    acl.ip_version
  end

  @spec append(ACL.t, ACE.t) :: ACL.t
  def append(acl, ace) do
    case ip_version(acl) / ACE.ip_version(ace) do
      1.0 ->
        acl |> aces(aces(acl) ++ [ace])
      _ ->
        raise ArgumentError, message: "ACL and ACE must have same IP version"
    end
  end

  @spec concat(ACL.t, ACL.t) :: ACL.t
  def concat(acl1, acl2) do
    case ip_version(acl1) / ip_version(acl2) do
      1.0 ->
        acl1 |> aces(aces(acl1) ++ aces(acl2))
      _ ->
        raise ArgumentError, message: "ACLs must have the same IP version"
    end
  end
  @spec concat([ACL.t]) :: ACL.t
  def concat(acls) do
    acls |> Enum.reduce(ACL.new(4), fn(acl, acc) -> concat(acc, acl) end)
  end

  defp flat_zip(list1, list2) do
    list1
    |> Enum.zip(list2)
    |> Enum.map(&(Tuple.to_list &1))
    |> List.flatten
  end

  @spec interleave(ACL.t, ACL.t) :: ACL.t
  def interleave(acl1, acl2) do
    case ip_version(acl1) / ip_version(acl2) do
      1.0 ->
        interleaved_aces = aces(acl1) |> flat_zip(aces acl2)

        remaining = [aces(acl1), aces(acl2)]
        |> Enum.max_by(fn l -> length l end)
        |> Enum.drop(div length(interleaved_aces), 2)

        acl1 |> aces(interleaved_aces ++ remaining)
      _ ->
        raise ArgumentError, message: "ACLs must have the same IP version"
    end
  end

  @spec reflect(ACL.t) :: ACL.t
  def reflect(acl) do
    reflected_aces = aces(acl) |> Enum.map(&(ACE.reflect &1))

    acl |> aces(reflected_aces)
  end

  defp append_icmp_ace(acl, action, src, dst, type, code) do
    append(acl, ACE.icmp(ip_version(acl), action, src, dst, type, code))
  end

  defp append_tcp_ace(acl, action, src, src_port, dst, dst_port) do
    append(acl, ACE.tcp(ip_version(acl), action, src, src_port, dst, dst_port))
  end

  defp append_udp_ace(acl, action, src, src_port, dst, dst_port) do
    append(acl, ACE.udp(ip_version(acl), action, src, src_port, dst, dst_port))
  end

  def permit(acl, :icmp, source, destination) do
    append_icmp_ace(acl, :permit, source, destination, :any, :any)
  end
  def permit(acl, :tcp, source, destination) do
    append_tcp_ace(acl, :permit, source, :any, destination, :any)
  end
  def permit(acl, :udp, source, destination) do
    append_udp_ace(acl, :permit, source, :any, destination, :any)
  end

  def permit(acl, :tcp, source, [eq: source_port], destination) do
    append_tcp_ace(acl, :permit, source, source_port, destination, :any)
  end
  def permit(acl, :tcp, source, destination, [eq: destination_port]) do
    append_tcp_ace(acl, :permit, source, :any, destination, destination_port)
  end
  def permit(acl, :udp, source, [eq: source_port], destination) do
    append_udp_ace(acl, :permit, source, source_port, destination, :any)
  end
  def permit(acl, :udp, source, destination, [eq: destination_port]) do
    append_udp_ace(acl, :permit, source, :any, destination, destination_port)
  end

  def permit(acl, :icmp, source, destination, type, code) do
    append_icmp_ace(acl, :permit, source, destination, type, code)
  end
  def permit(acl, :tcp, source, [eq: source_port], destination, [eq: destination_port]) do
    append_tcp_ace(acl, :permit, source, source_port, destination, destination_port)
  end
  def permit(acl, :tcp, source, source_port, destination, destination_port) do
    append_tcp_ace(acl, :permit, source, source_port, destination, destination_port)
  end
  def permit(acl, :udp, source, [eq: source_port], destination, [eq: destination_port]) do
    append_udp_ace(acl, :permit, source, source_port, destination, destination_port)
  end
  def permit(acl, :udp, source, source_port, destination, destination_port) do
    append_udp_ace(acl, :permit, source, source_port, destination, destination_port)
  end

  def deny(acl, :icmp, source, destination) do
    append_icmp_ace(acl, :deny, source, destination, :any, :any)
  end
  def deny(acl, :tcp, source, destination) do
    append_tcp_ace(acl, :deny, source, :any, destination, :any)
  end
  def deny(acl, :udp, source, destination) do
    append_udp_ace(acl, :deny, source, :any, destination, :any)
  end

  def deny(acl, :tcp, source, [eq: source_port], destination) do
    append_tcp_ace(acl, :deny, source, source_port, destination, :any)
  end
  def deny(acl, :tcp, source, destination, [eq: destination_port]) do
    append_tcp_ace(acl, :deny, source, :any, destination, destination_port)
  end
  def deny(acl, :udp, source, [eq: source_port], destination) do
    append_udp_ace(acl, :deny, source, source_port, destination, :any)
  end
  def deny(acl, :udp, source, destination, [eq: destination_port]) do
    append_udp_ace(acl, :deny, source, :any, destination, destination_port)
  end

  def deny(acl, :icmp, source, destination, type, code) do
    append_icmp_ace(acl, :deny, source, destination, type, code)
  end
  def deny(acl, :tcp, source, [eq: source_port], destination, [eq: destination_port]) do
    append_tcp_ace(acl, :deny, source, source_port, destination, destination_port)
  end
  def deny(acl, :tcp, source, source_port, destination, destination_port) do
    append_tcp_ace(acl, :deny, source, source_port, destination, destination_port)
  end
  def deny(acl, :udp, source, [eq: source_port], destination, [eq: destination_port]) do
    append_udp_ace(acl, :deny, source, source_port, destination, destination_port)
  end
  def deny(acl, :udp, source, source_port, destination, destination_port) do
    append_udp_ace(acl, :deny, source, source_port, destination, destination_port)
  end
end

defimpl String.Chars, for: ACL do
  import Kernel, except: [to_string: 1]

  def to_string(acl) do
    if ACL.ip_version(acl) == 6 do
      base_str = "ipv6"
    else
      base_str = "ip"
    end

    acl_name = acl
    |> ACL.name
    |> String.downcase
    |> String.replace(" ", "_")

    ([base_str <> " access-list extended " <> acl_name, "\n"]
      ++ (for ace <- ACL.aces(acl), do: "  #{ace}\n"))
    |> Enum.join
  end
end
