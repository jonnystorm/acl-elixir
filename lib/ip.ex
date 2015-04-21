# Copyright © 2015 Jonathan Storm <the.jonathan.storm@gmail.com>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the COPYING.WTFPL file for more details.

defmodule IP do
  # TODO: move version inference out of transforms

  @spec version_to_bits(4 | 6) :: 32 | 128
  def version_to_bits(4), do: 32
  def version_to_bits(6), do: 128

  @spec integer_to_binary_mask(non_neg_integer, pos_integer) :: binary
  def integer_to_binary_mask(int, mask_size)
      when is_integer(int)
       and rem(mask_size, 8) == 0 do
    ones = trunc(:math.pow(2, mask_size)) - 1
    zero_count = mask_size - int

    <<ones::size(int), 0::size(zero_count)>>
  end
  def integer_to_binary_mask(_, mask_size) do
    if is_integer(mask_size) && rem(mask_size, 8) != 0 do
      message = "invalid argument: mask_size must fall on byte boundary"
    else
      message = "invalid argument: integer expected"
    end

    raise ArgumentError, message: message
  end

  def invert_mask(mask) do
    len = bit_size mask
    Vector.bit_xor(mask, integer_to_binary_mask(len, len))
  end

  def contains_only?(string, characters)
      when is_binary(string) and is_binary(characters) do
    char_list = :binary.bin_to_list(characters)
    string
      |> :binary.bin_to_list
      |> Enum.all?(&(&1 in char_list))
  end

  defp ip_proto_num_to_kw_map do
    %{
      0x1  => "icmp",
      0x6  => "tcp",
      0x11 => "udp"
    }
  end

  defp ip_proto_kw_to_num_map do
    %{
      icmp: 0x1,
      tcp: 0x6,
      udp: 0x11
    }
  end

  @spec ip_proto_number_to_keyword(<<_ :: 8>>) :: String.t | nil
  def ip_proto_number_to_keyword(<<proto :: 4>>) do
    ip_proto_num_to_kw_map[proto]
  end
  @spec ip_proto_number_to_keyword(0..255) :: String.t | nil
  def ip_proto_number_to_keyword(proto) when is_integer(proto) do
    ip_proto_num_to_kw_map[proto]
  end

  @spec ip_proto_keyword_to_number(atom) :: 0..255
  def ip_proto_keyword_to_number(keyword) when is_atom(keyword) do
    ip_proto_kw_to_num_map[keyword]
  end
  @spec ip_proto_keyword_to_number(String.t) :: 0..255
  def ip_proto_keyword_to_number(keyword) when is_binary(keyword) do
    key = keyword
      |> String.downcase
      |> String.to_atom

    ip_proto_kw_to_num_map[key]
  end

  @spec prefix_to_ip(binary) :: {IP.IPv4Addr.t, IP.IPv4Addr.t} | {IP.IPv6Addr.t, IP.IPv6Addr.t}
  def prefix_to_ip(prefix) when is_binary(prefix) do
    [address_str, length_str] = :binary.split(prefix, "/")
    length = String.to_integer length_str

    cond do
      IP.IPv6Addr.is_ip_string(address_str) ->
        {IP.IPv6Addr.new(address_str), IP.IPv6Addr.new(length)}
      IP.IPv4Addr.is_ip_string(address_str) ->
        {IP.IPv4Addr.new(address_str), IP.IPv4Addr.new(length)}
      true ->
        raise ArgumentError, message: "invalid prefix"
    end
  end

  @spec prefix_to_binary(String.t) :: {<<_::4*8>>, <<_::4*8>>} | {<<_::16*8>>, <<_::16*8>>}
  def prefix_to_binary(prefix) when is_binary(prefix) do
    prefix
      |> IP.prefix_to_ip
      |> Tuple.to_list
      |> Enum.map(fn ip -> IP.Addr.address(ip) end)
      |> List.to_tuple
  end

  defmodule IPv4Addr do
    defstruct addr: nil
    @type t :: %IPv4Addr{addr: <<_ :: 4 * 8>>}

    def new(address) when is_integer(address) do
      %IPv4Addr{addr: IP.integer_to_binary_mask(address, 32)}
    end
    def new(address) do
      if is_ip_string(address) do
        {:ok, address} = string_to_ip(address)
      end

      if bit_size(address) == 32 do
        %IPv4Addr{addr: address}
      else
        raise ArgumentError, message: "invalid IPv4 binary"
      end
    end

    @spec is_ip_string(String.t) :: boolean
    def is_ip_string(string) when is_binary(string) do
      octets = :binary.split(string, ".", [:global])

      IP.contains_only?(string, "0123456789.")
        and length(octets) == 4
        and Enum.all?(octets, &(&1 != "" && String.to_integer(&1) in 0..255))
    end
    def is_ip_string(_), do: false

    @spec string_to_ip(String.t) :: {:ok, <<_ :: 4 * 8>>} | {:error, :badarg}
    def string_to_ip(string) when is_binary(string) do
      case is_ip_string(string) do
        true ->
          ip = string
            |> :binary.split(".", [:global])
            |> Enum.map(&(String.to_integer &1))
            |> :binary.list_to_bin

          {:ok, ip}
        false ->
          {:error, :badarg}
      end
    end
  end

  defmodule IPv6Addr do
    defstruct addr: nil
    @type t :: %IPv6Addr{addr: <<_ :: 16 * 8>>}

    def new(address) when is_integer(address) do
      %IPv6Addr{addr: IP.integer_to_binary_mask(address, 128)}
    end
    def new(address) do
      if is_ip_string(address) do
        {:ok, address} = string_to_ip(address)
      end

      if bit_size(address) == 128 do
        %IPv6Addr{addr: address}
      else
        raise ArgumentError, message: "invalid IPv6 binary"
      end
    end

    @spec expand_ip_string(String.t) :: String.t
    def expand_ip_string(string) when is_binary(string) do
      sep_count = string
        |> :binary.split(":", [:global])
        |> length
      zero_word_count = 8 - sep_count + 1

      case :binary.split(string, "::", [:global]) do
        [first, last] ->
          zero_words = (for _ <- 1..zero_word_count, do: ":0") |> Enum.join
          expanded = first <> zero_words <> ":" <> last

          if String.last(expanded) == ":" do
            expanded <> "0"
          else
            expanded
          end
        _ ->
          string
      end
    end

    @spec is_ip_string(String.t) :: boolean
    def is_ip_string(string) when is_binary(string) do
      words = string
        |> expand_ip_string
        |> :binary.split(":", [:global])

      IP.contains_only?(string, "0123456789abcdefABCDEF:")
        and length(words) == 8
        and Enum.all?(words, &(String.length(&1) > 0))
        and Enum.all?(words, &(String.length(&1) <= 4))
    end
    def is_ip_string(_), do: false

    @spec integer_to_bytes(integer) :: <<_ :: 8>>
    def integer_to_bytes(int) when is_integer(int) do
      if int == 0, do: <<0>>
      int
        |> Stream.unfold(fn 0 -> nil; x -> {rem(x, 256), div(x, 256)} end)
        |> Enum.to_list
        |> Enum.reverse
        |> :binary.list_to_bin
    end

    defp string_to_byteword(string, base) do
      string
        |> String.to_integer(base)
        |> integer_to_bytes
        |> String.rjust(2, 0)
    end

    defp _string_to_ip(<<>>, {cur_word_str, acc}) do
      acc <> string_to_byteword(cur_word_str, 16)
    end
    defp _string_to_ip(<<char, tail :: binary>>, {cur_word_str, acc}) do
      case char do
        ?: ->
          if cur_word_str == <<>> do
            _string_to_ip(tail, {<<>>, acc}) 
          else
            _string_to_ip(tail, {<<>>, acc <> string_to_byteword(cur_word_str, 16)})
          end
        _ ->
          _string_to_ip(tail, {cur_word_str <> <<char>>, acc})
      end
    end

    @spec string_to_ip(String.t) :: {:ok, <<_ :: 16 * 8>>} | {:error, :badarg}
    def string_to_ip(string) when is_binary(string) do
      case is_ip_string(string) do
        true ->
          {:ok, _string_to_ip(expand_ip_string(string), {<<>>, <<>>})}
        false ->
          {:error, :badarg}
      end
    end
  end

  defprotocol Addr do
    def address(ip)
  end
  
  defimpl Addr, for: IPv4Addr do
    def address(ipv4), do: ipv4.addr
  end

  defimpl Addr, for: IPv6Addr do
    def address(ipv6), do: ipv6.addr
  end
end

defimpl String.Chars, for: IP.IPv4Addr do
  import Kernel, except: [to_string: 1]

  @spec to_string(IP.IPv4Addr.t) :: String.t
  def to_string(ipv4) do
    ipv4
      |> IP.Addr.address
      |> :binary.bin_to_list
      |> Enum.join(".")
  end
end

defimpl String.Chars, for: IP.IPv6Addr do
  import Kernel, except: [to_string: 1]

  @spec to_string(IP.IPv6Addr.t) :: String.t
  def to_string(ipv6) do
    ipv6
      |> IP.Addr.address
      |> :binary.bin_to_list
      |> Enum.join(":")
      |> String.replace(~r/(0:)+/, ":")
  end
end
