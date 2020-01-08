# IP over SOCKS

This project implements a method to tunnel IP traffic (spec. TCP & UDP) over a
SOCKS5 proxy that supports both CONNECT and UDP ASSOCIATE methods.

The implemented method is described by the author of fqrouter project in [this post (Chinese)](https://fqrouter.tumblr.com/post/51474945203/socks%E4%BB%A3%E7%90%86%E8%BD%ACvpn).

## Usage

1. Clone and build the program
2. Start the socks proxy server
3. Run `ip-over-socks <SOCKS_PROXY_ADDR>:<SOCKS_PROXY_PORT>`
4. (Mandatory) Add route for the tun device:
  `ip route add 10.0.0.0/16 via 10.0.0.1`
5. Add more routes according to your need, for example:
  `ip route add 8.8.8.8 via 10.0.0.1`

The address of the tun device can be specified using the `-n` option. See the section below for all available options.

## Command line options

Use `ip-over-socks --help` to check the help information.

    ip-over-socks 0.1.0
    Tunnel TCP and UDP traffic over SOCKS5 Proxy

    USAGE:
        ip-over-socks [OPTIONS] <socks-server>

    FLAGS:
        -h, --help
                Prints help information

        -V, --version
                Prints version information


    OPTIONS:
        -m, --mtu <mtu>
                MTU value for the interface [default: 1490]

        -n, --net <net>
                The address space for the device

                The first available address will get assigned to the device, the second address will be taken as a dummy
                address for internal use. Therefore, you need to assign it a network space to support at least 2 hosts. In
                other words, the prefix length needs to be shorter than /31. [default: 10.0.0.1/16]
        -t, --tcp-port <tcp-port>
                Port for internal TCP proxy [default: 10001]

        -u, --udp-port <udp-port>
                Port for internal UDP proxy [default: 10001]


    ARGS:
        <socks-server>
                Address to the socks5 server

                The proxy must support CONNECT and UDP ASSOCIATE methods and do not have authentication.

## Copyright

Copyright 2020 Shou Ya

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.


