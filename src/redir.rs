fn redir() {
  loop {
    let packet = get_packet_from_tun()
    let socks_packet = translate_packet_to_socks5(packet)

  }
}


