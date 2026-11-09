Scenarios:
- scenario3.pcap: a new session with the same (src_ip, dst_ip, src_port, dst_port) tuple is created
- scenario4.pcap: FIN is retransmitted
- scenario5.pcap: client sends 3 SYN (retranmission) interlaced with 3 SYN/ACKs of the server
- scenario6.pcap: first SYN packet has 100 bytes and it's not TFO
- scenario7.pcap: handshake is done, then SEQ is wrapped around for a packet that arrives ahead of the previous one
