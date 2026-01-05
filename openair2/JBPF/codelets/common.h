#pragma once

#include <stdint.h>

//1. Packet header 정의

struct eth_hdr{
    uint8_t dst_mac[6]; //Source MAC 주소
    uint8_t src_mac[6]; //Destination MAC 주소
    uint16_t h_proto; //프로토콜 타입
}__attribute__((packed));

struct ip_hdrP{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint8_t ihl:4, version:4; // Little-Endian: IHL은 하위 4비트
#else
    uint8_t version:4, ihl:4; // Big-Endian
#endif
    uint8_t tos; // Type of Service
    uint16_t tot_len; // Total Length
    uint16_t id; // Identification
    uint16_t frag_off; // Fragment Offset
    uint8_t ttl; // Time to Live
    uint8_t protocol; // Protocol(TCP, UDP 등)
    uint16_t check; // Header Checksum
    uint32_t saddr; // Source IP Address
    uint32_t daddr; // Destination IP Address
}__attribute__((packed));


// TCP 헤더
struct tcp_hdr {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint32_t seq;
    uint32_t ack_seq;
    uint16_t res1:4,
             doff:4,
             fin:1,
             syn:1,
             rst:1,
             psh:1,
             ack:1,
             urg:1,
             ece:1,
             cwr:1;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
} __attribute__((packed));

// UDP 헤더
struct udp_hdr {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint16_t len;         // Datagram length
    uint16_t check;       // Checksum
} __attribute__((packed));
struct Packet5Tuple{
    uint64_t timestamp;  // Latency 측정을 위한 타임스탬프
    uint32_t src_ip;     // 네트워크 바이트 오더 (빅엔디안)
    uint32_t dst_ip;     // 네트워크 바이트 오더 (빅엔디안)
    uint16_t src_port;   // 호스트 바이트 오더 (변환 완료)
    uint16_t dst_port;   // 호스트 바이트 오더 (변환 완료)
    uint32_t ue_id;
    uint8_t protocol;
    uint8_t qfi;
    uint16_t _padding;   // 32바이트 정렬 (2바이트만 필요)
} __attribute__((packed));

// 프로토콜 상수 정의
#define ETH_P_IP    0x0800
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17