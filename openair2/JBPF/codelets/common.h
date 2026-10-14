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
    /*
     * timestamp: PDCP hook이 호출된 시점의 CPU TSC (rdtsc_oai())
     *   - nr-softmodem.c에서 (current_tsc - timestamp) / cpuf / 1000.0 으로
     *     PDCP → Application 레이턴시를 마이크로초 단위로 계산
     */
    uint64_t timestamp;  // CPU TSC (rdtsc_oai)

    /*
     * pkt_count: 마지막 리포트 이후 이 흐름에서 처리된 패킷 수
     *   - codelet이 5초마다 한 번씩 ringbuf에 출력하므로
     *     pkt_count = 지난 5초 동안 PDCP를 통과한 패킷 수
     *   - iperf3 1Gbps UDP → 약 87,000 pkt/s × 5s = ~435,000
     */
    uint64_t pkt_count;  // 마지막 리포트 이후 누적 패킷 수

    uint32_t src_ip;     // 네트워크 바이트 오더 (Big-Endian, 변환 안 함)
    uint32_t dst_ip;     // 네트워크 바이트 오더

    /*
     * 포트는 codelet에서 ntohs()로 변환되어 저장됨 (Host Byte Order)
     * 즉 dec 5201이면 그대로 5201로 저장됨
     */
    uint16_t src_port;   // 호스트 바이트 오더 (변환 완료)
    uint16_t dst_port;   // 호스트 바이트 오더

    uint32_t ue_id;      // UE 식별자 (RNTI 기반, PDCP 엔티티에서 가져옴)
    uint8_t  protocol;   // IP 프로토콜 번호: 6=TCP, 17=UDP, 1=ICMP
    uint8_t  qfi;        // QoS Flow Identifier (SDAP 헤더에서 추출, 0~63)
    uint16_t _padding;   // 구조체 크기를 4바이트 배수로 맞추기 위한 패딩
} __attribute__((packed));
/*
 * sizeof(Packet5Tuple) = 8+8+4+4+2+2+4+1+1+2 = 36 bytes
 * 8바이트 정렬: 36 % 8 = 4 → packed이므로 컴파일러 padding 없음
 * ringbuf 전송/수신 시 반드시 양쪽이 동일한 헤더를 사용해야 함
 */

/* 프로토콜 상수
 *
 * 코드렛은 eBPF 타겟이라 <netinet/in.h> 를 쓸 수 없어서 직접 정의한다.
 * 그런데 이 헤더는 호스트(nr-softmodem.c)도 include 하고, 거기서는
 * jbpf.h → jbpf_config.h → netinet/in.h 경로로 같은 매크로가 이미 들어와
 * "IPPROTO_TCP redefined" 경고가 났다. 값은 같으니 가드만 씌운다. */
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif