// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: PDCP Uplink L3/L4 Header Parser
// PDCP 계층에서 복호화된 IP 패킷의 L3/L4 헤더를 파싱하고 5-Tuple을 추출합니다.

/*
 * ============================================================
 * JBPF Codelet 기본 구조 설명
 * ============================================================
 *
 * 1. 필수 헤더 Include
 *    - jbpf_defs.h: JBPF 기본 타입 및 매크로
 *    - jbpf_helper.h: Helper 함수 (jbpf_ringbuf_output 등)
 *    - common.h: 공통 구조체 정의 (IP/TCP/UDP 헤더)
 *
 * 2. Map 정의
 *    - jbpf_ringbuf_map(): Application으로 데이터 전송용 링버퍼
 *
 * 3. Context 구조체
 *    - Application의 구조체와 100% 동일해야 함!
 *
 * 4. Main 함수
 *    - SEC("jbpf_generic") 매크로 필수
 *    - return 0 = 성공, return 1 = 에러
 */

#define USE_JBPF_PRINTF_HELPER
#include "jbpf_defs.h"
#include "jbpf_helper.h"
#include "common.h"

/*
 * ============================================================
 * Rate Limiting 상수 및 상태 구조체
 * ============================================================
 *
 * 문제: iperf3 UDP 고속 트래픽은 수만 pkt/s → 매 패킷 출력 시
 *       nr-softmodem 터미널 과부하
 *
 * 해결: ARRAY 맵에 {last_report_ns, pkt_count}를 저장하여
 *       5초마다 한 번만 ringbuf에 출력.
 *
 * jbpf_time_get_ns() 동작:
 *   - jBPF 런타임이 제공하는 helper (jbpf_helper.h:86)
 *   - 내부: CLOCK_MONOTONIC 기반, 시스템 부팅 이후 nanoseconds 반환
 *   - ARRAY 맵 초기값 = 0 → 첫 호출 시 즉시 리포트 출력
 *
 * ULL(unsigned long long) 접미사가 필요한 이유:
 *   5 * 1,000,000,000 = 5,000,000,000 > INT_MAX(2,147,483,647)
 *   → 32비트 정수로는 overflow. ULL로 64비트 연산 보장.
 */
#define REPORT_INTERVAL_NS  (5ULL * 1000000000ULL)

struct hp_rate_state {
    uint64_t last_report_ns;  /* 마지막 ringbuf 출력 시각 (nanoseconds) */
    uint64_t pkt_count;       /* 마지막 출력 이후 처리된 패킷 수 */
};

/*
 * Rate Limiting 상태 맵 (ARRAY 타입)
 *
 * ARRAY vs HASHMAP:
 *   ARRAY:   key = 정수 인덱스, 항상 메모리 할당됨, lookup 항상 성공
 *   HASHMAP: key = 임의값, 동적 관리, 처음에 없으면 NULL
 *   → 전역 단일 상태(카운터)에는 ARRAY가 적합
 *
 * max_entries=1: key=0만 유효. sizeof(hp_rate_state)=16바이트.
 */
struct jbpf_load_map_def SEC("maps") hp_state_map = {
    .type        = JBPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct hp_rate_state),
    .max_entries = 1,
};

/*
 * ============================================================
 * Output Map 정의 - Application으로 데이터 전송
 * ============================================================
 *
 * Syntax: jbpf_ringbuf_map(map_name, struct_type, num_elements)
 *
 * 파라미터:
 * - outmap: Map 이름
 * - struct Packet5Tuple: 전송할 데이터 구조체
 * - 32: 링버퍼 크기 (5초에 1개 출력이므로 32개면 충분)
 *   기존 1024에서 줄임: 출력 빈도가 낮아졌으므로 메모리 절약
 */
//Ringbuffer Map 생성 32개의 Packet5Tuple 구조체를 저장할 수 있는 outmap이라는 이름의 링버퍼 맵을 생성
jbpf_ringbuf_map(outmap, struct Packet5Tuple, 32);

/* Hook context 정의는 ../pdcp_hook_ctx.h 에 있다 (gNB 쪽과 공유).
 * 재정의하면 양쪽 레이아웃이 어긋나며 silent corruption 이 난다. */
#include "pdcp_hook_ctx.h"

/*
 * ============================================================
 * Helper: Network Byte Order 변환
 * ============================================================
 */
static inline uint16_t ntohs(uint16_t netshort) {
    return (netshort >> 8) | (netshort << 8);
}

/*
 * ============================================================
 * Main 함수: Codelet Entry Point
 * ============================================================
 *
 * SEC("jbpf_generic"): ELF section 지정 (필수!)
 *
 * 실행 흐름:
 * 1. hook_pdcp_uplink() 호출
 * 2. jbpf_main() 실행
 * 3. 5-Tuple 추출
 * 4. outmap으로 전송
 */
SEC("jbpf_generic")
uint64_t jbpf_main(void* state)
{
    /*
     * Step 1: Context 포인터 캐스팅
     */
    struct pdcp_uplink_ctx* ctx = (struct pdcp_uplink_ctx*)state;
    if (!ctx) {
        return 1;
    }

    /*
     * Step 1-B: Rate Limiting (5초마다 한 번만 출력)
     *
     * ARRAY 맵 lookup 패턴:
     *   uint32_t key = 0;
     *   struct T *ptr = jbpf_map_lookup_elem(&map, &key);
     *   if (!ptr) return 1;
     *
     * ARRAY 맵에서 key < max_entries이면 실제로 NULL이 되는 일이 없다.
     * 하지만 eBPF verifier는 이를 정적으로 증명할 수 없으므로
     * 반드시 NULL 체크 코드를 작성해야 검증을 통과한다.
     *
     * 흐름:
     *   1. pkt_count++ (매 패킷마다 카운터 증가)
     *   2. now - last_report_ns < 5s → return 0 (출력 없음)
     *   3. 5s 경과 → saved_count 보존, 타이머 리셋, 카운터 리셋
     *   4. 이후 기존 파싱 로직 실행 → ringbuf 출력
     */
    uint32_t rate_key = 0;
    struct hp_rate_state *st = jbpf_map_lookup_elem(&hp_state_map, &rate_key);
    if (!st)
        return 1;

    st->pkt_count++;

    uint64_t now = jbpf_time_get_ns();
    if (now - st->last_report_ns < REPORT_INTERVAL_NS)
        return 0;  /* 5초 아직 안 됨: 카운트만 하고 종료 */

    /* 5초 경과: 카운트 저장 후 리셋 */
    uint64_t saved_pkt_count = st->pkt_count;
    st->last_report_ns       = now;
    st->pkt_count            = 0;

    /*
     * [디버깅용] Codelet 진입 확인 로그
     * 이 로그가 보이면 Codelet은 정상적으로 로드되고 Hook이 호출된 것입니다.
     */
    jbpf_printf_debug("[CODELET] jbpf_main entered! (UE ID: %u)\n", ctx->ue_id);

    /*
     * Step 2: 메모리 포인터 변환 (uint64_t → 포인터)
     */
    struct ip_hdrP* ip = (struct ip_hdrP*)(void*)ctx->data;
    void* data_end = (void*)ctx->data_end;

    /*
     * Step 3: eBPF Verifier 경계 검사 (CRITICAL!)
     *
     * 규칙: 모든 포인터 접근 전에 경계 검사 필수!
     * 패턴: if (ptr + 1 > data_end) return 1;
     */
    if ((void*)(ip + 1) > data_end) {
        jbpf_printf_debug("[CODELET] Error: Packet too short for IP header\n");
        return 1;  // IP 헤더가 패킷 범위 초과
    }

    /*
     * Step 4: IP 헤더 검증
     */
    if (ip->version != 4) {
        jbpf_printf_debug("[CODELET] Error: Not IPv4 packet (ver=%d)\n", ip->version);
        return 1;  // IPv4가 아님
    }

    /*
     * Step 5: IP 헤더 필드 추출
     */
    uint8_t ihl = ip->ihl * 4;
    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->saddr;  // 네트워크 바이트 오더 그대로 저장
    uint32_t dst_ip = ip->daddr;

    /*
     * Step 6: L4 헤더 위치 계산
     *
     * 메모리 레이아웃:
     * [IP Header][L4 Header][Payload]
     * └─ ip   └─ l4_start
     */
    void* l4_start = (void*)ip + ihl;

    /*
     * Step 7: 출력 데이터 초기화
     */
    struct Packet5Tuple packet = {0};
    packet.timestamp  = ctx->meta_data; // 패킷 처리 시작 시간 기록
    packet.pkt_count  = saved_pkt_count; // 이 윈도우에서 처리한 패킷 수
    packet.src_ip     = src_ip;
    packet.dst_ip     = dst_ip;
    packet.ue_id      = ctx->ue_id;
    packet.qfi        = ctx->qfi;
    packet.protocol   = protocol;

    /*
     * Step 8: L4 프로토콜별 포트 추출
     *
     * TCP (6): 헤더 최소 20 bytes
     * UDP (17): 헤더 고정 8 bytes
     */
    if (protocol == IPPROTO_TCP) {
        struct tcp_hdr* tcp = (struct tcp_hdr*)l4_start;

        // eBPF Verifier 경계 검사
        if ((void*)(tcp + 1) > data_end) {
            return 1;
        }

        // 포트 추출 (Network → Host byte order)
        packet.src_port = ntohs(tcp->source);
        packet.dst_port = ntohs(tcp->dest);

    } else if (protocol == IPPROTO_UDP) {
        struct udp_hdr* udp = (struct udp_hdr*)l4_start;

        if ((void*)(udp + 1) > data_end) {
            return 1;
        }

        packet.src_port = ntohs(udp->source);
        packet.dst_port = ntohs(udp->dest);

    } else {
        // 기타 프로토콜 (ICMP 등) - 포트 없음
        packet.src_port = 0;
        packet.dst_port = 0;
    }

    /*
     * Step 9: 디버그 로그 출력
     * IP 주소는 네트워크 바이트 오더 (Big-Endian)이므로
     * Little-Endian x86_64에서 바이트 배열로 읽으면 역순으로 나옴
     * → 역순으로 추출해서 출력
     */
#ifdef USE_JBPF_PRINTF_HELPER
    {
        uint8_t *s = (uint8_t *)&packet.src_ip;
        uint8_t *d = (uint8_t *)&packet.dst_ip;

        if (protocol == IPPROTO_TCP) {
            jbpf_printf_debug("[CODELET] TCP %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (UE=%u QFI=%u)\n",
                              s[3], s[2], s[1], s[0], packet.src_port,
                              d[3], d[2], d[1], d[0], packet.dst_port,
                              ctx->ue_id, ctx->qfi);
        } else if (protocol == IPPROTO_UDP) {
            jbpf_printf_debug("[CODELET] UDP %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u (UE=%u QFI=%u)\n",
                              s[3], s[2], s[1], s[0], packet.src_port,
                              d[3], d[2], d[1], d[0], packet.dst_port,
                              ctx->ue_id, ctx->qfi);
        } else {
            jbpf_printf_debug("[CODELET] Proto=%u %u.%u.%u.%u -> %u.%u.%u.%u (UE=%u QFI=%u)\n",
                              protocol,
                              s[3], s[2], s[1], s[0],
                              d[3], d[2], d[1], d[0],
                              ctx->ue_id, ctx->qfi);
        }
    }
#endif

    /*
     * Step 10: 결과 데이터 전송
     *
     * jbpf_ringbuf_output(&map, &data, size)
     * → outmap 링버퍼에 packet 복사
     * → Application I/O Handler에서 읽을 수 있음
     * RingBuffer에 5-Tuple 구조체(데이터) 전송(outmap 맵을 통해 write)
     */

    if (jbpf_ringbuf_output(&outmap, &packet, sizeof(packet)) < 0) {
        return 1;
    }

    /*
     * Step 11: 성공 반환
     */
    return 0;
}
