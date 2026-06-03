// Copyright (c) 2026 OpenAirInterface
//
// JBPF Codelet: 6G Demand Packet Parser
//
// 역할:
//   PDCP 계층에서 복호화된 UL IP 패킷 중 demand 패킷
//   (UDP dst_port=48888, protocol_id=0x36474E49 '6GNI')을 식별하고 파싱하여
//   5초 주기로 Application(nr-softmodem)에 보고한다.
//
// -----------------------------------------------------------------------
// 전체 데이터 흐름
// -----------------------------------------------------------------------
//
//  UE app: write(sock, data)  → 실제 데이터
//  UE lib: sendto(demand_sock, demand6_pkt, 16, ...)  → demand UDP 패킷
//                        ↓ 둘 다 동일한 DRB를 통해 전송
//  [5G 프로토콜 스택: RRC → SDAP → PDCP → RLC → MAC → PHY]
//                        ↓
//  gNB PDCP 복호화 완료 → deliver_sdu_drb()
//                        ↓
//  hook_pdcp_uplink() → 이 codelet 실행
//                        ↓
//  ctx->data = 복호화된 IP 패킷 시작 (SDAP 헤더 이미 제거됨)
//
// -----------------------------------------------------------------------
// Demand 패킷 식별 기준
// -----------------------------------------------------------------------
//
//  1. IP 프로토콜 = UDP (17)
//  2. UDP 목적지 포트 = 48888
//  3. UDP 페이로드의 처음 4바이트 = DEMAND6_PROTOCOL_ID (0x36474E49 = '6GNI')
//
//  [IP Header (20B)][UDP Header (8B)][Demand Payload (16B)]
//                                     ↑ protocol_id(4) app_type(1) reserved(1)
//                                       src_port(2) payload_bytes(4)
//                                       deadline_ms(2) pad(2)
//
// -----------------------------------------------------------------------
// Byte Order (네트워크 바이트 오더) 처리
// -----------------------------------------------------------------------
//
//  네트워크 표준은 Big-Endian (MSB first).
//  x86_64는 Little-Endian (LSB first).
//
//  UE 쪽 코드에서 다중 바이트 필드를 htonl()/htons()로 변환해 전송:
//    pkt.protocol_id   = htonl(0x36474E49)
//    pkt.src_port      = htons(src_port)
//    pkt.payload_bytes = htonl(payload_bytes)
//    pkt.deadline_ms   = htons(deadline_ms)
//
//  gNB(LE)에서 uint32_t로 읽으면 바이트가 뒤집혀 있음.
//  예) protocol_id 0x36474E49가 메모리에는 [0x36][0x47][0x4E][0x49]으로 저장됨
//      LE에서 uint32_t 읽기: 0x494E4736 (역순)
//      ntohl(0x494E4736) = 0x36474E49 (원래값 복원)
//
//  따라서 비교 전에 ntohl()/ntohs() 변환이 필요하다.
//
// -----------------------------------------------------------------------
// Rate Limiting: 5초 주기 (header_parser.c와 동일한 패턴)
// -----------------------------------------------------------------------

#define USE_JBPF_PRINTF_HELPER
#include "jbpf_defs.h"
#include "jbpf_helper.h"
#include "common.h"

/* ============================================================
 * 상수 정의
 * ============================================================ */

/* 5초 = 5,000,000,000 ns */
#define REPORT_INTERVAL_NS  (5ULL * 1000000000ULL)

/*
 * DEMAND6_PROTOCOL_ID: '6','G','N','I' = 0x36474E49
 *
 * UE가 htonl(0x36474E49)로 저장했으므로 메모리에는 Big-Endian으로:
 *   [0x36][0x47][0x4E][0x49]
 * LE x86에서 uint32_t로 읽으면:
 *   value = 0x494E4736
 * ntohl(0x494E4736) == 0x36474E49 = DEMAND6_PROTOCOL_ID ✓
 *
 * 따라서 비교 시: ntohl(pkt->protocol_id) == DEMAND6_PROTOCOL_ID
 */
#define DEMAND6_PROTOCOL_ID  0x36474E49U

/*
 * DEMAND6_UDP_PORT: demand 패킷의 목적지 UDP 포트
 *
 * UDP 헤더의 dest 필드도 네트워크 바이트 오더.
 * ntohs(udp->dest) == DEMAND6_UDP_PORT 로 비교.
 */
#define DEMAND6_UDP_PORT  48888U

/* ============================================================
 * Context 구조체 (nr_pdcp_oai_api.c의 pdcp_uplink_ctx와 동일)
 * ============================================================ */
struct pdcp_uplink_ctx {
    uint64_t data;          /* IP 패킷 시작 포인터 (SDAP 이후) */
    uint64_t data_end;      /* 패킷 끝 포인터 */
    uint64_t meta_data;     /* CPU TSC (rdtsc_oai) */
    uint32_t ue_id;
    uint8_t  pdusession_id;
    uint8_t  rb_id;
    uint8_t  has_sdap_rx;
    uint8_t  qfi;
    uint32_t total_size;
    uint32_t ip_size;
};

/* ============================================================
 * Demand 패킷 구조체 (UE의 demand_pkt.h와 동일한 wire format)
 * ============================================================
 *
 * __attribute__((packed)): 컴파일러 padding 금지.
 * wire format에서 직접 캐스팅해서 읽으므로 필드 사이에 gap이 없어야 한다.
 *
 * 오프셋 표:
 *   [  0] protocol_id    (4B) = 0x36474E49 '6GNI' (network order)
 *   [  4] app_type       (1B) = 0=UNKNOWN, 1=LLM, 2=VLA, 3=VIDEO, 4=BULK
 *   [  5] _reserved      (1B) = 0
 *   [  6] src_port       (2B) = flow 식별자 (network order)
 *   [  8] payload_bytes  (4B) = 예상 전송 크기 (network order)
 *   [ 12] deadline_ms    (2B) = soft deadline (ms), 0=없음 (network order)
 *   [ 14] _pad           (2B) = 정렬 패딩, 항상 0
 *   Total: 16 bytes
 */
struct __attribute__((packed)) demand6_t {
    uint32_t protocol_id;   /* +0   '6GNI' — 프로토콜 식별자   (4B) */
    uint8_t  app_type;      /* +4   app_type_t                  (1B) */
    uint8_t  _reserved;     /* +5   항상 0                      (1B) */
    uint16_t src_port;      /* +6   flow 식별자, network order  (2B) */
    uint32_t payload_bytes; /* +8   예상 전송량, network order  (4B) */
    uint16_t deadline_ms;   /* +12  soft deadline (ms)          (2B) */
    uint16_t _pad;          /* +14  정렬 패딩                   (2B) */
};

/* ============================================================
 * Application으로 전송할 리포트 구조체
 * ============================================================
 *
 * 5초 윈도우 동안 수집된 demand 정보를 요약해서 전송.
 *
 * 레이아웃 (자연 정렬):
 *   [ 0] timestamp_ns       (8B) = 리포트 시각
 *   [ 8] sum_payload_bytes  (8B) = 이 윈도우의 payload_bytes 합계
 *   [16] ue_id              (4B)
 *   [20] intent_count       (4B) = 이 윈도우의 demand 패킷 수
 *   [24] payload_bytes_last (4B) = 마지막 패킷의 payload_bytes (host order)
 *   [28] src_port           (2B) = 마지막 src_port (host order)
 *   [30] deadline_ms        (2B) = 마지막 deadline (host order)
 *   [32] app_type           (1B) = 마지막 app_type
 *   [33] _pad               (7B) → 구조체 크기 40B (8 배수)
 *   Total: 40 bytes
 */
struct IntentReport {
    uint64_t timestamp_ns;
    uint64_t sum_payload_bytes;
    uint32_t ue_id;
    uint32_t intent_count;
    uint32_t payload_bytes_last;
    uint16_t src_port;
    uint16_t deadline_ms;
    uint8_t  app_type;
    uint8_t  _pad[7];
};

/* ============================================================
 * 윈도우 내 누적 상태 (ARRAY 맵에 저장)
 * ============================================================
 *
 * 5초 윈도우 동안 demand 패킷을 계속 받으면서 상태를 누적.
 * 5초가 지나면 이 상태를 IntentReport로 복사해 ringbuf 출력.
 *
 * last_report_ns: jbpf_time_get_ns() 기준 나노초
 * sum_payload_bytes: 윈도우 내 모든 demand의 payload_bytes 합
 *   → UE가 이 5초 동안 보내려는 총 데이터량 추정
 */
struct intent_state {
    uint64_t last_report_ns;
    uint64_t sum_payload_bytes;
    uint32_t ue_id;
    uint32_t intent_count;
    uint32_t payload_bytes_last;
    uint16_t src_port;
    uint16_t deadline_ms;
    uint8_t  app_type;
    uint8_t  _pad[7];
};

/* ============================================================
 * 맵 선언
 * ============================================================ */

/*
 * intent_output: Application으로 IntentReport를 전달하는 ringbuffer
 * 용량 32: 5초에 1개 출력, 충분함
 *
 * out_io_channel name과 반드시 일치해야 함 (YAML 파일에서 지정)
 */
jbpf_ringbuf_map(intent_output, struct IntentReport, 32);

/*
 * intent_state_map: 윈도우 누적 상태 저장 (ARRAY, key=0)
 *
 * ARRAY 타입을 쓰는 이유:
 *   여러 UE가 있어도 이 codelet은 모든 UE의 demand를 단일 상태로 집계.
 *   (per-UE 집계가 필요하면 HASHMAP으로 변경)
 */
struct jbpf_load_map_def SEC("maps") intent_state_map = {
    .type        = JBPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct intent_state),
    .max_entries = 1,
};

/* ============================================================
 * Byte Order 변환 헬퍼
 * ============================================================
 *
 * eBPF 환경에서 표준 라이브러리 ntohl/ntohs를 쓸 수 없으므로 직접 구현.
 *
 * ntohs: 2바이트 swap
 *   상위 8비트를 하위로, 하위 8비트를 상위로
 *   예) 0xBEB8 → 0xB8BE
 *
 * ntohl: 4바이트 swap
 *   [B3][B2][B1][B0] → [B0][B1][B2][B3]
 *   예) 0x494E4736 → 0x36474E49
 */
static inline uint16_t ntohs_impl(uint16_t v) {
    return (v >> 8) | (v << 8);
}

static inline uint32_t ntohl_impl(uint32_t v) {
    return ((v & 0x000000FFU) << 24) |
           ((v & 0x0000FF00U) <<  8) |
           ((v & 0x00FF0000U) >>  8) |
           ((v & 0xFF000000U) >> 24);
}

/* ============================================================
 * Main: Codelet 진입점
 * ============================================================ */
SEC("jbpf_generic")
uint64_t jbpf_main(void* state)
{
    struct pdcp_uplink_ctx* ctx = (struct pdcp_uplink_ctx*)state;
    if (!ctx)
        return 1;

    /* ── Step 1: 상태 맵 lookup ─────────────────────────────── */

    uint32_t key = 0;
    struct intent_state *st = jbpf_map_lookup_elem(&intent_state_map, &key);
    if (!st)
        return 1;

    /* ── Step 2: IP 헤더 파싱 ───────────────────────────────── */

    /*
     * ctx->data: PDCP 복호화 후 IP 패킷 시작 주소.
     * HOOK_ASSIGN에서 sdap_offset이 이미 적용됨.
     *
     * 포인터 캐스팅: uint64_t → void* → struct ip_hdrP*
     * eBPF verifier는 포인터 범위를 추적하므로 반드시 경계 검사 필요.
     */
    struct ip_hdrP* ip = (struct ip_hdrP*)(void*)ctx->data;
    void* data_end     = (void*)ctx->data_end;

    if ((void*)(ip + 1) > data_end)
        return 1;

    if (ip->version != 4)
        return 1;  /* IPv4만 처리 */

    /* demand는 항상 UDP. 다른 프로토콜이면 조기 반환. */
    if (ip->protocol != IPPROTO_UDP)
        return 0;

    /* ── Step 3: UDP 헤더 파싱 및 포트 필터링 ───────────────── */

    /*
     * IHL(IP Header Length): 4바이트 워드 단위
     *   ihl=5 → 20바이트 (표준 옵션 없음)
     *
     * l4_start: IP 헤더 직후, UDP 헤더 시작
     */
    uint8_t ihl    = ip->ihl * 4;
    void* l4_start = (void*)ip + ihl;

    struct udp_hdr* udp = (struct udp_hdr*)l4_start;
    if ((void*)(udp + 1) > data_end)
        return 1;

    /*
     * UDP 목적지 포트 필터링
     *
     * udp->dest는 네트워크 바이트 오더(Big-Endian).
     * ntohs_impl()로 Host 오더로 변환 후 48888과 비교.
     */
    if (ntohs_impl(udp->dest) != DEMAND6_UDP_PORT)
        return 0;  /* demand 포트가 아님: 일반 데이터 패킷 */

    /* ── Step 4: UDP 페이로드에서 demand6_t 파싱 ─────────────── */

    /*
     * UDP 헤더 구조 (8바이트 고정):
     *   [src_port 2B][dst_port 2B][length 2B][checksum 2B]
     *
     * UDP 페이로드 시작 = UDP 헤더 끝
     */
    void* udp_payload = (void*)udp + sizeof(struct udp_hdr);  /* 8바이트 이동 */

    /*
     * demand6_t는 16바이트.
     * 경계 검사: payload + 16 <= data_end 이어야 접근 가능.
     */
    if (udp_payload + sizeof(struct demand6_t) > data_end)
        return 1;

    struct demand6_t* pkt = (struct demand6_t*)udp_payload;

    /*
     * Protocol ID 검증
     *
     * 메모리 상태:
     *   UE가 htonl(0x36474E49) 저장 → 메모리: [0x36][0x47][0x4E][0x49]
     *   gNB LE에서 uint32_t 읽기: 0x494E4736
     *   ntohl_impl(0x494E4736) = 0x36474E49 = DEMAND6_PROTOCOL_ID ✓
     *
     * 이 검사가 없으면 다른 UDP 48888 트래픽이 demand로 잘못 파싱될 수 있음.
     */
    if (ntohl_impl(pkt->protocol_id) != DEMAND6_PROTOCOL_ID)
        return 0;  /* protocol_id 불일치: demand 패킷이 아님 */

    /* ── Step 5: 상태 누적 ──────────────────────────────────── */

    /*
     * 파싱된 demand 필드들을 상태에 누적.
     * 모든 네트워크 바이트 오더 필드는 ntohl/ntohs 변환 후 저장.
     */
    st->intent_count++;
    st->ue_id               = ctx->ue_id;
    st->app_type            = pkt->app_type;
    st->src_port            = ntohs_impl(pkt->src_port);
    st->payload_bytes_last  = ntohl_impl(pkt->payload_bytes);
    st->deadline_ms         = ntohs_impl(pkt->deadline_ms);
    st->sum_payload_bytes  += st->payload_bytes_last;  /* 윈도우 합계 누적 */

    /* ── Step 6: Rate Limiting (5초 경과 여부 확인) ──────────── */

    uint64_t now = jbpf_time_get_ns();
    if (now - st->last_report_ns < REPORT_INTERVAL_NS)
        return 0;  /* 아직 5초 안 됨 */

    /* ── Step 7: IntentReport 빌드 및 ringbuf 출력 ───────────── */

    struct IntentReport report = {
        .timestamp_ns       = now,
        .sum_payload_bytes  = st->sum_payload_bytes,
        .ue_id              = st->ue_id,
        .intent_count       = st->intent_count,
        .payload_bytes_last = st->payload_bytes_last,
        .src_port           = st->src_port,
        .deadline_ms        = st->deadline_ms,
        .app_type           = st->app_type,
    };

    jbpf_ringbuf_output(&intent_output, &report, sizeof(report));

    /* 상태 리셋: 다음 5초 윈도우 시작 */
    st->last_report_ns     = now;
    st->intent_count       = 0;
    st->sum_payload_bytes  = 0;

    return 0;
}
