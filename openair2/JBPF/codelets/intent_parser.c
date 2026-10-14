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

/*
 * qos_weight_msg.h 는 codelet 과 host (nr-softmodem.c) 가 *공유*하는
 * wire format 정의. include 경로는 codelet build 시 자동으로
 * ${CMAKE_SOURCE_DIR}/openair2/JBPF 가 포함되므로 파일명 그대로 가능.
 */
#include "qos_weight_msg.h"

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

/*
 * app_type 값 — UE 의 demand_pkt.h (app_type_t) 와 동일해야 한다.
 *
 * 숫자를 switch 문에 직접 박아두지 않고 이름을 주는 이유: UE 쪽 enum 과
 * 짝이 맞는지를 읽는 사람이 바로 확인할 수 있어야 한다. wire 값이라
 * 한쪽만 바뀌면 조용히 엉뚱한 정책이 걸린다.
 */
#define APP_TYPE_UNKNOWN  0U
#define APP_TYPE_LLM      1U
#define APP_TYPE_VLA      2U
#define APP_TYPE_VIDEO    3U
#define APP_TYPE_BULK     4U
#define APP_TYPE_RESET    255U   /* 전체 정책 해제 (스펙 외 — 데모 제어용) */

/* Hook context 정의는 ../pdcp_hook_ctx.h 에 있다 (gNB 쪽과 공유).
 * 재정의하면 양쪽 레이아웃이 어긋나며 silent corruption 이 난다. */
#include "pdcp_hook_ctx.h"

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
 * UE 별 누적 상태 (HASHMAP 에 ue_id 를 키로 저장)
 * ============================================================
 *
 * 5초 윈도우 동안 demand 패킷을 받으면서 UE 별로 상태를 누적하고,
 * 5초가 지나면 IntentReport 로 복사해 ringbuf 출력한다.
 *
 * last_report_ns   : jbpf_time_get_ns() 기준 나노초
 * sum_payload_bytes: 윈도우 내 payload_bytes 합 — 이 UE 가 5초간
 *                    보내려는 총 데이터량 추정
 * last_weight_q16  : *직전에 host 로 push 한* 가중치.
 *                    0 = 아직 push 안 함 (유효 가중치는 최소
 *                    QOS_WEIGHT_Q16(0.25) = 0x4000 이므로 0 과 겹치지
 *                    않는다). 이 값과 비교해 *변화가 있을 때만* push
 *                    하므로, demand6 가 초당 수천 개 들어와도 host 쪽
 *                    스케줄러 락 진입은 정책이 바뀌는 순간에만 발생한다.
 */
struct intent_state {
    uint64_t last_report_ns;     /*  0 */
    uint64_t sum_payload_bytes;  /*  8 */
    uint32_t ue_id;              /* 16 */
    uint32_t intent_count;       /* 20 */
    uint32_t payload_bytes_last; /* 24 */
    uint32_t last_weight_q16;    /* 28 */
    uint16_t src_port;           /* 32 */
    uint16_t deadline_ms;        /* 34 */
    uint8_t  app_type;           /* 36 */
    uint8_t  _pad[3];            /* 37 → 총 40 B (8 배수) */
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
 * weight_output: 정책(QoS weight) 즉시 적용용 ringbuffer
 *
 * intent_output 과의 차이:
 *   intent_output  : 5초 윈도우 *통계* — 디버깅/관찰용, 느림
 *   weight_output  : demand6 한 개 받을 때마다 *즉시* push — 정책 채널
 *
 * 용량 64:
 *   - heartbeat 250ms 주기로 demand6 가 들어오므로 초당 ~4 push
 *   - host 가 잠깐 늦더라도 16초치 backlog 흡수 가능
 *
 * 스트림 ID 매핑:
 *   YAML 의 out_io_channel.stream_id 가
 *     CC112233445566778899AABBCCDDEE01
 *   로 잡혀있어야 한다. nr-softmodem.c 의 is_weight_stream() 이
 *   id[0]==0xCC && id[15]==0x01 로 식별.
 */
jbpf_ringbuf_map(weight_output, struct WeightUpdate, 64);

/*
 * intent_state_map: UE 별 누적 상태 (HASHMAP, key = ctx->ue_id)
 *
 * HASHMAP 을 쓰는 이유:
 *   PF 가중치는 UE 간 *순서*만 바꾸므로 데모 자체가 경합하는 UE 2대
 *   이상을 전제한다. 단일 ARRAY 슬롯에 집계하면 그 순간 ue_id /
 *   sum_payload_bytes 가 UE 끼리 서로를 덮어써서 IntentReport 가
 *   거짓값을 보고한다.
 *
 * max_entries = MAX_MOBILES_PER_GNB (= 16, OAI 의 gNB 당 UE 상한) 과
 * 맞춰둔다. 키는 CU-UE-ID 이고 재사용되지 않으므로 UE 가 반복 접속하면
 * 엔트리가 쌓이는데, 상한에 닿으면 update 가 실패하고 해당 UE 의
 * 리포트만 빠진다 (정책 경로는 영향 없음). 장시간 실험에서 문제가 되면
 * APP_TYPE_RESET 으로 맵을 비울 수 있다.
 */
#define INTENT_STATE_MAX_UE  16

struct jbpf_load_map_def SEC("maps") intent_state_map = {
    .type        = JBPF_MAP_TYPE_HASHMAP,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct intent_state),
    .max_entries = INTENT_STATE_MAX_UE,
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

    /*
     * 상태 맵 lookup 은 Step 5 로 미뤘다.
     *
     * 이 hook 은 *모든* UL 패킷마다 호출되는데 그중 demand6 는 극소수다.
     * 맵 접근을 패킷 식별 뒤로 미루면 일반 트래픽은 헤더 몇 바이트만
     * 보고 빠져나간다 (HASHMAP 은 해시 계산이 붙으므로 더 중요해졌다).
     */

    /* ── Step 1: IP 헤더 파싱 ───────────────────────────────── */

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

    /* ── Step 4.5: 전체 리셋 요청 ───────────────────────────────
     *
     * app_type == APP_TYPE_RESET 은 "모든 UE 의 정책을 해제"다.
     * 데모 중 여러 UE 를 토글한 뒤 기준 상태로 돌아가기 위한 경로.
     *
     * 상태 맵 lookup 보다 *먼저* 처리하는 이유:
     *   jbpf_map_clear() 로 맵을 비우면 UE 별 last_weight_q16 캐시도
     *   함께 사라진다. 그래서 리셋 직후 각 UE 의 다음 intent 가
     *   "변화 없음"으로 억제되지 않고 정상적으로 다시 push 된다.
     *   (맵을 비우기 전에 st 를 잡아뒀다면 dangling 이 된다.)
     */
    if (pkt->app_type == APP_TYPE_RESET) {
        struct WeightUpdate wu = {
            .rnti        = 0,                          /* 무시됨 */
            .duration_ms = QOS_WEIGHT_TTL_CLEAR_ALL,
            .weight_q16  = QOS_WEIGHT_Q16(1),          /* 무시됨 */
        };
        jbpf_ringbuf_output(&weight_output, &wu, sizeof(wu));
        jbpf_map_clear(&intent_state_map);
        return 0;
    }

    /* ── Step 5: UE 별 상태 lookup-or-create ────────────────── */

    /*
     * HASHMAP 은 ARRAY 와 달리 키가 없으면 NULL 을 돌려주므로,
     * 처음 보는 UE 는 빈 엔트리를 만들고 다시 lookup 해야 한다.
     * (update_elem 은 포인터를 돌려주지 않는다.)
     */
    uint32_t key = ctx->ue_id;
    struct intent_state *st = jbpf_map_lookup_elem(&intent_state_map, &key);
    if (!st) {
        struct intent_state fresh = {0};
        fresh.ue_id          = ctx->ue_id;
        fresh.last_report_ns = jbpf_time_get_ns();
        if (jbpf_map_update_elem(&intent_state_map, &key, &fresh, 0) != 0)
            return 1;   /* 맵 상한 도달 — 이 UE 의 리포트는 포기 */
        st = jbpf_map_lookup_elem(&intent_state_map, &key);
        if (!st)
            return 1;
    }

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

    /* ── Step 5.5: QoS weight 정책 발사 ─────────────────────────
     *
     * 이게 *programmable interface* 의 핵심 자리.
     *
     * 데이터 파싱은 위에서 끝났고, 여기서 "이 UE에게 어떤 정책을
     * 적용할 것인가" 를 결정해 host 로 push 한다.
     *
     * ── 디자인 모델: one-shot 영구 적용 ─────────────────────────
     * 원래는 매 demand6 가 도착할 때마다 TTL 을 갱신하는 heartbeat
     * 모델이었으나, 다음 두 가지 문제가 있었다:
     *   1. heartbeat 간격이 TCP send() 빈도 (수백 ms) 와 묶이면서
     *      TTL=20ms 가 너무 짧아 boost 가 *깜박이는* 현상
     *   2. 사용자의 본래 의도는 "intent 가 한 번 표명되면 codelet
     *      유지 동안 영구" — packet-by-packet adaptation 이 아니었음
     *
     * 새 모델:
     *   duration_ms = 0 → host 측에서 "영구 (clear_all / 재시작까지
     *   유지)" 로 해석. heartbeat 빈도와 정책 유효 기간이 *완전히
     *   분리*. demand6 가 한 번이라도 도착하면 그 정책이 박힌다.
     *   해제는 app_type = BULK/UNKNOWN (1.0x) 또는 RESET 으로 한다.
     *
     * ── 변화가 있을 때만 push 한다 ─────────────────────────────
     * host 콜백은 WeightUpdate 하나당 NR_SCHED_LOCK 을 잡고
     * connected_ue_list 를 순회해 CU-UE-ID → MAC RNTI 를 역조회한다.
     * LD_PRELOAD shim 은 send()/write() 마다 demand6 를 쏘기 때문에,
     * 매번 push 하면 non-RT 스레드가 스케줄러 락을 초당 수천 번
     * 건드리게 되고 그대로 슬롯 지터가 된다.
     *
     * 정책은 app_type 하나로만 결정되므로 직전 push 값과 비교하면
     * 충분하다. 결과적으로 push 는 "intent 가 실제로 바뀐 순간"에만
     * 일어난다 — 정상 상태에서는 0 msg/s.
     */
    {
        uint32_t weight_q16;
        switch (pkt->app_type) {
            case APP_TYPE_LLM:    weight_q16 = QOS_WEIGHT_Q16(8); break;
            case APP_TYPE_VLA:    weight_q16 = QOS_WEIGHT_Q16(4); break;
            case APP_TYPE_VIDEO:  weight_q16 = QOS_WEIGHT_Q16(2); break;
            default:              weight_q16 = QOS_WEIGHT_Q16(1); break;
        }

        if (weight_q16 != st->last_weight_q16) {
            struct WeightUpdate wu = {
                .rnti        = (uint16_t)ctx->ue_id,  /* host 가 MAC RNTI 로 변환 */
                .duration_ms = 0,                     /* 영구 */
                .weight_q16  = weight_q16,
            };

            /*
             * jbpf_ringbuf_output(map, data, size):
             *   ringbuf 한 slot 에 data 를 복사. host consumer 가 가져간다.
             *
             * drop 되면 last_weight_q16 을 갱신하지 않는다 → 다음 demand6
             * 가 같은 정책을 다시 시도한다. 이 재시도 경로가 있어야
             * ringbuf full 상황에서 정책이 영구히 유실되지 않는다.
             */
            if (jbpf_ringbuf_output(&weight_output, &wu, sizeof(wu)) == 0)
                st->last_weight_q16 = weight_q16;
        }
    }

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
