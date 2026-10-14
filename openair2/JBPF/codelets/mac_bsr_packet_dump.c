// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: BSR 패킷 덤프 (Buffer Status Report Raw Capture)
//
// 목적:
//   UE로부터 수신된 모든 BSR(Buffer Status Report) MAC CE를 필터링 없이
//   캡처하여 nr-softmodem 터미널에 ASCII 패킷 덤프로 표시한다.
//
//   BSR은 UL 스케줄링의 핵심 시그널링이다:
//   ┌─────────────────────────────────────────────────────────────────┐
//   │  BSR 기반 UL 스케줄링 루프                                     │
//   │                                                                 │
//   │  UE: UL 데이터 발생                                            │
//   │    ↓ (SR로 UL grant 요청)                                      │
//   │  gNB: UL grant 발행 (DCI Fmt0)                                 │
//   │    ↓ (PUSCH 전송)                                              │
//   │  UE → gNB: PUSCH (BSR MAC CE + 실제 데이터)                    │
//   │    ↓ (hook 지점: 이 codelet 실행)                              │
//   │  gNB: estimated_bytes 기반으로 다음 슬롯 PRB 할당              │
//   │    ↓                                                           │
//   │  UE: 추가 데이터 전송 기회 획득                                 │
//   └─────────────────────────────────────────────────────────────────┘
//
// BSR 종류:
//   Short BSR (bsr_type=0):
//     - 1개 LCG에 대한 버퍼 크기 보고
//     - 5비트 인덱스 → 테이블 조회로 바이트 변환
//     - lcg_id: 보고한 LCG 번호 (0~7)
//
//   Long BSR (bsr_type=1):
//     - 최대 8개 LCG 모두 보고
//     - 8비트 인덱스 × LCG 수
//     - lcg_id: 0xFF (여러 LCG 포함을 의미)
//
// Hook: mac_bsr_event
// 위치: gNB_scheduler_ulsch.c - Short/Long BSR MAC CE 처리 직후
//
// Stream ID: AABB001122334455667788990000AA06
//   id[0] = 0xAA (MAC 스케줄러 그룹)
//   id[15] = 0x06 (BSR 패킷 덤프)
//
// 출력 구조체 bsr_packet_frame 레이아웃 (24 bytes, 8-byte 정렬):
//   Offset  0: ts_cycles        (8B) - CPU rdtsc 타임스탬프
//   Offset  8: rnti             (2B) - UE 식별자
//   Offset 10: frame            (2B) - 10ms 프레임 번호
//   Offset 12: slot             (1B) - 슬롯 번호
//   Offset 13: bsr_type         (1B) - 0=Short, 1=Long
//   Offset 14: lcg_id           (1B) - 논리채널그룹 ID (Long BSR는 0xFF)
//   Offset 15: _pad             (1B) - 정렬 패딩
//   Offset 16: estimated_bytes  (4B) - 추정 UL 버퍼 크기
//   Offset 20: seq_num          (4B) - 전역 이벤트 시퀀스 번호
//   Total: 24 bytes

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/* Hook context 정의는 ../mac_scheduler_hooks.h 에 있다 (gNB 쪽과 공유).
 * 재정의하면 양쪽 레이아웃이 어긋나며 silent corruption 이 난다. */
#include "mac_scheduler_hooks.h"

/* ============================================================
 * 출력 패킷 프레임 구조체 (nr-softmodem.c의 bsr_packet_frame과 동일)
 *
 * 크기 계산 (컴파일러 패딩 없이 자연 정렬됨):
 *   uint64_t(8) + uint16_t(2) + uint16_t(2) + uint8_t(1)*4 + uint32_t(4) + uint32_t(4)
 *   = 8 + 2 + 2 + 4 + 4 + 4 = 24 bytes
 *
 * 정렬 검증:
 *   - offset 0: uint64_t → 8 정렬 ✓
 *   - offset 8: uint16_t → 2 정렬 ✓
 *   - offset 10: uint16_t → 2 정렬 ✓
 *   - offset 12~15: uint8_t × 4 → 1 정렬 ✓
 *   - offset 16: uint32_t → 4 정렬 ✓
 *   - offset 20: uint32_t → 4 정렬 ✓
 *   - sizeof = 24, 24 % 8 = 0 → trailing padding 없음 ✓
 * ============================================================ */
struct bsr_packet_frame {
    /* === 타임스탬프 === */
    uint64_t ts_cycles;        /* CPU rdtsc (meta_data에서 복사) */

    /* === 5G NR 시간 좌표 + UE 식별 === */
    uint16_t rnti;             /* UE Radio Network Temporary ID */
    uint16_t frame;            /* 10ms 프레임 (0~1023) */
    uint8_t  slot;             /* 슬롯 번호 (SCS=30kHz → 0~19) */

    /* === BSR 페이로드 === */
    uint8_t  bsr_type;         /* 0=Short BSR, 1=Long BSR */

    /*
     * LCG ID (Logical Channel Group)
     *
     * DRB들을 논리적으로 묶은 그룹 번호:
     *   LCG 0: SRB (제어 신호, RRC 메시지)
     *   LCG 1~7: DRB (데이터, 보통 LCG1=인터넷, LCG2=VoLTE 등)
     *
     * Short BSR: 단 1개 LCG를 보고 → lcg_id = 0~7
     * Long BSR: 모든 LCG를 보고 → lcg_id = 0xFF (다중 LCG 표시)
     */
    uint8_t  lcg_id;

    uint8_t  _pad;             /* 정렬 패딩 (1바이트) */

    /*
     * OAI의 estimated_bytes 계산 방식:
     *   BSR 인덱스(5bit 또는 8bit)는 로그 스케일 범위를 나타냄.
     *   OAI는 해당 범위의 상한값을 estimated_bytes로 사용 (보수적 추정).
     *   예) BSR index 15 → 800 bytes 이하 → estimated_bytes = 800
     */
    uint32_t estimated_bytes;  /* 추정 UL 버퍼 크기 (바이트, 상한값) */

    /* === 시퀀스 번호 === */
    uint32_t seq_num;          /* gNB 기동 이후 전역 BSR 이벤트 번호 (0부터) */
};

/* ============================================================
 * JBPF 맵 선언
 *
 * [1] bsr_dump_output: Ringbuffer (출력용)
 *   - 64개 슬롯 × 24 bytes = 1536 bytes
 *   - BSR은 SR보다 훨씬 자주 발생할 수 있음 (UL 데이터 흐름 중 매 PUSCH마다)
 *   - 슬롯이 가득 차면 oldest 드롭 → 주요 이벤트는 유지됨
 *
 * [2] bsr_dump_seq_counter: Array (내부 상태)
 *   - 전역 BSR 시퀀스 번호 유지
 *   - Array 맵: index 0 = uint32_t 카운터
 * ============================================================ */
jbpf_ringbuf_map(bsr_dump_output, struct bsr_packet_frame, 64);

struct jbpf_load_map_def SEC("maps") bsr_dump_seq_counter = {
    .type        = JBPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(uint32_t),
    .max_entries = 1,
};

/* ============================================================
 * jbpf_main: 코드렛 진입점
 *
 * 학습 포인트:
 *
 * 1. eBPF ARRAY 맵 vs HASHMAP:
 *    - ARRAY: key는 정수 인덱스, 항상 메모리 할당됨 → 빠름
 *    - HASHMAP: 임의 key → 동적 관리 → key가 없으면 NULL 반환
 *    이 codelet은 단순 카운터이므로 ARRAY가 적합.
 *
 * 2. designated initializer:
 *    struct foo f = { .field1 = v1, .field2 = v2 };
 *    나머지 필드는 0으로 초기화. eBPF verifier는 uninitialzed 필드를 거부.
 *
 * 3. jbpf_ringbuf_output 반환값:
 *    0 = 성공 (ringbuf에 공간 있음, memcpy 완료)
 *   -1 = 실패 (ringbuf 가득 참, 이 이벤트는 드롭됨)
 *    반환값을 확인하지 않아도 segfault는 발생하지 않음.
 * ============================================================ */
SEC("jbpf_generic")
uint64_t
jbpf_main(void *state)
{
    struct mac_bsr_event_ctx *ctx = (struct mac_bsr_event_ctx *)state;

    /*
     * 시퀀스 번호 읽기
     *
     * jbpf_map_lookup_elem(&bsr_dump_seq_counter, &key):
     *   - 맵에서 key=0에 해당하는 uint32_t 슬롯 포인터 반환
     *   - ARRAY 맵이므로 key < max_entries(=1)이면 항상 non-NULL
     *   - 그러나 eBPF verifier 규칙상 NULL 체크 필수
     */
    uint32_t key = 0;
    uint32_t *seq_ptr = jbpf_map_lookup_elem(&bsr_dump_seq_counter, &key);
    if (!seq_ptr)
        return 1;

    uint32_t current_seq = *seq_ptr;
    *seq_ptr = current_seq + 1;

    /*
     * 출력 프레임 구성
     *
     * BSR 타입에 따른 해석:
     *   bsr_type == 0 (Short BSR):
     *     lcg_id = 0~7: 이 LCG의 버퍼에 데이터가 있음
     *     estimated_bytes: 해당 LCG의 버퍼 크기 추정값
     *
     *   bsr_type == 1 (Long BSR):
     *     lcg_id = 0xFF: 여러 LCG가 포함됨
     *     estimated_bytes: 전체 LCG 합산 버퍼 크기 추정값
     */
    struct bsr_packet_frame pkt = {
        .ts_cycles       = ctx->meta_data,
        .rnti            = ctx->rnti,
        .frame           = ctx->frame,
        .slot            = ctx->slot,
        .bsr_type        = ctx->bsr_type,
        .lcg_id          = ctx->lcg_id,
        ._pad            = 0,
        .estimated_bytes = ctx->estimated_bytes,
        .seq_num         = current_seq,
    };

    jbpf_ringbuf_output(&bsr_dump_output, &pkt, sizeof(pkt));

    return 0;
}
