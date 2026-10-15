// Copyright (c) 2025 OpenAirInterface
//
// JBPF Codelet: SR 패킷 덤프 (Scheduling Request Raw Capture)
//
// 목적:
//   유효한 SR(Scheduling Request) 이벤트를 필터링 없이 100% 캡처하여
//   nr-softmodem 터미널에 Wireshark 스타일의 ASCII 패킷 덤프로 표시한다.
//
//   기존 mac_sr_monitor.c는 통계(10번에 1번 출력)에 집중하지만,
//   이 codelet은 구조체 전체를 raw 형태로 전달하여 패킷 수준의 관찰을 가능하게 한다.
//
// UL 시그널링 흐름에서 SR의 위치:
//   1. UE에 UL 데이터 발생
//   2. UE → gNB: SR (PUCCH Fmt0/1, 1비트 시그널) ← 이 hook 지점
//   3. gNB → UE: UL Grant (DCI Fmt0_0/0_1)
//   4. UE → gNB: PUSCH (BSR MAC CE + 데이터)
//   5. gNB: BSR 파싱 → 다음 슬롯 PRB 할당 결정
//
// Hook: mac_sr_detect
// 위치: gNB_scheduler_uci.c - PUCCH Format 0/1 UCI 처리 직후
//
// Stream ID: AABB001122334455667788990000AA05
//   id[0] = 0xAA (MAC 스케줄러 그룹)
//   id[15] = 0x05 (SR 패킷 덤프)
//
// 출력 구조체 sr_packet_frame 레이아웃 (24 bytes, 8-byte 정렬):
//   Offset  0: ts_cycles     (8B) - CPU rdtsc 타임스탬프
//   Offset  8: rnti          (2B) - UE 식별자
//   Offset 10: frame         (2B) - 10ms 프레임 번호
//   Offset 12: slot          (1B) - 슬롯 번호
//   Offset 13: sr_detected   (1B) - SR 유효 여부 (항상 1)
//   Offset 14: ul_cqi        (1B) - PUCCH 수신 품질
//   Offset 15: _pad[5]       (5B) - 정렬 패딩
//   Offset 20: seq_num       (4B) - 전역 이벤트 시퀀스 번호
//   Total: 24 bytes

#include "jbpf_defs.h"
#include "jbpf_helper.h"

/* Hook context 정의는 ../mac_scheduler_hooks.h 에 있다 (gNB 쪽과 공유).
 * 재정의하면 양쪽 레이아웃이 어긋나며 silent corruption 이 난다. */
#include "mac_scheduler_hooks.h"

/* ============================================================
 * 출력 패킷 프레임 구조체 (nr-softmodem.c의 sr_packet_frame과 동일)
 *
 * 크기 계산:
 *   uint64_t(8) + uint16_t(2) + uint16_t(2) + uint8_t(1)*3 + uint8_t[5](5) + uint32_t(4)
 *   = 8 + 2 + 2 + 3 + 5 + 4 = 24 bytes
 *   sizeof 확인: 최대 정렬 단위 = 8(uint64_t), 24 % 8 = 0 ✓ 패딩 불필요
 *
 * 중요: nr-softmodem.c의 handle_mac_sr_packet_dump()와 구조 일치 필수
 * ============================================================ */
struct sr_packet_frame {
    /* === 타임스탬프 === */
    uint64_t ts_cycles;   /* CPU rdtsc (meta_data에서 복사) */

    /* === 5G NR 시간 좌표 + UE 식별 === */
    uint16_t rnti;        /* UE Radio Network Temporary ID */
    uint16_t frame;       /* 10ms 프레임 (0~1023, 10.24초 주기) */
    uint8_t  slot;        /* 슬롯 (SCS=30kHz → 20슬롯/프레임) */

    /* === SR 페이로드 === */
    uint8_t  sr_detected; /* SR 감지 여부 (이 codelet에선 항상 1) */
    uint8_t  ul_cqi;      /* PUCCH UL CQI: 148=SNR 10dB */

    /* === 정렬 패딩 (명시적으로 5바이트 채움) === */
    uint8_t  _pad[5];     /* 구조체 크기를 24바이트(8의 배수)로 맞춤 */

    /* === 시퀀스 번호 === */
    uint32_t seq_num;     /* gNB 기동 이후 전역 SR 이벤트 번호 (0부터) */
};

/* ============================================================
 * JBPF 맵 선언
 *
 * [1] sr_dump_output: Ringbuffer (출력용)
 *   - Codelet → nr-softmodem 방향
 *   - 64개 슬롯 × 24 bytes = 1536 bytes
 *   - 슬롯이 가득 차면 가장 오래된 데이터 덮어씀
 *
 * [2] sr_dump_seq_counter: Array (내부 상태)
 *   - 전역 시퀀스 번호 유지
 *   - Array 맵 index 0에 uint32_t 저장
 *   - 이 카운터는 롤오버 허용 (uint32_t 최대 43억 이벤트)
 * ============================================================ */
jbpf_ringbuf_map(sr_dump_output, struct sr_packet_frame, 64);

struct jbpf_load_map_def SEC("maps") sr_dump_seq_counter = {
    .type        = JBPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(uint32_t),
    .max_entries = 1,
};

/* ============================================================
 * jbpf_main: 코드렛 진입점
 *
 * 호출 시점: gNB가 UE의 PUCCH를 통한 SR을 유효하다고 판단한 직후
 *
 * eBPF 프로그래밍 제약사항:
 *   - 동적 메모리 할당 불가 (malloc, free 없음)
 *   - 포인터 역참조 전 반드시 NULL 확인
 *   - 스택 프레임 크기 제한 (512바이트, BPF 표준)
 *   - 루프는 제한적으로만 허용 (verifier 통과 조건)
 *   - jbpf_map_lookup_elem 반환값은 항상 NULL 검사 필수
 *     → NULL이면 맵이 초기화 전이거나 키가 없음을 의미
 *
 * 반환값: 0 = 성공, 1 = 오류 (ringbuf 전송 실패 포함)
 * ============================================================ */
SEC("jbpf_generic")
uint64_t
jbpf_main(void *state)
{
    /*
     * state를 mac_sr_detect_ctx로 캐스팅
     *
     * JBPF는 user-space eBPF이므로 커널 eBPF와 달리
     * 포인터 자체가 유효한 user-space 주소다.
     * state는 gNB 스케줄러가 스택에 할당한 구조체를 가리킨다.
     */
    struct mac_sr_detect_ctx *ctx = (struct mac_sr_detect_ctx *)state;

    /*
     * 시퀀스 번호 읽기 및 증가
     *
     * JBPF_MAP_TYPE_ARRAY에서 key=0인 원소를 가져온다.
     * 반환값은 맵 내부 슬롯에 대한 포인터이므로,
     * 값을 변경하면 맵에 직접 반영된다 (memcpy 불필요).
     *
     * NULL 반환 이유: JBPF_MAP_TYPE_ARRAY는 max_entries 범위 초과 시 NULL 반환
     * key=0이고 max_entries=1이므로 이론상 NULL이 될 수 없지만,
     * eBPF verifier 요구사항으로 반드시 확인해야 한다.
     */
    uint32_t key = 0;
    uint32_t *seq_ptr = jbpf_map_lookup_elem(&sr_dump_seq_counter, &key);
    if (!seq_ptr)
        return 1;

    uint32_t current_seq = *seq_ptr;
    *seq_ptr = current_seq + 1;  /* 다음 호출을 위해 증가 */

    /*
     * 출력 프레임 구성
     *
     * 스택에 구조체를 선언하고 모든 필드를 명시적으로 초기화한다.
     * eBPF에서는 uninitialzed 메모리 사용 시 verifier 오류가 발생한다.
     *
     * Designated initializer 문법 사용:
     *   .field = value 형식으로 필드를 명확하게 초기화
     *   나머지 필드는 0으로 자동 초기화됨
     */
    struct sr_packet_frame pkt = {
        .ts_cycles   = ctx->meta_data,   /* CPU rdtsc 복사 */
        .rnti        = ctx->rnti,
        .frame       = ctx->frame,
        .slot        = ctx->slot,
        .sr_detected = ctx->sr_detected,
        .ul_cqi      = ctx->ul_cqi,
        ._pad        = {0, 0, 0, 0, 0},  /* 명시적 패딩 초기화 */
        .seq_num     = current_seq,
    };

    /*
     * Ringbuffer로 출력
     *
     * jbpf_ringbuf_output은 내부적으로:
     *   1. ringbuf에서 sizeof(sr_packet_frame)만큼 슬롯 예약
     *   2. &pkt 내용을 예약된 슬롯으로 memcpy
     *   3. 슬롯을 커밋하여 소비자(nr-softmodem.c 콜백)에게 알림
     *
     * 반환값: 0=성공, -1=ringbuf 가득 참 (드롭)
     */
    jbpf_ringbuf_output(&sr_dump_output, &pkt, sizeof(pkt));

    return 0;
}
