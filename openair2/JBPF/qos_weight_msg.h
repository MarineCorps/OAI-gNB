/*
 * qos_weight_msg.h
 *
 * ============================================================
 * Codelet ↔ Host 가 공유하는 wire format 헤더
 * ============================================================
 *
 * 이 파일은 *반드시* eBPF codelet (intent_parser.c 등) 과
 * 호스트 코드 (nr-softmodem.c, qos_weight.c) 가 **동일한** 정의를
 * 보도록 하기 위한 단일 source of truth 이다.
 *
 * 양쪽이 구조체 정의를 따로 갖고 있으면 한쪽만 수정했을 때
 * silent corruption 이 발생한다 (필드 오프셋이 어긋나면서
 * weight 가 ttl 자리로 들어가는 등의 버그).
 *
 * ------------------------------------------------------------
 * 데이터 흐름
 * ------------------------------------------------------------
 *
 *   UE app
 *      │  sendto(demand_sock, demand6, 16B, ...)
 *      ▼
 *   gNB PDCP → hook_pdcp_uplink()
 *      │
 *      ▼
 *   intent_parser.c (eBPF codelet)
 *      │  demand6 파싱 → 정책 결정 (app_type → weight)
 *      │  jbpf_ringbuf_output(weight_output, &WeightUpdate, 8B)
 *      ▼
 *   nr-softmodem.c::jbpf_io_output_handler()
 *      │  is_weight_stream() → 디스패치
 *      │  qos_weight_apply(rnti, weight_q16/65536, ttl_ms)
 *      ▼
 *   qos_weight.c 의 host-side 테이블
 *      ▲
 *      │  매 슬롯 lookup
 *   gNB_scheduler_ulsch.c::pf_ul()
 *
 * ------------------------------------------------------------
 * Wire format (총 8 바이트, packed)
 * ------------------------------------------------------------
 *
 *   offset  field         size  설명
 *   ------  ------------  ----  ---------------------------------
 *      0    rnti           2B   UE 식별자 (host byte order로 통일)
 *      2    duration_ms    2B   TTL (밀리초). 이후 자동 만료.
 *      4    weight_q16     4B   Q16.16 fixed point. 1.0 = (1<<16)
 *
 * ------------------------------------------------------------
 * Byte order
 * ------------------------------------------------------------
 *
 * Codelet 과 host 는 *같은 머신* 의 *같은 프로세스* 안에서 실행됨
 * (JBPF 가 in-process 런타임이므로). 따라서 네트워크 표준
 * Big-Endian 변환이 필요 없고, **양쪽 다 host byte order**
 * (= x86_64 = Little-Endian) 그대로 사용한다.
 *
 * ⚠️ 주의: demand6_t 와 헷갈리지 말 것 — demand6_t 는
 *    *UE 호스트에서 gNB 호스트로* 무선 구간을 거쳐 가는 wire 라
 *    네트워크 byte order (htonl/htons) 가 적용된다. 반면
 *    WeightUpdate 는 같은 프로세스 안의 메시지라 변환 불필요.
 *
 * ------------------------------------------------------------
 * Q16.16 fixed point 설명
 * ------------------------------------------------------------
 *
 * eBPF VM 은 float 연산을 직접 다루지 못하는 환경이 많다.
 * codelet 쪽에서 정수만 쓰도록 weight 를 *Q16.16 형식*으로 표현:
 *   - 상위 16비트: 정수부
 *   - 하위 16비트: 소수부 (1/65536 단위)
 *
 * 변환:
 *   1.0  → (1 << 16)  = 0x00010000
 *   4.0  → (4 << 16)  = 0x00040000
 *   2.5  → (2 << 16) | (0x8000) = 0x00028000
 *   0.5  → (0 << 16) | (0x8000) = 0x00008000
 *
 * Host 쪽에서 float 으로 환원:
 *   float w = (float)weight_q16 / 65536.0f;
 *
 * 이 변환은 *host 쪽 단 한 곳* (qos_weight_apply 호출자) 에서만
 * 일어나야 한다. 그래야 fixed-point 표현이 wire 와 host-side
 * table 사이의 경계 자리에 갇힘.
 */

#ifndef QOS_WEIGHT_MSG_H
#define QOS_WEIGHT_MSG_H

#include <stdint.h>

/*
 * WeightUpdate — codelet 이 ringbuf 로 발사하는 단위 메시지
 *
 * __attribute__((packed)):
 *   컴파일러가 멤버 사이에 padding 을 넣지 못하도록 강제.
 *   eBPF codelet 이 캐스팅으로 그대로 읽기 때문에 필드 오프셋이
 *   wire layout 과 정확히 일치해야 한다.
 */
struct WeightUpdate {
    uint16_t rnti;          /* +0  UE 식별자 (host byte order) */
    uint16_t duration_ms;   /* +2  TTL (밀리초).
                             *     0      = 영구 (clear_all / 재시작까지 유지)
                             *     1..N   = N ms 후 자동 만료 (heartbeat 모드)
                             *     0xFFFF = QOS_WEIGHT_TTL_CLEAR_ALL — 전체 해제
                             *              (rnti / weight_q16 필드 무시) */
    uint32_t weight_q16;    /* +4  Q16.16 가중치. (1<<16) = 1.0
                             *     정확히 1.0 이면 해당 UE 의 정책 해제 */
} __attribute__((packed));  /* 총 8 바이트 */

/*
 * duration_ms 센티널: "모든 UE 의 가중치를 해제".
 *
 * 왜 별도 스트림이 아니라 센티널인가:
 *   정책 채널(0xCC…01)을 하나로 유지하면 YAML·stream_id·디스패처를 건드릴
 *   필요가 없다. TTL 로 쓸 수 없는 값(65535ms = 65초, 실사용 범위 밖)을
 *   골라 재사용했다.
 *
 * 트리거: demand6 의 app_type == 255 (APP_RESET)
 */
#define QOS_WEIGHT_TTL_CLEAR_ALL  0xFFFFu

/*
 * Q16.16 ↔ float 변환을 위한 매크로
 *
 * Codelet 쪽에서 정책 결정 시 사용:
 *   .weight_q16 = QOS_WEIGHT_Q16(4)        // 4.0 → 0x00040000
 *
 * Host 쪽에서 float 으로 환원 시 사용:
 *   float w = QOS_WEIGHT_FROM_Q16(wu->weight_q16);
 */
#define QOS_WEIGHT_Q16(integer_part)   ((uint32_t)((integer_part) << 16))
#define QOS_WEIGHT_FROM_Q16(q16)       ((float)(q16) / 65536.0f)

#endif /* QOS_WEIGHT_MSG_H */
