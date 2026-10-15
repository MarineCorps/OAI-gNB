# JBPF Codelet Makefile — eBPF 프로그램을 clang 으로 컴파일
#
# 사용:
#   make              모든 코드렛 빌드
#   make DEBUG=1      jbpf_printf_debug() 출력 활성화 (아래 주의사항 참조)
#   make <name>.o     하나만 빌드
#   make clean        .o 삭제
#   make list         빌드 대상 목록 확인
#
# 보통은 직접 호출하지 않고 ~/codelet.sh build 를 쓴다.

CLANG      := clang-14
LLVM_STRIP := llvm-strip-14

# eBPF 컴파일 플래그
#
# Include path:
#   -I../..  : openair2/          (구 codelet 들이 쓰던 경로)
#   -I..     : openair2/JBPF/     — 공유 헤더 위치.
#              qos_weight_msg.h (wire format), pdcp_hook_ctx.h /
#              mac_scheduler_hooks.h (hook context) 를 짧은 경로로 가져온다.
#              이 헤더들은 gNB 쪽과 *같은 파일*이어야 한다 — 양쪽이 따로
#              정의를 들고 있으면 필드 오프셋이 어긋나며 silent corruption.
#              CMakeLists.txt 의 -I${SRC}/openair2/JBPF 와 동일한 의미.
CFLAGS := -target bpf \
          -O2 \
          -g \
          -D__x86_64__ \
          -I../.. \
          -I.. \
          -I/usr/local/include \
          -I/usr/include/x86_64-linux-gnu \
          -Wall \
          -Wno-unused-value \
          -Wno-pointer-sign \
          -Wno-compare-distinct-pointer-types

# ── 코드렛 디버그 출력 (DEBUG=1) ──────────────────────────────────
#
# 코드렛 소스의 #define USE_JBPF_PRINTF_HELPER 는 *코드렛 자신의* 디버그
# 블록을 여는 로컬 플래그다. 그런데 jbpf_printf_debug() 매크로 자체는
# jbpf_helper.h:266 에서 JBPF_DEBUG_ENABLED 로 게이트되어 있고, 이 매크로가
# 없으면 ((void)0) 으로 치환된다.
#
# 즉 JBPF_DEBUG_ENABLED 없이 빌드하면 코드렛의 jbpf_printf_debug() 출력은
# 전부 사라진다 (header_parser.c 의 'unused variable s/d' 경고가 그 증거다).
#
# 기본값을 off 로 두는 이유:
#   jbpf_printf 는 fast path 에 쓰지 말라고 공식 문서에 명시돼 있다.
#   header_parser 는 *모든* UL 패킷마다 돌면서 printf 를 6번 호출하므로
#   항상 켜두면 PDCP 스레드에 그대로 비용이 얹힌다.
#
# 주의: jbpf_printf_debug 는 인자를 최대 3개까지만 받는다. header_parser 의
#       IP 주소 출력처럼 12개를 넘기는 호출은 DEBUG=1 로도 제대로 찍히지
#       않는다 (별도 수정 필요).
ifeq ($(DEBUG),1)
CFLAGS += -DJBPF_DEBUG_ENABLED
endif

# 빌드 대상은 codelets.list 에서 읽는다 (CMakeLists.txt 와 공유).
# sed: 인라인 주석(#...) 제거 → 전체 주석/빈 줄 제거 → 공백 정리
CODELETS := $(shell sed -e 's/#.*//' -e 's/[[:space:]]*$$//' codelets.list | grep -v '^$$')
OBJS     := $(addsuffix .o, $(CODELETS))

.PHONY: all clean list install

all: $(OBJS)
	@echo "──────────────────────────────────────────────"
	@echo "코드렛 $(words $(OBJS))개 빌드 완료:"
	@ls -1 $(OBJS) | sed 's/^/  /'

%.o: %.c
	@echo "  CLANG   $<"
	@$(CLANG) $(CFLAGS) -c $< -o $@
	@$(LLVM_STRIP) -g $@

list:
	@echo "codelets.list 의 빌드 대상 $(words $(CODELETS))개:"
	@for c in $(CODELETS); do echo "  $$c"; done

# 운영 환경용. 로컬 개발에서는 YAML 이 절대 경로를 가리키므로 불필요.
install: all
	sudo mkdir -p /usr/local/share/oai/jbpf/codelets
	sudo cp $(OBJS) /usr/local/share/oai/jbpf/codelets/
	sudo cp *.yaml  /usr/local/share/oai/jbpf/
	@echo "설치 완료: /usr/local/share/oai/jbpf/"

clean:
	rm -f $(OBJS)
	@echo "clean 완료"
