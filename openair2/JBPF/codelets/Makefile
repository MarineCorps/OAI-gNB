# JBPF Codelet Makefile
# eBPF 프로그램을 clang으로 컴파일

CLANG := clang-14
LLVM_STRIP := llvm-strip-14

# eBPF 컴파일 플래그
CFLAGS := -target bpf \
          -O2 \
          -g \
          -D__x86_64__ \
          -I../.. \
          -I/usr/local/include \
          -I/usr/include/x86_64-linux-gnu \
          -Wall \
          -Wno-unused-value \
          -Wno-pointer-sign \
          -Wno-compare-distinct-pointer-types

# Codelet 소스 파일
# ──────────────────────────────────────────────────────────────
# 기존 SDAP/PDCP 계층 codelets:
#   sdap_packet_stats  : UL 패킷 통계 (hook: sdap_uplink)
#   sdap_qfi_classifier: QFI 기반 트래픽 분류 (hook: sdap_uplink)
#   header_parser      : IP/TCP/UDP 헤더 파싱 (hook: pdcp_uplink)
#
# 신규 MAC 스케줄러 codelets:
#   mac_dl_prb_stats   : DL PRB 점유율 (hook: mac_dl_prb_alloc)
#   mac_ul_prb_stats   : UL PRB 점유율 (hook: mac_ul_prb_alloc)
#   mac_bsr_monitor    : BSR 수신 모니터링 (hook: mac_bsr_event)
#   mac_sr_monitor     : SR 감지 모니터링 (hook: mac_sr_detect)
# ──────────────────────────────────────────────────────────────
CODELETS := sdap_packet_stats sdap_qfi_classifier header_parser \
            mac_dl_prb_stats mac_ul_prb_stats mac_bsr_monitor mac_sr_monitor
OBJS := $(addsuffix .o, $(CODELETS))

# 로컬 개발 경로 (설치 불필요)
LOCAL_DIR := $(shell pwd)

.PHONY: all clean install

all: $(OBJS)
	@echo "Build complete! Codelets are ready in $(LOCAL_DIR)"
	@ls -lh *.o

%.o: %.c
	@echo "Compiling eBPF codelet: $<"
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "  → $@ created"

# Optional: 시스템 경로에 설치 (운영 환경용)
install: all
	@echo "Installing codelets to /usr/local/share/oai/jbpf/..."
	sudo mkdir -p /usr/local/share/oai/jbpf/codelets
	sudo cp $(OBJS) /usr/local/share/oai/jbpf/codelets/
	sudo cp oai_gnb_monitoring.yaml /usr/local/share/oai/jbpf/
	@echo "Installation complete!"

clean:
	rm -f $(OBJS)
	@echo "Clean complete"
