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
CODELETS := sdap_packet_stats sdap_qfi_classifier header_parser
OBJS := $(addsuffix .o, $(CODELETS))

# 설치 경로
INSTALL_DIR := /usr/local/share/oai/jbpf/codelets
YAML_INSTALL_DIR := /usr/local/share/oai/jbpf

.PHONY: all clean install

all: $(OBJS)

%.o: %.c
	@echo "Compiling eBPF codelet: $<"
	$(CLANG) $(CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@
	@echo "  → $@ created"

install: all
	@echo "Installing codelets to $(INSTALL_DIR)..."
	sudo mkdir -p $(INSTALL_DIR)
	sudo mkdir -p $(YAML_INSTALL_DIR)
	sudo cp $(OBJS) $(INSTALL_DIR)/
	sudo cp oai_gnb_monitoring.yaml $(YAML_INSTALL_DIR)/
	@echo "Installation complete!"
	@ls -lh $(INSTALL_DIR)

clean:
	rm -f $(OBJS)
	@echo "Clean complete"
