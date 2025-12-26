# JBPF Codelet 빌드 설정
# eBPF 프로그램을 clang으로 컴파일하여 .o 파일 생성

# clang-14와 llvm-strip-14 찾기
find_program(CLANG_EXEC clang-14 REQUIRED)
find_program(LLVM_STRIP_EXEC llvm-strip-14 REQUIRED)

message(STATUS "Found clang: ${CLANG_EXEC}")
message(STATUS "Found llvm-strip: ${LLVM_STRIP_EXEC}")

# Codelet 컴파일 플래그
set(CODELET_CFLAGS
    -target bpf              # eBPF 타겟 지정
    -O2                      # 최적화 레벨 2
    -g                       # 디버그 심볼 포함 (나중에 strip)
    -I${CMAKE_SOURCE_DIR}/openair2/JBPF
    -I/usr/local/include     # jbpf 헤더 위치
    -Wall                    # 모든 경고 활성화
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
)

#
# add_jbpf_codelet 함수
# eBPF C 코드를 .o 파일로 컴파일하는 커스텀 함수
#
# 사용법:
#   add_jbpf_codelet(타겟명 소스파일명)
#
function(add_jbpf_codelet TARGET_NAME SOURCE_FILE)
    set(OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.o)

    # 커스텀 빌드 커맨드 정의
    add_custom_command(
        OUTPUT ${OUTPUT_FILE}
        # 1단계: clang으로 컴파일
        COMMAND ${CLANG_EXEC} ${CODELET_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${OUTPUT_FILE}
        # 2단계: 디버그 심볼 제거 (크기 축소)
        COMMAND ${LLVM_STRIP_EXEC} -g ${OUTPUT_FILE}
        # 의존성: 소스 파일이 변경되면 재빌드
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
        COMMENT "Compiling eBPF codelet: ${SOURCE_FILE}"
    )

    # 타겟 생성 (ALL: 기본 빌드에 포함)
    add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE})

    # 설치 규칙: /usr/local/share/oai/jbpf/codelets/
    install(FILES ${OUTPUT_FILE}
            DESTINATION share/oai/jbpf/codelets)
endfunction()

# Codelet 빌드 등록
add_jbpf_codelet(sdap_packet_stats sdap_packet_stats.c)
add_jbpf_codelet(sdap_qfi_classifier sdap_qfi_classifier.c)

# YAML 파일도 설치
install(FILES oai_gnb_monitoring.yaml
        DESTINATION share/oai/jbpf)
