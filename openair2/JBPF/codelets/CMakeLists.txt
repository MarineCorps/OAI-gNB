# JBPF Codelet 빌드 설정 — eBPF C 코드를 clang 으로 .o 로 컴파일
#
# 빌드 대상 목록은 codelets.list 에 있고 Makefile 과 공유한다.
# 목록을 두 곳에 두면 반드시 드리프트한다 (실제로 intent_parser 가
# Makefile 에만 있던 적이 있다).

find_program(CLANG_EXEC clang-14 REQUIRED)
find_program(LLVM_STRIP_EXEC llvm-strip-14 REQUIRED)

message(STATUS "Found clang: ${CLANG_EXEC}")
message(STATUS "Found llvm-strip: ${LLVM_STRIP_EXEC}")

# Codelet 컴파일 플래그 (codelets/Makefile 의 CFLAGS 와 같은 의미)
set(CODELET_CFLAGS
    -target bpf                        # eBPF 타겟
    -O2
    -g                                 # 디버그 심볼 (아래에서 strip)
    -D__x86_64__                       # eBPF 에서 필수
    -I${CMAKE_SOURCE_DIR}/openair2     # 구 codelet 경로
    -I${CMAKE_SOURCE_DIR}/openair2/JBPF  # 공유 헤더 (qos_weight_msg.h 등)
    -I/usr/local/include               # jbpf 헤더
    -I/usr/include/x86_64-linux-gnu    # 아키텍처별 헤더
    -Wall
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
)

# 코드렛 디버그 출력. 자세한 설명은 codelets/Makefile 의 같은 블록 참조.
# jbpf_printf 는 fast path 용이 아니므로 기본값은 off.
option(JBPF_CODELET_DEBUG "Enable jbpf_printf_debug() in codelets" OFF)
if(JBPF_CODELET_DEBUG)
    list(APPEND CODELET_CFLAGS -DJBPF_DEBUG_ENABLED)
endif()

#
# add_jbpf_codelet(<타겟명> <소스파일>)
#   eBPF C 소스를 .o 로 컴파일하고 디버그 심볼을 제거한다.
#
function(add_jbpf_codelet TARGET_NAME SOURCE_FILE)
    set(OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_NAME}.o)

    add_custom_command(
        OUTPUT ${OUTPUT_FILE}
        COMMAND ${CLANG_EXEC} ${CODELET_CFLAGS}
                -c ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE} -o ${OUTPUT_FILE}
        COMMAND ${LLVM_STRIP_EXEC} -g ${OUTPUT_FILE}
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${SOURCE_FILE}
        COMMENT "Compiling eBPF codelet: ${SOURCE_FILE}"
    )

    add_custom_target(${TARGET_NAME} ALL DEPENDS ${OUTPUT_FILE})

    install(FILES ${OUTPUT_FILE}
            DESTINATION share/oai/jbpf/codelets)
endfunction()

#
# codelets.list 를 읽어 대상을 등록한다.
#   - '#' 주석(줄 전체 / 인라인)과 빈 줄 무시
#   - 목록이 바뀌면 CMake 재실행이 필요하므로 CONFIGURE_DEPENDS 대신
#     파일을 configure 의존성에 명시적으로 등록한다.
#
set(CODELET_LIST_FILE ${CMAKE_CURRENT_SOURCE_DIR}/codelets.list)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CODELET_LIST_FILE})

file(STRINGS ${CODELET_LIST_FILE} CODELET_LINES)
set(JBPF_CODELETS "")
foreach(line ${CODELET_LINES})
    string(REGEX REPLACE "#.*$" "" line "${line}")   # 인라인 주석 제거
    string(STRIP "${line}" line)
    if(NOT line STREQUAL "")
        list(APPEND JBPF_CODELETS ${line})
    endif()
endforeach()

message(STATUS "JBPF codelets from codelets.list: ${JBPF_CODELETS}")

foreach(codelet ${JBPF_CODELETS})
    add_jbpf_codelet(${codelet} ${codelet}.c)
endforeach()

# 매니페스트 전체를 설치한다 (예전에는 oai_gnb_monitoring.yaml 하나만 했다).
file(GLOB CODELET_MANIFESTS ${CMAKE_CURRENT_SOURCE_DIR}/*.yaml)
install(FILES ${CODELET_MANIFESTS}
        DESTINATION share/oai/jbpf)
