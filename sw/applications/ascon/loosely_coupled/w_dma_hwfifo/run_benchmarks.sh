#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../../../../.." && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

mkdir -p \
  "${RESULTS_DIR}/AEAD128" \
  "${RESULTS_DIR}/HASH256" \
  "${RESULTS_DIR}/XOF128" \
  "${RESULTS_DIR}/CXOF128"

cd "${REPO_ROOT}"

run_case() {
  local algorithm="$1"
  local project="$2"
  local compile_definitions="$3"
  local case_name="$4"
  local log_file="${RESULTS_DIR}/${algorithm}/${case_name}.log"

  printf '\n[%s] Running %s\n' "${algorithm}" "${case_name}"
  printf 'Result: %s\n' "${log_file}"

  {
    printf 'Algorithm: %s\n' "${algorithm}"
    printf 'Case: %s\n' "${case_name}"
    printf 'CDEFS: %s\n\n' "${compile_definitions}"

    CDEFS="${compile_definitions}" make app PROJECT="${project}"
    make verilator-run
  } 2>&1 | tee "${log_file}"
}

AEAD128_PROJECT="ascon/loosely_coupled/w_dma_hwfifo/ascon_AEAD128"
AEAD128_CASES=(
  "16 0"
  "0 16"
  "16 16"
  "1536 0"
  "0 1536"
  "1536 1536"
  "16384 0"
  "0 16384"
  "16384 16384"
)

for test_case in "${AEAD128_CASES[@]}"; do
  read -r ad_length message_length <<< "${test_case}"
  run_case \
    "AEAD128" \
    "${AEAD128_PROJECT}" \
    "AD_LENGTH=${ad_length}U;MESSAGE_LENGTH=${message_length}U" \
    "ad_${ad_length}_pt_${message_length}"
done

HASH256_PROJECT="ascon/loosely_coupled/w_dma_hwfifo/ascon_HASH256"
HASH256_CASES=(16 1536 16384)

for message_length in "${HASH256_CASES[@]}"; do
  run_case \
    "HASH256" \
    "${HASH256_PROJECT}" \
    "MESSAGE_LENGTH=${message_length}U" \
    "message_${message_length}"
done

XOF128_PROJECT="ascon/loosely_coupled/w_dma_hwfifo/ascon_XOF128"
XOF128_CASES=(
  "16 32"
  "16 1536"
  "1536 32"
  "1536 1536"
  "16 16384"
  "16384 32"
  "16384 16384"
)

for test_case in "${XOF128_CASES[@]}"; do
  read -r message_length output_length <<< "${test_case}"
  run_case \
    "XOF128" \
    "${XOF128_PROJECT}" \
    "MESSAGE_LENGTH=${message_length}U;OUTPUT_LENGTH=${output_length}U" \
    "message_${message_length}_output_${output_length}"
done

CXOF128_PROJECT="ascon/loosely_coupled/w_dma_hwfifo/ascon_CXOF128"
CXOF128_CASES=(
  "16 16 32"
  "16 16 1536"
  "16 1536 32"
  "16 1536 1536"
  "256 16 32"
  "256 16 1536"
  "256 1536 32"
  "256 1536 1536"
  "16 16 16384"
  "16 16384 32"
  "16 16384 16384"
  "256 16 16384"
  "256 16384 32"
  "256 16384 16384"
)

for test_case in "${CXOF128_CASES[@]}"; do
  read -r customization_length message_length output_length <<< "${test_case}"
  run_case \
    "CXOF128" \
    "${CXOF128_PROJECT}" \
    "CUSTOMIZATION_LENGTH=${customization_length}U;MESSAGE_LENGTH=${message_length}U;OUTPUT_LENGTH=${output_length}U" \
    "z_${customization_length}_message_${message_length}_output_${output_length}"
done

printf '\nAll w_dma_hwfifo cases completed. Results are in:\n%s\n' "${RESULTS_DIR}"
