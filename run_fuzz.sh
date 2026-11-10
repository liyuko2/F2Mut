#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 INPUT_DIR OUTPUT_DIR -- TARGET [TARGET_ARGS...]" >&2
  exit 2
}

[[ $# -ge 4 ]] || usage
input_dir="$1"
output_dir="$2"
shift 2
[[ "$1" == "--" ]] || usage
shift
[[ $# -ge 1 ]] || usage
target_command=("$@")

[[ -d "$input_dir" ]] || { echo "input directory not found: $input_dir" >&2; exit 2; }
if ! find "$input_dir" -type f -size +0c -print -quit | grep -q .; then
  echo "input directory has no non-empty seed files: $input_dir" >&2
  exit 2
fi
input_dir="$(cd "$input_dir" && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"

if [[ ! -x "$ROOT_DIR/afl-fuzz" ]]; then
  make -C "$ROOT_DIR" afl-fuzz
fi

export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export AFL_PYTHON_MODULE="MutatorMin"
export AFL_IGNORE_UNKNOWN_ENVS="${AFL_IGNORE_UNKNOWN_ENVS:-1}"
export AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR="${AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR:-$ROOT_DIR/elf_template_executor.py}"
export AFL_LLM_FORMAT_EXECUTOR_DIR="${AFL_LLM_FORMAT_EXECUTOR_DIR:-$output_dir/generated_format_executors}"
export AFL_LLM_MUTATORS_DIR="${AFL_LLM_MUTATORS_DIR:-$output_dir/runtime_state}"
export AFL_LLM_SEED_DIR="${AFL_LLM_SEED_DIR:-$output_dir/generated_seed_data}"
export AFL_LLM_G2FUZZ_SOURCE_DIR="${AFL_LLM_G2FUZZ_SOURCE_DIR:-$ROOT_DIR/G2FUZZ}"
export AFL_LLM_G2FUZZ_OUTPUT_DIR="${AFL_LLM_G2FUZZ_OUTPUT_DIR:-$output_dir/g2fuzz_output}"
export AFL_LLM_AFL_OUT="${AFL_LLM_AFL_OUT:-$output_dir/default}"
export AFL_LLM_TEMPLATE_MODE="${AFL_LLM_TEMPLATE_MODE:-1}"
export AFL_LLM_SEED_GEN="${AFL_LLM_SEED_GEN:-0}"
export AFL_LLM_BOTTLENECK_EXPANSION="${AFL_LLM_BOTTLENECK_EXPANSION:-0}"

exec "$ROOT_DIR/afl-fuzz" -i "$input_dir" -o "$output_dir" -- "${target_command[@]}"
