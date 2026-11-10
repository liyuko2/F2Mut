#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat >&2 <<EOF
Usage: $0 [--nogen] INPUT_DIR OUTPUT_DIR -- TARGET [TARGET_ARGS...]

Start fuzzing with already prepared templates. For the full pipeline use run.sh.
Default: run G2FUZZ_DIR/afl-fuzz (G2FUZZ_DIR defaults to $ROOT_DIR/G2FUZZ).
--nogen: run $ROOT_DIR/afl-fuzz, building it from local sources if missing.
EOF
}

mode="normal"
case "${1:-}" in
  --nogen)
    mode="NoGen"
    shift
    ;;
  -h|--help)
    usage
    exit 0
    ;;
esac

[[ $# -ge 4 ]] || { usage; exit 2; }
input_dir="$1"
output_dir="$2"
shift 2
[[ "$1" == "--" ]] || { usage; exit 2; }
shift
[[ $# -ge 1 ]] || { usage; exit 2; }
target_command=("$@")
if [[ "${target_command[0]}" == */* && "${target_command[0]}" != /* ]]; then
  target_command[0]="$PWD/${target_command[0]}"
fi

initial_template="${AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR:-}"
executor_dir="${AFL_LLM_FORMAT_EXECUTOR_DIR:-}"
[[ -f "$initial_template" && -n "$executor_dir" && -d "$executor_dir" ]] || {
  echo "prepared initial template and executor pool are required; use run.sh to prepare them" >&2
  exit 2
}
initial_template="$(cd "$(dirname "$initial_template")" && pwd)/$(basename "$initial_template")"
executor_dir="$(cd "$executor_dir" && pwd)"
if ! find "$executor_dir" -maxdepth 1 -name '*.py' -type f -size +0c -print -quit | grep -q .; then
  echo "prepared executor pool has no non-empty Python files: $executor_dir" >&2
  exit 2
fi
work_dir="${AFL_LLM_G2FUZZ_WORK_DIR:-$PWD}"
[[ -d "$work_dir" ]] || { echo "G2FUZZ work directory not found: $work_dir" >&2; exit 2; }
work_dir="$(cd "$work_dir" && pwd)"

afl_options=()
g2fuzz_source_dir="${AFL_LLM_G2FUZZ_SOURCE_DIR:-$ROOT_DIR/G2FUZZ}"
if [[ "$mode" == "normal" ]]; then
  g2fuzz_dir="${G2FUZZ_DIR:-$ROOT_DIR/G2FUZZ}"
  [[ -d "$g2fuzz_dir" ]] || {
    echo "G2FUZZ directory not found: $g2fuzz_dir; set G2FUZZ_DIR to a compiled G2FUZZ checkout" >&2
    exit 2
  }
  g2fuzz_dir="$(cd "$g2fuzz_dir" && pwd)"
  afl_fuzz="$g2fuzz_dir/afl-fuzz"
  [[ -f "$afl_fuzz" && -x "$afl_fuzz" ]] || {
    echo "G2FUZZ afl-fuzz is not executable: $afl_fuzz; build G2FUZZ first or use --nogen" >&2
    exit 2
  }
  g2fuzz_source_dir="${AFL_LLM_G2FUZZ_SOURCE_DIR:-$g2fuzz_dir}"
  [[ -f "$g2fuzz_source_dir/generator_mutation.py" ]] || {
    echo "G2FUZZ generator_mutation.py not found in: $g2fuzz_source_dir" >&2
    exit 2
  }
  g2fuzz_source_dir="$(cd "$g2fuzz_source_dir" && pwd)"
  for config in model_setting.json program_to_format.json openai_key.txt; do
    [[ -s "$work_dir/$config" ]] || {
      echo "native G2FUZZ runtime config missing: $work_dir/$config; prepare with run.sh" >&2
      exit 2
    }
  done
  afl_options=(-k "$g2fuzz_source_dir")
else
  afl_fuzz="$ROOT_DIR/afl-fuzz"
fi

[[ -d "$input_dir" ]] || { echo "input directory not found: $input_dir" >&2; exit 2; }
if ! find "$input_dir" -type f -size +0c -print -quit | grep -q .; then
  echo "input directory has no non-empty seed files: $input_dir" >&2
  exit 2
fi
input_dir="$(cd "$input_dir" && pwd)"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
if [[ "$mode" == "normal" ]]; then
  [[ -s "$output_dir/default/feature_pool.json" &&
     -s "$output_dir/default/feature_programs.json" &&
     -d "$output_dir/default/generators" ]] || {
    echo "native G2FUZZ generation state is missing under $output_dir/default; prepare with run.sh" >&2
    exit 2
  }
fi

if [[ "$mode" == "NoGen" && ! -x "$afl_fuzz" ]]; then
  make -C "$ROOT_DIR" afl-fuzz
fi

export PYTHONPATH="$ROOT_DIR${PYTHONPATH:+:$PYTHONPATH}"
export AFL_PYTHON_MODULE="MutatorMin"
export AFL_IGNORE_UNKNOWN_ENVS="${AFL_IGNORE_UNKNOWN_ENVS:-1}"
export AFL_LLM_FALLBACK_TEMPLATE_EXECUTOR="$initial_template"
export AFL_LLM_FORMAT_EXECUTOR_DIR="$executor_dir"
export AFL_LLM_MUTATORS_DIR="${AFL_LLM_MUTATORS_DIR:-$output_dir/runtime_state}"
export AFL_LLM_SEED_DIR="${AFL_LLM_SEED_DIR:-$output_dir/generated_seed_data}"
export AFL_LLM_G2FUZZ_SOURCE_DIR="$g2fuzz_source_dir"
export AFL_LLM_G2FUZZ_OUTPUT_DIR="${AFL_LLM_G2FUZZ_OUTPUT_DIR:-$output_dir/g2fuzz_output}"
export AFL_LLM_AFL_OUT="${AFL_LLM_AFL_OUT:-$output_dir/default}"
export AFL_LLM_TEMPLATE_MODE=1
export AFL_LLM_TEMPLATE_POOL=1
export AFL_LLM_TEMPLATE_INITIAL_ONLY=0
export AFL_LLM_SEED_GEN=0
export AFL_LLM_BOTTLENECK_EXPANSION="${AFL_LLM_BOTTLENECK_EXPANSION:-0}"
echo "[F2Mut] mode=$mode afl-fuzz=$afl_fuzz" >&2
cd "$work_dir"
exec "$afl_fuzz" -i "$input_dir" -o "$output_dir" "${afl_options[@]}" -- "${target_command[@]}"
