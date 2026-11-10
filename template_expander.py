#!/usr/bin/env python3
"""Template Expander — extend a template executor via LLM and write validated output.

Usage:
  python3 template_expander.py INPUT_TEMPLATE.py [INPUT_TEMPLATE2.py ...] \\
      --count 3 --output-dir generated_format_executors

The input template is the reference .py file (e.g. a format-specific executor).
The LLM reads it, understands its structure, helpers, profile, and convention,
then generates NEW operators that extend the OP_HANDLERS while reusing the
existing helpers and execution flow.

Multiple input templates produce multiple extensions; --count repeats generation
for each input (--count 3 with 1 input = 3 outputs, with 2 inputs = 6 outputs).
Without --count, --architecture-variants generates 5 outputs per input and all
other generations produce 1. Repeated variants of one input and style avoid NEW
mutation handlers already generated earlier in the same command.
"""

import argparse
import ast
import hashlib
import importlib
import importlib.util
import inspect
import json
import os
import re
import shlex
import subprocess
import struct
import sys
import tempfile
import time

from template_safety import validate_template_memory_safety
from llm_generation_metrics import GenerationMetrics, add_metrics_to_timing_record, response_usage

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

try:
    import httpx
except ImportError:
    httpx = None

DEFAULT_MODULE_URL = "https://api.deepseek.com"
DEFAULT_MODULE_NAME = "deepseek-chat"
DEFAULT_VARIANT_COUNT = 1
ARCHITECTURE_VARIANT_DEFAULT_COUNT = 5
FORMAT_EXECUTOR_DIR_NAME = "generated_format_executors"
FORMAT_EXECUTOR_DIR_ENV = "AFL_LLM_FORMAT_EXECUTOR_DIR"
TEMPLATE_EXECUTOR_DIR_ENV = "AFL_LLM_TEMPLATE_EXECUTOR_DIR"
TEMPLATE_TIMING_LOG_ENV = "AFL_LLM_TEMPLATE_TIMING_LOG"
TEMPLATE_TIMING_LOG_NAME = "template_generation_timing.jsonl"
AUTO_INSTALL_MODULES_ENV = "AFL_LLM_TEMPLATE_AUTO_INSTALL_MODULES"
AUTO_INSTALL_PIP_ARGS_ENV = "AFL_LLM_TEMPLATE_PIP_ARGS"
AUTO_INSTALL_PIP_TIMEOUT_ENV = "AFL_LLM_TEMPLATE_PIP_TIMEOUT"
AUTO_INSTALL_PACKAGE_MAP_ENV = "AFL_LLM_TEMPLATE_PACKAGE_MAP"
AUTO_INSTALL_MAX_ATTEMPTS_ENV = "AFL_LLM_TEMPLATE_INSTALL_MAX_ATTEMPTS"


def _base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _format_executor_dir():
    path = (
        os.environ.get(FORMAT_EXECUTOR_DIR_ENV) or
        os.environ.get(TEMPLATE_EXECUTOR_DIR_ENV) or
        FORMAT_EXECUTOR_DIR_NAME
    )
    path = str(path).strip()
    if not os.path.isabs(path):
        path = os.path.join(_base_dir(), path)
    return os.path.abspath(path)


def _repo_relative_abs_path(path):
    path = str(path or "").strip()
    if not path:
        return None
    if not os.path.isabs(path):
        path = os.path.join(_base_dir(), path)
    return os.path.abspath(path)


def _timestamp_utc(epoch_seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch_seconds))


def _resolve_timing_log_path(explicit_path=None, output_dir=None, disabled=False):
    if disabled:
        return None
    value = explicit_path if explicit_path is not None else os.environ.get(TEMPLATE_TIMING_LOG_ENV)
    if isinstance(value, str):
        value = value.strip()
    if value:
        if str(value).lower() in {"0", "false", "no", "off", "none"}:
            return None
        return _repo_relative_abs_path(value)
    base_dir = output_dir or _format_executor_dir()
    return os.path.abspath(os.path.join(base_dir, TEMPLATE_TIMING_LOG_NAME))


def _finish_timing_record(record, status, error=None):
    finished_at = time.time()
    record["status"] = status
    record["finished_at"] = finished_at
    record["finished_at_utc"] = _timestamp_utc(finished_at)
    record["duration_sec"] = round(finished_at - float(record["started_at"]), 6)
    if error:
        record["error"] = str(error)[:2000]
    return record["duration_sec"]


def _append_timing_record(path, record):
    if not path:
        return
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "a", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=True, sort_keys=True)
        f.write("\n")


_SYSTEM_PROMPT = """\
You are an expert binary format mutation engineer. You will receive a Python
template executor as reference and must EXTEND it by adding lightweight
structure-aware mutation operators. Your output must be ONE complete, runnable
Python file that follows the exact same contract as the reference executor.

## Contract

Each operator function signature is:

    def op_name(buf, op, profile, max_size) -> bool

- buf: bytearray that the operator mutates in-place
- op: dict with the "op" key and optional parameters
- profile: dict describing the binary format structure (e.g. field offsets,
  sizes, regions, endianness)
- max_size: int maximum allowed output length
- Return True only if the buffer was actually changed; return False otherwise.

The module MUST define these top-level names exactly:
MAX_OUTPUT_SIZE, DEFAULT_PLAN, OP_HANDLERS,
  execute_template_plan, mutate

If the reference executor defines FEATURE_SCHEMA, FEATURE_ACTIONS,
parse_profile, applicable_ops, you SHOULD also define them.

## Design Principles

1. **Local, bounded mutations** — change 1-4 bytes at computed offsets, not
   global rewrites.  Each operator should target a specific structural field
   or region.
	2. **max_size safety** — always check len(buf) and max_size before growing or
	   writing.  Any required final offset or length derived from input data MUST
	   be checked against max_size before allocating, repeating bytes, extending,
	   or rebuilding a buffer.  Checking max_size only after allocation is
	   forbidden.  Return the original data (or False) if limits are exceeded.
	   Treat all current-input fields such as size, length, count, entry_count,
	   sample_count, number_of_entries, table_count, and offset as untrusted.
	   Never use such values directly in range(), list/bytes multiplication,
	   bytearray(count), extend(), or any allocation.  First compute a bounded
	   value using both container bounds and a small literal cap, e.g.
	   bounded_count = min(declared_count, available_bytes // entry_size, 128).
3. **Return True only on actual change** — if the mutation did not modify buf,
   return False.  Never return True unconditionally.
4. **Keep input parseable** — prefer small, reversible changes.  Construct and
   repair operators must restore known-good field values rather than injecting
   random bytes.
5. **Operator categories** — generate a balanced set across these roles:
   - **construct** (ensure_*, init_*): write known-good values into empty or
     corrupted fields
   - **repair/sync** (sync_*, repair_*, fix_*): restore cross-field consistency
   - **explore** (mutate_*, fuzz_*, inject_*, shuffle_*, explore_*): discover new
     paths by changing type, flag, offset, size, count, index, or reference fields
   - **controlled-desync** (desync_*, shift_*, misalign_*): intentionally break
     a single cross-reference to test error-handling paths

## Must-Include Operator Roles

Generate at least one operator for EACH of these generic structural roles.
Derive the actual field names, offsets, and encoding from the reference
executor's profile and helpers:

- **type**: mutate/swap/desync the format identifier fields (e.g. magic bytes,
  format version, type tag)
- **flag**: mutate bit-flag or permission fields
- **offset**: mutate, shift, or repair pointer/offset fields that reference
  other structures
- **size**: mutate size or length fields (file size, region size, table size)
- **count**: mutate count fields (number of headers, entries, elements)
- **index**: mutate or desync index fields that reference other structures
- **reference**: repair or desync cross-references between structures
- **checksum**: inject or update checksum/hash fields if present
- **alignment**: mutate or repair alignment fields
- **entry_size**: mutate entry-size or stride fields
- **metadata**: mutate metadata fields (version, flags, OS/ABI, timestamps)
- **string**: mutate string content in string tables or name fields (preserve
  null terminators)
- **payload**: mutate content regions (code, data, rodata, etc.)
- **construct-chunk**: construct a new top-level or sub-level structural unit
  (e.g. a chunk/block/entry that the format defines as a self-contained record
  with its own header, type tag, length, and payload).  In formats with a
  header table this means appending a new table entry whose type and size
  fields are set, and whose data payload is written into the buffer.  In
  chunked formats this means emitting a length-prefixed or tag-prefixed record.
- **construct-directory**: construct a new directory/index/table that groups
  multiple entries and is itself referenced from the format's main header or
  root structure.  In formats with separate index and data areas this means
  adding a new index entry in the top-level table that points to a data region.
- **construct-table**: construct a structured sub-table with entries that
  cross-reference other parts of the file (e.g. lookup tables, symbol index
  tables, relocation/offset maps, hash bucket+chain arrays, color palettes).
  Each entry in the sub-table should contain at least one offset or index that
  points elsewhere in the file.
- **construct-string**: construct a new name/label entry or extend an existing
  string pool.  In formats with a central name table this means appending
  bytes and updating the string-table length field; in tag-based formats this
  means inserting a new tagged string record.

## Forbidden Patterns

- Do NOT perform networking, shell commands, dynamic code execution, or target
  execution. Do NOT use: subprocess, socket, os.system, __import__, eval, exec,
  compile, open (except in argparse/main), print (except in main), logging, chr
  with large values
- Do NOT append random bytes unconditionally (no meaningless tail blocks)
	- Do NOT perform pure random byte flips (use struct-aware mutations)
	- Do NOT return True without actually changing buf
	- Do NOT use while loops
	- Do NOT loop over or allocate from an input-declared count/size/length
	  directly.  Forbidden examples: for i in range(entry_count),
	  [value] * sample_count, b"\\0" * length, bytearray(size), or
	  buf.extend(data * count) unless the value was first clamped by len(buf),
	  the containing table/box bounds, and a small literal HARD_CAP.
	- Do NOT materialize lists for entries that are merely declared by a corrupted
	  input count.  Parse only the entries that physically fit in the current
	  buffer and within the literal cap.
	- Imports are not restricted to a fixed allowlist. Prefer Python standard
	  library modules when practical. You may import third-party modules when they
	  materially simplify local parsing or mutation; validation can install missing
	  packages. Do not import modules merely for side effects.
- Do NOT regenerate operators that already exist in the reference executor's
  OP_HANDLERS — define ONLY NEW operators.
- Every callable registered in OP_HANDLERS MUST accept the runtime positional
  arguments (buf, op, profile, max_size).  Wrap helpers with a compatible
  callable when their own signature differs.

## Output Format

Output a single JSON object with exactly these keys:
{
  "kind": "format_template_executor_code",
  "version": 1,
  "format": "infer from the reference executor",
  "name": "descriptive_name_for_this_variant",
  "description": "one-line description of the mutation style",
  "style": "one of: conservative_repair, aggressive_explore, offset_shift, header_extreme, string_table, mixed, constructor",
  "code": "COMPLETE PYTHON SOURCE CODE AS A SINGLE STRING"
}

When the architecture_variants modifier is active, the JSON object MUST also
contain an "architecture_target" object with canonical "id", "word_size",
"byte_order", and "abi" keys.  The generated module MUST define an identical
top-level ARCHITECTURE_TARGET dict and an ARCHITECTURE_OP_METADATA dict.

ARCHITECTURE_OP_METADATA MUST declare every operator whose purpose is to
coherently transition to or restore the selected architecture.  Each key must
be an operator name present in OP_HANDLERS.  Each value must contain:

    {
        "role": "architecture_transition" or "target_repair",
        "architecture_target": ARCHITECTURE_TARGET
    }

Use "architecture_transition" only for coherent conversion operators and
"target_repair" only for ensure/repair/sync/fix operators that restore
consistency with ARCHITECTURE_TARGET.  Do not declare controlled-desync
operators as transitions or repairs.  Include at least one operator of each
role.  Operators that restore only a source/reference architecture must not be
declared as target repairs.  MANDATORY: every target-repair operator must be
generated from ARCHITECTURE_TARGET and must not reuse, preserve, or restore the
reference executor's architecture.

The `code` value must be the full Python source of the executor module,
escaped as a JSON string.  You may reuse helper functions and constants from
the reference executor and you MUST NOT duplicate operators that already
exist in the reference executor's OP_HANDLERS.

The DEFAULT_PLAN should include any construct/ensure operators from the
reference at the start, any sync/repair operators at the end, with your
NEW operators in the middle.
"""

_ARCHITECTURE_VARIANTS_HINT = (
    "architecture_variants modifier: apply the requested primary style across "
    "architecture-sensitive variants and structures supported by the feature context "
    "and reference executor.  Prioritize architecture-related feature descriptions.  "
    "Generate two clearly separated operator families: (1) coherent "
    "architecture-specific construct, mutate, repair, and transition operators that "
    "preserve all related invariants for a compatible target architecture; and (2) "
    "controlled-desync operators that change exactly one architecture discriminator or "
    "relationship to exercise dispatch and error-handling paths.  A coherent transition "
    "operator must update every architecture-coupled property and structure that can be "
    "derived, and must return False when a complete compatible representation cannot be "
    "produced.  Every architecture-specific operator must check compatibility before "
    "mutation and return False when required evidence is absent.  Include repair/sync "
    "operators that restore consistency with the selected target.  Reference-profile "
    "repair operators may remain available, but must not be identified as target repairs.  "
    "MANDATORY: generate every target-repair operator according to ARCHITECTURE_TARGET; "
    "never reuse, preserve, or restore the reference executor's architecture in a "
    "target-repair operator.  Never "
    "describe a single-discriminator change as a coherent architecture conversion.  Keep "
    "coherent-transition and controlled-desync operators independently callable.  Derive "
    "architecture identifiers, widths, byte order, layout, conventions, relationships, "
    "and values only from the reference executor, profile, and verified feature context; "
    "do not invent unsupported constants or representations.  Declare the selected target "
    "in both the response architecture_target object and the generated module's top-level "
    "ARCHITECTURE_TARGET dict, using canonical id, word_size, byte_order, and abi keys.  "
    "Also define ARCHITECTURE_OP_METADATA.  It must map every coherent target-transition "
    "and target-repair operator name to a dict containing role and architecture_target.  "
    "The role must be exactly architecture_transition or target_repair, and every declared "
    "architecture_target must equal the module's ARCHITECTURE_TARGET.  Include at least one "
    "operator of each role.  Do not include controlled-desync or source/reference-only "
    "repair operators in ARCHITECTURE_OP_METADATA."
)


_STYLE_HINTS = {
    "conservative_repair": (
        "conservative_repair style: weight heavily toward repair_*, sync_*, and "
        "ensure_* operators.  Include a few explore_* operators but always pair them "
        "with a corresponding repair.  Only one or two desync_* operators for testing.  "
        "DEFAULT_PLAN: 70% repair/construct, 25% explore, 5% desync.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "aggressive_explore": (
        "aggressive_explore style: weight heavily toward explore_* and desync_* "
        "operators targeting different structural fields (type, flags, offsets, "
        "sizes, counts, indices, references, alignment).  Minimal repair at "
        "start/end only.  DEFAULT_PLAN: 15% repair, 70% explore, 15% desync.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "offset_shift": (
        "offset_shift style: focus on offset/size/alignment fields and their "
        "cross-references.  Target offset fields (pointers, virtual/physical "
        "addresses, table offsets), alignment fields, and entry sizes.  Include "
        "shift_offset (shift all offsets by a small delta), desync_reference "
        "(break one cross-reference), and repair_reference (restore consistency).  "
        "DEFAULT_PLAN: 30% repair, 50% offset/size explore, 20% desync.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "header_extreme": (
        "header_extreme style: deep coverage of header fields rarely touched "
        "by other executors.  Target version, flag, type, metadata, slot-size, "
        "count, and index fields in the main header and sub-headers.  Include "
        "explore_metadata, explore_entsize, desync_index, and inject_checksum.  "
        "DEFAULT_PLAN: 20% repair, 60% explore (header fields), 20% desync.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "string_table": (
        "string_table style: mutate string tables and naming references.  Include "
        "mutate_string (change individual chars preserving null terminators), "
        "inject_string (insert a new string into an existing string table), "
        "and desync_index (make index references point to wrong entries).  "
        "Also include repair_reference for restoring string table integrity.  "
        "DEFAULT_PLAN: 20% repair, 50% string/metadata, 30% header explore.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "mixed": (
        "mixed style: balanced coverage across all structural roles.  Each "
        "operator targets a different field category (type, flag, offset, size, "
        "count, index, reference, alignment, entry_size, metadata, string, payload).  "
        "Include at least one operator from every must-include role.  "
        "DEFAULT_PLAN: 30% repair, 50% explore, 20% desync.  "
        "Derive field names and offsets from the reference executor's profile and helpers."
    ),
    "constructor": (
        "constructor style: focus on BUILDING MISSING structural features not present "
        "in the original input.  Generate operators that add new chunks, directories, "
        "sub-tables, and string entries to the buffer.  Each construct operator must: "
        "(1) ensure necessary buffer space, (2) write a well-formed structural record "
        "(header entry, chunk, or table) with correct type/length fields, (3) update "
        "the parent header's count field to reflect the new entry.  Also include a few "
        "mutate/desync operators for variety.  "
        "DEFAULT_PLAN: ensure at start, then construct_* to build features, then a few "
        "mutate/desync, then sync at end.  "
        "Derive field names, offsets, sizes, table structures, and encoding from the "
        "reference executor's profile, constants, and helper functions."
    ),
}

_USER_PROMPT_TEMPLATE = """\
Below is the INPUT TEMPLATE executor that you must extend.  Study its structure,
helpers, profile, and conventions.  Generate NEW operators that complement the
existing ones — do not duplicate any operator already present in OP_HANDLERS.

--- BEGIN INPUT TEMPLATE ---
{input_code}
--- END INPUT TEMPLATE ---

Requested style: **{style_name}**
{style_hint}

	IMPORTANT: Derive all field names, offsets, sizes, and encoding details from
	the reference executor's profile, constants, and helper functions.  Do NOT
	hardcode format-specific field names unless they are defined as constants or
	profile keys in the reference.  Your operators should work with the same profile
	structure and helper functions used by the reference executor.
	If the reference parser uses input-declared counts directly, do not copy that
	pattern.  Repair it in your output by clamping counts with available bytes and
	a small literal HARD_CAP before any loop or allocation.

	Remember: output exactly ONE JSON object with keys kind, version, format, name,
description, style, code.  The code field must be a complete runnable Python
module following the contract in the system prompt.
"""


def _normalize_model_name(model):
    model = str(model or "").strip()
    if model.upper() == "GLM":
        return "glm-4-flash-250414"
    return model or DEFAULT_MODULE_NAME


def _is_glm_model(model):
    return str(model or "").lower().startswith("glm-")


def _is_deepseek_model(model):
    return str(model or "").lower().startswith("deepseek-")


def _generation_count(explicit_count=None, architecture_variants=False):
    if explicit_count is not None:
        return max(int(explicit_count), 1)
    if architecture_variants:
        return ARCHITECTURE_VARIANT_DEFAULT_COUNT
    return DEFAULT_VARIANT_COUNT


def _generation_style_hint(style, architecture_variants=False):
    hint = _STYLE_HINTS.get(style, _STYLE_HINTS["mixed"])
    if architecture_variants:
        hint = hint + "\n\n" + _ARCHITECTURE_VARIANTS_HINT
    return hint


def _op_handler_bindings(code):
    """Return literal OP_HANDLERS key-to-function bindings without importing code."""
    try:
        tree = ast.parse(code, filename="<executor-dedup>", mode="exec")
    except (SyntaxError, TypeError, ValueError):
        return {}, {}

    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    bindings = {}
    for node in tree.body:
        value = None
        targets = []
        if isinstance(node, ast.Assign):
            value = node.value
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            value = node.value
            targets = [node.target]
        if not any(isinstance(target, ast.Name) and target.id == "OP_HANDLERS" for target in targets):
            continue
        if not isinstance(value, ast.Dict):
            continue
        # A generated module may replace an earlier provisional mapping. Only
        # the final literal assignment represents its exported operator set.
        bindings = {}
        for key_node, value_node in zip(value.keys, value.values):
            if not (
                isinstance(key_node, ast.Constant)
                and isinstance(key_node.value, str)
                and isinstance(value_node, ast.Name)
            ):
                continue
            bindings[key_node.value] = value_node.id
    return bindings, functions


def _handler_body_fingerprint(function_node):
    if function_node is None:
        return None
    # Exclude the function name so a copied handler renamed by the model still
    # collides. Arguments and implementation remain part of the fingerprint.
    payload = ast.dump(
        ast.Module(
            body=[
                ast.FunctionDef(
                    name="_handler",
                    args=function_node.args,
                    body=function_node.body,
                    decorator_list=[],
                    returns=function_node.returns,
                    type_comment=getattr(function_node, "type_comment", None),
                )
            ],
            type_ignores=[],
        ),
        annotate_fields=True,
        include_attributes=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _operator_registry(code, excluded_operator_names=None):
    excluded = set(excluded_operator_names or ())
    bindings, functions = _op_handler_bindings(code)
    names = []
    fingerprints = {}
    for operator_name in sorted(bindings):
        if operator_name in excluded:
            continue
        names.append(operator_name)
        fingerprint = _handler_body_fingerprint(functions.get(bindings[operator_name]))
        if fingerprint:
            fingerprints.setdefault(fingerprint, operator_name)
    return {
        "operator_names": names,
        "fingerprints": fingerprints,
    }


def _merge_operator_registries(target, source):
    target_names = set(target.get("operator_names") or ())
    target_names.update(source.get("operator_names") or ())
    target["operator_names"] = sorted(target_names)
    target_fingerprints = target.setdefault("fingerprints", {})
    for fingerprint, operator_name in (source.get("fingerprints") or {}).items():
        target_fingerprints.setdefault(fingerprint, operator_name)
    return target


def _same_style_dedup_hint(operator_names):
    names = sorted({str(name) for name in operator_names or () if str(name)})
    if not names:
        return ""
    compact_names = json.dumps(names, ensure_ascii=True, separators=(",", ":"))
    return (
        f"\n\nPrior NEW handlers in this style: {compact_names}. Do not reuse these names "
        "or equivalent bodies; use different mutation targets or strategies. Shared "
        "reference helpers, dispatchers, and handlers are allowed."
    )


def _validate_same_style_dedup(code, reference_operator_names, previous_registry):
    candidate = _operator_registry(code, excluded_operator_names=reference_operator_names)
    previous_names = set((previous_registry or {}).get("operator_names") or ())
    duplicate_names = sorted(previous_names.intersection(candidate["operator_names"]))

    previous_fingerprints = (previous_registry or {}).get("fingerprints") or {}
    duplicate_bodies = []
    for fingerprint, candidate_name in candidate["fingerprints"].items():
        previous_name = previous_fingerprints.get(fingerprint)
        if previous_name is not None:
            duplicate_bodies.append((candidate_name, previous_name))

    if not duplicate_names and not duplicate_bodies:
        return True, None, candidate

    details = []
    if duplicate_names:
        details.append("reused operator names=" + ",".join(duplicate_names))
    if duplicate_bodies:
        pairs = sorted({f"{new}={old}" for new, old in duplicate_bodies})
        details.append("copied handler bodies=" + ",".join(pairs))
    return (
        False,
        "same-style duplicate mutation handlers: " + "; ".join(details),
        candidate,
    )


def _architecture_variant_slot_hint(index=None, count=None):
    if index is None or count is None:
        return ""
    index = max(int(index), 1)
    count = max(int(count), index)
    return (
        f"Architecture variant slot: {index} of {count}.  Select one coherent target "
        "architecture variant that is meaningfully different from the reference "
        "configuration and from variants likely selected for other slots.  Use only "
        "targets supported by the reference executor or verified feature context.  Keep "
        "the selected target internally consistent throughout this generated executor."
    )


def _normalize_architecture_target(target):
    if not isinstance(target, dict):
        return None
    target_id = str(
        target.get("id")
        or target.get("architecture")
        or target.get("name")
        or ""
    ).strip().lower()
    if not target_id:
        return None
    word_size = target.get("word_size", target.get("width", target.get("bits", "")))
    try:
        word_size = int(word_size)
        if word_size <= 0:
            return None
    except (TypeError, ValueError):
        word_size = str(word_size or "").strip().lower()
        if not word_size:
            return None
    byte_order = str(
        target.get("byte_order")
        or target.get("endianness")
        or target.get("endian")
        or ""
    ).strip().lower()
    if not byte_order:
        return None
    abi = str(target.get("abi") or "").strip().lower()
    return {
        "id": target_id,
        "word_size": word_size,
        "byte_order": byte_order,
        "abi": abi,
    }


def _architecture_target_key(target):
    normalized = _normalize_architecture_target(target)
    if normalized is None:
        return None
    return json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _validate_architecture_op_metadata(module, expected_architecture_target):
    metadata = getattr(module, "ARCHITECTURE_OP_METADATA", None)
    if not isinstance(metadata, dict) or not metadata:
        return False, (
            "architecture variant module missing non-empty "
            "ARCHITECTURE_OP_METADATA dict"
        )

    handlers = getattr(module, "OP_HANDLERS", {})
    expected_key = _architecture_target_key(expected_architecture_target)
    role_counts = {
        "architecture_transition": 0,
        "target_repair": 0,
    }
    for op_name, declaration in metadata.items():
        if not isinstance(op_name, str) or not op_name:
            return False, "ARCHITECTURE_OP_METADATA keys must be non-empty strings"
        if op_name not in handlers or not callable(handlers.get(op_name)):
            return False, (
                f"ARCHITECTURE_OP_METADATA references missing or non-callable "
                f"operator {op_name!r}"
            )
        if not isinstance(declaration, dict):
            return False, (
                f"ARCHITECTURE_OP_METADATA[{op_name!r}] must be a dict"
            )
        role = declaration.get("role")
        if role not in role_counts:
            return False, (
                f"ARCHITECTURE_OP_METADATA[{op_name!r}].role must be "
                "'architecture_transition' or 'target_repair'"
            )
        declared_target = _normalize_architecture_target(
            declaration.get("architecture_target")
        )
        if _architecture_target_key(declared_target) != expected_key:
            return False, (
                f"ARCHITECTURE_OP_METADATA[{op_name!r}].architecture_target "
                "does not match ARCHITECTURE_TARGET"
            )
        role_counts[role] += 1

    missing_roles = sorted(
        role for role, count in role_counts.items()
        if count <= 0
    )
    if missing_roles:
        return False, (
            "ARCHITECTURE_OP_METADATA missing required roles: "
            + ", ".join(missing_roles)
        )
    return True, None


def _validate_op_handler_signatures(handlers):
    for op_name, handler in handlers.items():
        if not isinstance(op_name, str) or not op_name:
            return False, "OP_HANDLERS keys must be non-empty strings"
        if not callable(handler):
            return False, f"OP_HANDLERS[{op_name!r}] must be callable"
        try:
            inspect.signature(handler).bind(bytearray(), {}, {}, 1048576)
        except (TypeError, ValueError) as e:
            return False, (
                f"OP_HANDLERS[{op_name!r}] must accept runtime arguments "
                f"(buf, op, profile, max_size): {e}"
            )
    return True, None


def _architecture_exclusion_hint(targets):
    normalized = []
    seen = set()
    for target in targets or []:
        item = _normalize_architecture_target(target)
        key = _architecture_target_key(item)
        if item is not None and key not in seen:
            normalized.append(item)
            seen.add(key)
    if not normalized:
        return ""
    return (
        "Previously selected architecture targets that MUST NOT be selected again: "
        + json.dumps(normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + ". Select a target with a different normalized id, word_size, byte_order, or abi."
    )


def _module_url_for_model(model, explicit_url=None):
    if _is_glm_model(model):
        return None
    return explicit_url or os.environ.get("MODULE_URL") or DEFAULT_MODULE_URL


def _resolve_api_key(model):
    if _is_glm_model(model):
        return (
            os.environ.get("ZHIPU_API_KEY")
            or os.environ.get("GLM_API_KEY")
            or os.environ.get("OPENAI_API_KEY")
        )
    return os.environ.get("OPENAI_API_KEY")


def _create_client(model, module_url=None, api_key=None, timeout=120):
    module_url = _module_url_for_model(model, module_url)
    if _is_glm_model(model):
        try:
            from zhipuai import ZhipuAI
        except ImportError:
            raise ImportError("zhipuai package required for GLM models; pip install zhipuai")
        return ZhipuAI(api_key=api_key)
    if OpenAI is None:
        raise ImportError("openai package required; pip install openai")
    kwargs = {
        "api_key": api_key,
        "base_url": module_url,
        "timeout": timeout,
    }
    # httpx rejects the commonly used "socks://" alias while parsing proxy
    # environment variables. If an HTTP(S) proxy is available too, select it
    # explicitly so an invalid ALL_PROXY value cannot prevent client creation.
    all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy") or ""
    http_proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    if all_proxy.lower().startswith("socks://") and http_proxy and httpx is not None:
        kwargs["http_client"] = httpx.Client(proxy=http_proxy, timeout=timeout)
    return OpenAI(**kwargs)


def _build_completion_kwargs(model, system_prompt, user_prompt, temperature=0.2,
                             max_tokens=65536, top_p=0.95):
    kwargs = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if _is_glm_model(model):
        kwargs["thinking"] = {"type": "disabled"}
    else:
        kwargs.update({
            "response_format": {"type": "json_object"},
            "top_p": top_p,
            "stream": False,
            "stop": None,
            "frequency_penalty": 0,
            "presence_penalty": 0,
        })
        if _is_deepseek_model(model):
            kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    return kwargs


def _response_content(response):
    try:
        return (response.choices[0].message.content or "").strip()
    except (AttributeError, IndexError, TypeError):
        return ""


def _response_finish_reason(response):
    try:
        return response.choices[0].finish_reason
    except (AttributeError, IndexError, TypeError):
        return None


def _response_usage(response):
    return response_usage(response)


def extract_json(text):
    text = text.strip()
    for fence in ("```json", "```python", "```"):
        if text.startswith(fence):
            text = text[len(fence):]
            if text.endswith("```"):
                text = text[:-3]
            text = text.strip()
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except (json.JSONDecodeError, ValueError):
                    return None
    return None


_FORBIDDEN_TOKENS = [
    "subprocess", "socket", "os.system", "__import__",
    "eval(", "exec(", "compile(", "pprint(",
    "pickle", "marshal", "shelve", "dbm",
]
_IMPORT_PACKAGE_ALIASES = {
    "PIL": "Pillow",
    "cv2": "opencv-python",
    "yaml": "PyYAML",
    "Crypto": "pycryptodome",
    "bs4": "beautifulsoup4",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "magic": "python-magic",
}
_REQUIRED_TOPLEVEL_NAMES = [
    "MAX_OUTPUT_SIZE", "DEFAULT_PLAN", "OP_HANDLERS",
    "execute_template_plan", "mutate",
]
_REQUIRED_FUNCTIONS = ["execute_template_plan", "mutate"]


def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return bool(default)
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _auto_install_enabled():
    return _env_flag(AUTO_INSTALL_MODULES_ENV, default=True)


def _auto_install_max_attempts():
    try:
        return max(int(os.environ.get(AUTO_INSTALL_MAX_ATTEMPTS_ENV, "5")), 0)
    except (TypeError, ValueError):
        return 5


def _auto_install_timeout():
    try:
        return max(float(os.environ.get(AUTO_INSTALL_PIP_TIMEOUT_ENV, "120")), 1.0)
    except (TypeError, ValueError):
        return 120.0


def _extra_package_aliases():
    raw = os.environ.get(AUTO_INSTALL_PACKAGE_MAP_ENV)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {
        str(key).strip(): str(value).strip()
        for key, value in parsed.items()
        if str(key).strip() and str(value).strip()
    }


def _missing_module_name(exc):
    module_name = getattr(exc, "name", None)
    if not module_name:
        match = re.search(r"No module named ['\"]([^'\"]+)['\"]", str(exc))
        if match:
            module_name = match.group(1)
    if not module_name:
        return None
    return str(module_name).split(".")[0]


def _package_for_import(module_name):
    aliases = dict(_IMPORT_PACKAGE_ALIASES)
    aliases.update(_extra_package_aliases())
    return aliases.get(module_name, module_name)


def _valid_package_spec(package):
    return bool(re.match(r"^[A-Za-z0-9_.\-\[\],:~!=<>]+$", str(package or "")))


def _pip_install_package(package):
    if not _valid_package_spec(package):
        return False, f"refusing invalid package spec {package!r}"
    cmd = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
    ]
    extra_args = os.environ.get(AUTO_INSTALL_PIP_ARGS_ENV)
    if extra_args:
        cmd.extend(shlex.split(extra_args))
    cmd.append(package)
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=_auto_install_timeout(),
            check=False,
        )
    except Exception as exc:
        return False, f"pip install {package!r} failed to start: {exc}"
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-1000:]
        return False, f"pip install {package!r} exited {proc.returncode}: {detail}"
    importlib.invalidate_caches()
    return True, f"installed {package}"


def _install_missing_module(exc, attempted):
    if not _auto_install_enabled():
        return False, f"auto install disabled by {AUTO_INSTALL_MODULES_ENV}=0"
    module_name = _missing_module_name(exc)
    if not module_name:
        return False, f"could not determine missing module from {exc}"
    if module_name in attempted:
        return False, f"already attempted installation for missing module {module_name!r}"
    attempted.add(module_name)
    package = _package_for_import(module_name)
    print(
        f"[template-expander] missing module {module_name!r}; installing {package!r}",
        file=sys.stderr,
    )
    return _pip_install_package(package)


def _run_with_missing_module_install(action, attempted=None):
    attempted = attempted if attempted is not None else set()
    remaining = _auto_install_max_attempts()
    while True:
        try:
            return action()
        except ModuleNotFoundError as exc:
            if remaining <= 0:
                raise
            ok, message = _install_missing_module(exc, attempted)
            if not ok:
                raise RuntimeError(message) from exc
            remaining -= 1


def _load_module_from_path(module_path, module_name, attempted=None):
    def load_once():
        sys.modules.pop(module_name, None)
        spec = importlib.util.spec_from_file_location(module_name, module_path)
        if spec is None or spec.loader is None:
            raise ImportError(f"could not load module spec for {module_path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    return _run_with_missing_module_install(load_once, attempted=attempted)


class _ForbiddenCallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.function_stack = []
        self.error = None

    def visit_FunctionDef(self, node):
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)

    def visit_Call(self, node):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id == "print"
            and self.function_stack != ["main"]
        ):
            self.error = "forbidden print() outside main"
            return
        self.generic_visit(node)


def _validate_code(code):
    if not isinstance(code, str) or len(code) < 200:
        return False, "code too short or not a string"
    for token in _FORBIDDEN_TOKENS:
        if token in code:
            return False, f"forbidden token: {token}"
    try:
        tree = ast.parse(code, filename="<executor>", mode="exec")
    except SyntaxError as e:
        return False, f"syntax error: {e}"
    call_visitor = _ForbiddenCallVisitor()
    call_visitor.visit(tree)
    if call_visitor.error:
        return False, call_visitor.error
    ok, error = validate_template_memory_safety(code)
    if not ok:
        return False, error
    for name in _REQUIRED_TOPLEVEL_NAMES:
        if name not in code:
            return False, f"missing required top-level name: {name}"
    for fn in _REQUIRED_FUNCTIONS:
        pattern = rf"def\s+{fn}\s*\("
        if not re.search(pattern, code):
            return False, f"missing required function: {fn}"
    return True, None


def _validate_executor_module(code, sample_data=None, expected_architecture_target=None):
    ok, error = _validate_code(code)
    if not ok:
        return False, error
    tmp_dir = tempfile.mkdtemp(prefix="template_expander_")
    module_path = os.path.join(tmp_dir, "test_executor.py")
    attempted_installs = set()
    try:
        with open(module_path, "w", encoding="utf-8") as f:
            f.write(code)
        module = _load_module_from_path(
            module_path,
            "_test_executor",
            attempted=attempted_installs,
        )
    except Exception as e:
        return False, f"import error: {e}"
    finally:
        try:
            os.unlink(module_path)
            os.rmdir(tmp_dir)
        except OSError:
            pass
    for attr in ("MAX_OUTPUT_SIZE", "DEFAULT_PLAN",
                 "OP_HANDLERS", "execute_template_plan", "mutate"):
        if not hasattr(module, attr):
            return False, f"missing module attribute: {attr}"
    if expected_architecture_target is not None:
        expected_key = _architecture_target_key(expected_architecture_target)
        module_target = _normalize_architecture_target(
            getattr(module, "ARCHITECTURE_TARGET", None)
        )
        if module_target is None:
            return False, "architecture variant module missing ARCHITECTURE_TARGET dict"
        if _architecture_target_key(module_target) != expected_key:
            return False, (
                "module ARCHITECTURE_TARGET does not match response architecture_target"
            )
        ok, error = _validate_architecture_op_metadata(module, module_target)
        if not ok:
            return False, error
    handlers = getattr(module, "OP_HANDLERS", {})
    if not isinstance(handlers, dict) or len(handlers) < 8:
        return False, f"OP_HANDLERS must have at least 8 entries, got {len(handlers) if isinstance(handlers, dict) else 'N/A'}"
    ok, error = _validate_op_handler_signatures(handlers)
    if not ok:
        return False, error
    if sample_data is not None:
        try:
            plan = getattr(module, "DEFAULT_PLAN", None)
            result = _run_with_missing_module_install(
                lambda: module.execute_template_plan(sample_data, plan, None, 1048576),
                attempted=attempted_installs,
            )
            if result is None or not isinstance(result, (bytes, bytearray)):
                return False, "execute_template_plan returned None or non-bytes on sample data"
        except Exception as e:
            return False, f"execute_template_plan failed on sample data: {e}"
    return True, None


def load_feature_context(feature_pool_path=None, seed_features_path=None):
    if not feature_pool_path and not seed_features_path:
        return None
    context = {"features": []}
    pool_features = {}
    if feature_pool_path and os.path.isfile(feature_pool_path):
        try:
            with open(feature_pool_path, "r", encoding="utf-8") as f:
                pool = json.load(f)
            features = pool.get("features", pool) if isinstance(pool, dict) else pool
            if isinstance(features, dict):
                # Native G2FUZZ writes {feature_name: description_string}.
                # Keep its names while also accepting the structured pool schema.
                features = [
                    {"id": name, "description": value}
                    if isinstance(value, str) else value
                    for name, value in features.items()
                ]
            for feat in features:
                if not isinstance(feat, dict):
                    continue
                fid = feat.get("id", "").strip("* ")
                desc = feat.get("description", "").strip()
                status = feat.get("status", "unknown")
                if not fid or not desc:
                    continue
                pool_features[fid] = {
                    "id": fid,
                    "description": desc,
                    "status": status,
                    "seeds": feat.get("seed_count", 0),
                    "finds": 0,
                }
        except (OSError, json.JSONDecodeError):
            pass
    if seed_features_path and os.path.isfile(seed_features_path):
        try:
            with open(seed_features_path, "r", encoding="utf-8") as f:
                sf = json.load(f)
            runtime_features = sf.get("features", sf)
            if isinstance(runtime_features, dict):
                runtime_features = list(runtime_features.values())
            for feat in runtime_features:
                if not isinstance(feat, dict):
                    continue
                fid = feat.get("feature_id", feat.get("id", "")).strip("* ")
                finds = feat.get("finds", 0)
                seeds = feat.get("seed_count", 0)
                desc = feat.get("description", "").strip()
                if fid in pool_features:
                    pool_features[fid]["finds"] = finds
                    pool_features[fid]["seeds"] = max(
                        pool_features[fid]["seeds"], seeds
                    )
                elif desc:
                    pool_features[fid] = {
                        "id": fid,
                        "description": desc,
                        "status": feat.get("status", "unknown"),
                        "seeds": seeds,
                        "finds": finds,
                    }
        except (OSError, json.JSONDecodeError):
            pass
    context["features"] = sorted(
        pool_features.values(),
        key=lambda f: (f["finds"], f["seeds"]),
        reverse=True,
    )
    return context


def _build_feature_prompt(context):
    if not context:
        return ""
    parts = []
    high_impact = [f for f in context["features"] if f["finds"] > 0]
    constructible = [
        f for f in context["features"]
        if f["finds"] == 0 and f["status"] == "success"
    ]
    failed = [f for f in context["features"] if f["status"] == "failed"]
    unverified = [
        f for f in context["features"]
        if f["finds"] == 0 and f["status"] not in {"success", "failed"}
    ]
    if high_impact:
        parts.append("\n## High-Impact Structural Features\n")
        parts.append(
            "The following structural features have been observed to trigger new "
            "execution paths in the target program during fuzzing. Treat them as "
            "high-priority semantic targets across applicable operator roles.\n"
        )
        for feat in high_impact:
            parts.append(
                f"- **{feat['id']}** (finds={feat['finds']}, seeds={feat['seeds']}): "
                f"{feat['description']}"
            )
        parts.append("")
    if constructible:
        parts.append("## Verified Structural Features\n")
        parts.append(
            "These features have verified examples but have not yet demonstrated "
            "coverage gains. Use them as lower-priority semantic targets for applicable "
            "operator roles.\n"
        )
        for feat in constructible:
            parts.append(
                f"- **{feat['id']}** (seeds={feat['seeds']}): "
                f"{feat['description']}"
            )
        parts.append("")
    if failed:
        parts.append("## Features with Validation Difficulties\n")
        parts.append(
            "These features were identified but could not be fully validated. Use them "
            "only for bounded partial states, exploration of existing evidence, or "
            "incremental restoration of dependencies.\n"
        )
        for feat in failed:
            parts.append(f"- **{feat['id']}**: {feat['description']}")
        parts.append("")
    if unverified:
        parts.append("## Unverified Structural Features\n")
        parts.append(
            "These features have not yet been verified. Use them cautiously and do not "
            "assume that a complete valid representation is currently available.\n"
        )
        for feat in unverified:
            parts.append(f"- **{feat['id']}**: {feat['description']}")
        parts.append("")
    if high_impact or constructible or failed or unverified:
        parts.append("## Feature-Aware Operator Guidance\n")
        parts.append(
            "Use the feature descriptions above as semantic guidance. Derive every "
            "concrete representation, location, size, encoding, and relationship from "
            "the reference executor's profile, constants, helpers, and available "
            "evidence. Do not assume any particular format, named field, fixed location, "
            "or architecture.\n"
            "\n"
            "For each relevant feature, consider complementary operators from these "
            "roles when sufficient structural evidence is available:\n"
            "\n"
            "- **construct**: create the smallest coherent representation and initialize "
            "the relationships required for recognition.\n"
            "\n"
            "- **explore/mutate**: keep the feature reachable while varying one meaningful "
            "property, boundary, relationship, or content value at a time.\n"
            "\n"
            "- **controlled-desync**: intentionally violate exactly one relationship or "
            "invariant while preserving unrelated structure.\n"
            "\n"
            "- **repair/sync**: restore one violated relationship or invariant from current "
            "evidence or a known-good profile. Pair a focused desync operator with a "
            "corresponding repair operator when feasible.\n"
            "\n"
            "Each feature-aware operator must be narrowly scoped and must verify that its "
            "required evidence or containing structure is available. Follow the requested "
            "style when choosing the role mix. Prefer high-impact features, but do not "
            "duplicate existing handlers or force every feature into every role.\n"
        )
    return "\n".join(parts)


def load_template(path):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"template not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def load_sample_data(path=None):
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            return f.read()
    return b""


def generate_from_template(input_path, style="mixed", module_name=None,
                            module_url=None, api_key=None, temperature=0.25,
                            max_tokens=65536, retries=2, retry_delay=5.0,
                            timeout=120, sample_data=None,
                            feature_pool_path=None,
                            seed_features_path=None,
                            architecture_variants=False,
                            architecture_variant_index=None,
                            architecture_variant_count=None,
                            architecture_variant_excluded_targets=None,
                            previous_style_operator_registry=None):
    metrics = GenerationMetrics("load_template_prompt_llm_retries_validation")
    input_code = load_template(input_path)
    reference_registry = _operator_registry(input_code)
    module_name = _normalize_model_name(module_name or os.environ.get("MODULE_NAME"))
    api_key = api_key or _resolve_api_key(module_name)
    if not api_key:
        raise ValueError("no API key available; set OPENAI_API_KEY")

    style_hint = _generation_style_hint(style, architecture_variants)
    if architecture_variants:
        slot_hint = _architecture_variant_slot_hint(
            architecture_variant_index,
            architecture_variant_count,
        )
        if slot_hint:
            style_hint = style_hint + "\n\n" + slot_hint
        exclusion_hint = _architecture_exclusion_hint(
            architecture_variant_excluded_targets
        )
        if exclusion_hint:
            style_hint = style_hint + "\n\n" + exclusion_hint

    feature_context = load_feature_context(
        feature_pool_path=feature_pool_path,
        seed_features_path=seed_features_path,
    )
    feature_prompt = _build_feature_prompt(feature_context)

    system_prompt = _SYSTEM_PROMPT
    if feature_prompt:
        system_prompt = system_prompt + feature_prompt

    user_prompt = _USER_PROMPT_TEMPLATE.format(
        input_code=input_code,
        style_name=style,
        style_hint=style_hint,
    )
    user_prompt += _same_style_dedup_hint(
        (previous_style_operator_registry or {}).get("operator_names")
    )

    client = _create_client(module_name, module_url=module_url, api_key=api_key, timeout=timeout)
    last_error = None
    last_content = ""

    for attempt in range(retries + 1):
        if attempt > 0 and retry_delay > 0:
            time.sleep(retry_delay)
        try:
            kwargs = _build_completion_kwargs(
                module_name, system_prompt, user_prompt,
                temperature=temperature, max_tokens=max_tokens,
            )
            response = metrics.call(client.chat.completions.create, **kwargs)
            content = _response_content(response)
            if not content:
                last_error = "empty response from LLM"
                continue

            parsed = extract_json(content)
            if parsed is None:
                finish = _response_finish_reason(response)
                if finish == "length":
                    last_error = "response truncated by max_tokens"
                else:
                    last_error = "response did not contain a valid JSON object"
                last_content = content
                continue

            code = parsed.get("code", "")
            if not code:
                last_error = "JSON response missing 'code' field"
                last_content = content
                continue

            architecture_target = None
            if architecture_variants:
                architecture_target = _normalize_architecture_target(
                    parsed.get("architecture_target")
                )
                if architecture_target is None:
                    last_error = (
                        "validation failed: architecture variant response missing "
                        "valid architecture_target"
                    )
                    last_content = content
                    user_prompt += (
                        "\n\nYour previous attempt failed validation:\n"
                        "architecture variant response must include a valid "
                        "architecture_target object with canonical id, word_size, "
                        "byte_order, and abi keys.\n"
                        "Please choose a supported target and output a corrected JSON object."
                    )
                    continue
                excluded_keys = {
                    _architecture_target_key(target)
                    for target in (architecture_variant_excluded_targets or [])
                }
                target_key = _architecture_target_key(architecture_target)
                if target_key in excluded_keys:
                    last_error = (
                        "validation failed: duplicate architecture_target "
                        f"{target_key}"
                    )
                    last_content = content
                    user_prompt += (
                        "\n\nYour previous attempt failed validation:\n"
                        f"duplicate architecture_target {target_key}. "
                        "Select a different supported architecture target and output "
                        "a corrected JSON object."
                    )
                    continue

            ok, error = _validate_executor_module(
                code,
                sample_data=sample_data,
                expected_architecture_target=architecture_target,
            )
            if not ok:
                last_error = f"validation failed: {error}"
                last_content = content
                user_prompt += (
                    f"\n\nYour previous attempt failed validation:\n{error}\n"
                    "Please fix and output a corrected JSON object."
                )
                continue

            ok, error, candidate_registry = _validate_same_style_dedup(
                code,
                reference_registry["operator_names"],
                previous_style_operator_registry,
            )
            if not ok:
                last_error = f"validation failed: {error}"
                last_content = content
                user_prompt += (
                    f"\n\nYour previous attempt failed validation:\n{error}\n"
                    "Replace the duplicated NEW handlers with different mutation targets "
                    "or strategies and output a corrected JSON object."
                )
                continue

            parsed["code"] = code
            parsed.setdefault("kind", "format_template_executor_code")
            parsed.setdefault("version", 1)
            parsed.setdefault("format", "infer")
            parsed.setdefault("name", style)
            parsed["input_template"] = os.path.basename(input_path)
            parsed["style"] = style
            parsed["same_style_dedup"] = {
                "previous_operator_count": len(
                    (previous_style_operator_registry or {}).get("operator_names") or ()
                ),
                "new_operator_names": candidate_registry["operator_names"],
            }
            parsed["architecture_variants"] = bool(architecture_variants)
            if parsed["architecture_variants"]:
                parsed["architecture_target"] = architecture_target
                parsed["architecture_variant_index"] = architecture_variant_index
                parsed["architecture_variant_count"] = architecture_variant_count
            parsed["_llm"] = {
                "model": module_name,
                "base_url": _module_url_for_model(module_name, module_url),
                "usage": _response_usage(response),
                "metrics": metrics.snapshot(),
            }
            return parsed

        except Exception as e:
            last_error = str(e)[:500]
            continue

    snippet = last_content[:500].replace("\n", "\\n") if last_content else ""
    failure = RuntimeError(
        f"failed to generate executor after {retries + 1} attempts: {last_error}; "
        f"response_prefix={snippet!r}"
    )
    failure.generation_metrics = metrics.snapshot()
    raise failure


def save_executor(template, output_dir=None):
    output_dir = output_dir or _format_executor_dir()
    os.makedirs(output_dir, exist_ok=True)
    code = template["code"]
    digest = hashlib.sha256(code.encode("utf-8")).hexdigest()[:12]
    name = re.sub(r"[^a-zA-Z0-9_]", "_", template.get("name", "expanded"))[:48]
    filename = f"{name}_{digest}.py"
    json_path = os.path.join(output_dir, f"{name}_{digest}.json")
    code_path = os.path.join(output_dir, filename)
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(template, f, ensure_ascii=False, indent=2, sort_keys=True)
    with open(code_path, "w", encoding="utf-8") as f:
        f.write(code)
    return {"json": json_path, "code": code_path, "sha256": hashlib.sha256(code.encode("utf-8")).hexdigest()}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extend a template executor via LLM and write validated output"
    )
    parser.add_argument("inputs", nargs="+", metavar="INPUT",
                        help="path(s) to input template .py file(s)")
    parser.add_argument("--style", default=None,
                        help="generation style: conservative_repair, aggressive_explore, "
                             "offset_shift, header_extreme, string_table, mixed, "
                             "constructor (default: mixed)")
    parser.add_argument(
        "--count",
        type=int,
        default=None,
        help=(
            "number of variants to generate per input template "
            "(default: 5 with architecture variants, 1 otherwise)"
        ),
    )
    parser.add_argument(
        "--architecture-variants",
        action="store_true",
        help=(
            "add architecture-variant generation guidance to the selected style "
            "(also changes the default count to 5)"
        ),
    )
    parser.add_argument("--output-dir", default=None,
                        help=(
                            "output directory for generated executors; default uses "
                            f"${FORMAT_EXECUTOR_DIR_ENV}, then ${TEMPLATE_EXECUTOR_DIR_ENV}, "
                            f"then {FORMAT_EXECUTOR_DIR_NAME}"
                        ))
    parser.add_argument(
        "--timing-log",
        help=(
            "append template generation timing records to this JSONL file; "
            f"default uses ${TEMPLATE_TIMING_LOG_ENV}, then output-dir/{TEMPLATE_TIMING_LOG_NAME}"
        ),
    )
    parser.add_argument(
        "--no-timing-log",
        action="store_true",
        help="disable template generation timing log output",
    )
    parser.add_argument("--sample", default=None,
                        help="path to sample input file for validation")
    parser.add_argument("--model", default=None,
                        help="LLM model name (default: deepseek-chat)")
    parser.add_argument("--url", default=None,
                        help="LLM API base URL")
    parser.add_argument("--api-key", default=None,
                        help="LLM API key (default: OPENAI_API_KEY env)")
    parser.add_argument("--temperature", type=float, default=0.25)
    parser.add_argument("--max-tokens", type=int, default=65536)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=5.0)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--no-auto-install",
        action="store_true",
        help=(
            "disable automatic pip install for modules missing from generated "
            f"executors; equivalent to {AUTO_INSTALL_MODULES_ENV}=0"
        ),
    )
    parser.add_argument("--feature-pool", default=None,
                        help="path to feature_pool.json for feature-aware prompts")
    parser.add_argument("--seed-features", default=None,
                        help="path to seed_features.json for runtime coverage feedback")
    args = parser.parse_args(argv)

    if args.no_auto_install:
        os.environ[AUTO_INSTALL_MODULES_ENV] = "0"

    sample_data = load_sample_data(args.sample)
    styles = [args.style] if args.style else ["mixed"]
    results = []
    failed = []
    timing_log_path = _resolve_timing_log_path(
        args.timing_log,
        output_dir=args.output_dir,
        disabled=args.no_timing_log,
    )

    for input_path in args.inputs:
        for style in styles:
            architecture_variants = bool(args.architecture_variants)
            generation_count = _generation_count(
                args.count,
                architecture_variants=architecture_variants,
            )
            selected_architecture_targets = []
            reference_operator_names = _operator_registry(
                load_template(input_path)
            )["operator_names"]
            style_operator_registry = {"operator_names": [], "fingerprints": {}}
            for i in range(generation_count):
                modifier_label = (
                    "+architecture_variants"
                    if architecture_variants
                    else ""
                )
                label = f"{os.path.basename(input_path)}:{style}{modifier_label}" + (
                    f":{i+1}" if generation_count > 1 else ""
                )
                print(f"[template-expander] generating {label}", file=sys.stderr)
                started_at = time.time()
                timing_record = {
                    "version": 1,
                    "tool": "template_expander",
                    "event": "template_expansion",
                    "timer_scope": "load_template_prompt_llm_validation_save",
                    "input_template": os.path.abspath(input_path),
                    "sample": os.path.abspath(args.sample) if args.sample else None,
                    "feature_pool": os.path.abspath(args.feature_pool) if args.feature_pool else None,
                    "seed_features": os.path.abspath(args.seed_features) if args.seed_features else None,
                    "style": style,
                    "index": i + 1,
                    "count": generation_count,
                    "architecture_variants": architecture_variants,
                    "model": _normalize_model_name(args.model),
                    "base_url": _module_url_for_model(args.model, args.url),
                    "output_dir": os.path.abspath(args.output_dir) if args.output_dir else _format_executor_dir(),
                    "retries": args.retries,
                    "retry_delay": args.retry_delay,
                    "max_tokens": args.max_tokens,
                    "timeout": args.timeout,
                    "started_at": started_at,
                    "started_at_utc": _timestamp_utc(started_at),
                }
                result_entry = None
                failed_entry = None
                try:
                    template = generate_from_template(
                        input_path=input_path,
                        style=style,
                        module_name=args.model,
                        module_url=args.url,
                        api_key=args.api_key,
                        temperature=args.temperature,
                        max_tokens=args.max_tokens,
                        retries=args.retries,
                        retry_delay=args.retry_delay,
                        timeout=args.timeout,
                        sample_data=sample_data,
                        feature_pool_path=args.feature_pool,
                        seed_features_path=args.seed_features,
                        architecture_variants=architecture_variants,
                        architecture_variant_index=i + 1 if architecture_variants else None,
                        architecture_variant_count=generation_count if architecture_variants else None,
                        architecture_variant_excluded_targets=selected_architecture_targets,
                        previous_style_operator_registry=style_operator_registry,
                    )
                    add_metrics_to_timing_record(timing_record, template.get("_llm", {}).get("metrics"))
                    paths = save_executor(template, output_dir=args.output_dir)
                    generated_registry = _operator_registry(
                        template.get("code", ""),
                        excluded_operator_names=reference_operator_names,
                    )
                    _merge_operator_registries(style_operator_registry, generated_registry)
                    if architecture_variants:
                        selected_architecture_targets.append(
                            dict(template["architecture_target"])
                        )
                    code = template.get("code", "")
                    op_count = 0
                    try:
                        mod_path = paths["code"]
                        mod = _load_module_from_path(mod_path, "_count_ops")
                        op_count = len(getattr(mod, "OP_HANDLERS", {}))
                    except Exception:
                        op_count = code.count("def ") - 2
                    print(
                        f"[template-expander] saved {label}: "
                        f"code={paths['code']} ops={op_count}",
                        file=sys.stderr,
                    )
                    timing_record["paths"] = paths
                    timing_record["op_count"] = op_count
                    timing_record["architecture_target"] = template.get("architecture_target")
                    timing_record["dedup_new_operator_names"] = generated_registry["operator_names"]
                    timing_record["dedup_seen_operator_count"] = len(
                        style_operator_registry["operator_names"]
                    )
                    result_entry = {
                        "input": input_path, "style": style, "index": i + 1,
                        "architecture_variants": architecture_variants,
                        "architecture_target": template.get("architecture_target"),
                        "status": "ok", "paths": paths, "op_count": op_count,
                        "llm": template.get("_llm", {}),
                    }
                    results.append(result_entry)
                    _finish_timing_record(timing_record, "ok")
                except Exception as e:
                    add_metrics_to_timing_record(timing_record, getattr(e, "generation_metrics", None))
                    print(f"[template-expander] FAILED {label}: {e}", file=sys.stderr)
                    failed_entry = {
                        "input": input_path,
                        "style": style,
                        "architecture_variants": architecture_variants,
                        "index": i + 1,
                        "error": str(e),
                    }
                    failed.append(failed_entry)
                    _finish_timing_record(timing_record, "failed", error=e)
                finally:
                    if result_entry is not None:
                        result_entry["duration_sec"] = timing_record.get("duration_sec")
                    if failed_entry is not None:
                        failed_entry["duration_sec"] = timing_record.get("duration_sec")
                        failed_entry["llm_metrics"] = timing_record.get("llm_metrics")
                    _append_timing_record(timing_log_path, timing_record)

    report = {"results": results, "failed": failed, "timing_log": timing_log_path}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
