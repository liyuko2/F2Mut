#!/usr/bin/env python3
"""Adapter that runs G2FUZZ-style feature and generator synthesis in this tree.

The adapter intentionally keeps G2FUZZ's feature/generator interaction model:
feature discovery returns numbered text features, generator synthesis returns a
single Markdown code block, and generator mutation extends an existing generator
for a new feature. The surrounding storage, smoke validation, and AFL import
metadata are normalized to this repository's `generated_seed_data` layout.
"""

import contextlib
import ast
import importlib
import json
import os
import random
import re
import shutil
import sys
import time


DEFAULT_G2FUZZ_SOURCE_DIR = "third_party/g2fuzz"


def _base_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _short_error(exc, limit=600):
    text = str(exc)
    return text if len(text) <= limit else text[:limit] + "...<truncated>"


def _load_json_dict(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
            return payload if isinstance(payload, dict) else {}
    except (OSError, ValueError, json.JSONDecodeError):
        return {}


def _atomic_write_json(path, payload):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(payload if isinstance(payload, dict) else {}, f, indent=2, sort_keys=True)
        f.write("\n")
    os.replace(tmp_path, path)


def _g2fuzz_state_dir(output_dir):
    seed_data_dir = os.path.dirname(os.path.abspath(output_dir))
    return os.path.join(seed_data_dir, "g2fuzz")


def _update_g2fuzz_compat_state(output_dir, generator_id, py_path, candidate, seeds):
    """Mirror normalized results into G2FUZZ-style state files.

    G2FUZZ's mutation loop uses generators/, feature_programs.json and
    mutation_log/relationship.json as first-class state. Keeping these files in
    sync makes the adapter a thin compatibility layer instead of a disconnected
    prompt clone.
    """
    state_dir = _g2fuzz_state_dir(output_dir)
    generators_dir = os.path.join(state_dir, "generators")
    seeds_dir = os.path.join(state_dir, "gen_seeds")
    mutation_log_dir = os.path.join(state_dir, "mutation_log")
    os.makedirs(generators_dir, exist_ok=True)
    os.makedirs(seeds_dir, exist_ok=True)
    os.makedirs(mutation_log_dir, exist_ok=True)

    compat_generator_name = f"{generator_id}.py"
    compat_generator_path = os.path.join(generators_dir, compat_generator_name)
    try:
        shutil.copyfile(py_path, compat_generator_path)
    except OSError:
        with open(compat_generator_path, "w", encoding="utf-8") as f:
            f.write(candidate.get("generator_code") or "")

    feature_programs_path = os.path.join(state_dir, "feature_programs.json")
    feature_programs = _load_json_dict(feature_programs_path)
    primary_feature = str(candidate.get("primary_feature") or candidate.get("feature_id") or generator_id)
    feature_programs[primary_feature] = candidate.get("generator_code") or ""
    feature_ids = candidate.get("feature_ids") or []
    feature_names = candidate.get("features") or []
    for index, feature_id in enumerate(feature_ids):
        name = feature_names[index] if index < len(feature_names) else feature_id
        if name and name not in feature_programs:
            feature_programs[str(name)] = candidate.get("generator_code") or ""
    _atomic_write_json(feature_programs_path, feature_programs)

    relationship_path = os.path.join(mutation_log_dir, "relationship.json")
    relationship = _load_json_dict(relationship_path)
    parent_id = candidate.get("parent_generator_id")
    if parent_id and parent_id != generator_id:
        parent_name = f"{parent_id}.py"
        children = relationship.get(parent_name)
        if not isinstance(children, list):
            children = []
        if compat_generator_name not in children:
            children.append(compat_generator_name)
        relationship[parent_name] = children
        _atomic_write_json(relationship_path, relationship)
    elif not os.path.exists(relationship_path):
        _atomic_write_json(relationship_path, relationship)

    manifest_path = os.path.join(state_dir, "generators_manifest.json")
    manifest = _load_json_dict(manifest_path)
    items = manifest.setdefault("generators", {})
    items[generator_id] = {
        "generator_id": generator_id,
        "generator_py": os.path.relpath(compat_generator_path, state_dir),
        "format": candidate.get("format"),
        "feature_id": candidate.get("feature_id"),
        "feature_ids": list(candidate.get("feature_ids") or []),
        "features": list(candidate.get("features") or []),
        "primary_feature": candidate.get("primary_feature"),
        "generation_mode": candidate.get("generation_mode"),
        "generation_strategy": candidate.get("generation_strategy"),
        "mutation_source": candidate.get("mutation_source"),
        "parent_generator_id": parent_id,
        "seed_count": len(seeds or []),
        "seed_paths": [str(item.get("path")) for item in (seeds or []) if isinstance(item, dict) and item.get("path")],
        "updated_ts": int(time.time()),
    }
    manifest["updated_ts"] = int(time.time())
    _atomic_write_json(manifest_path, manifest)
    return {
        "state_dir": state_dir,
        "generator_py": compat_generator_path,
        "feature_programs": feature_programs_path,
        "relationship": relationship_path,
        "manifest": manifest_path,
    }


def rebuild_g2fuzz_compat_state(output_dir, metadata_path):
    """Rebuild G2FUZZ-style state from normalized seed metadata.

    Older runs may have valid `seed_features.json` and seed generator files but
    no G2FUZZ mirror directory. Rebuilding keeps feature iteration keyed off the
    same state files that G2FUZZ's mutation loop expects.
    """
    metadata = _load_json_dict(metadata_path)
    generators = metadata.get("generators")
    seeds = metadata.get("seeds")
    if not isinstance(generators, dict):
        generators = {}
    if not isinstance(seeds, dict):
        seeds = {}

    state_dir = _g2fuzz_state_dir(output_dir)
    generators_dir = os.path.join(state_dir, "generators")
    seeds_dir = os.path.join(state_dir, "gen_seeds")
    mutation_log_dir = os.path.join(state_dir, "mutation_log")
    os.makedirs(generators_dir, exist_ok=True)
    os.makedirs(seeds_dir, exist_ok=True)
    os.makedirs(mutation_log_dir, exist_ok=True)

    feature_programs = {}
    manifest = {"generators": {}, "updated_ts": int(time.time())}
    relationship = {}

    for generator_id, entry in sorted(generators.items()):
        if not isinstance(entry, dict):
            continue
        generator_id = str(entry.get("generator_id") or generator_id)
        py_path = os.path.join(output_dir, f"{generator_id}.py")
        code = ""
        if os.path.isfile(py_path):
            try:
                with open(py_path, "r", encoding="utf-8") as f:
                    code = f.read()
            except OSError:
                code = ""
            try:
                shutil.copyfile(py_path, os.path.join(generators_dir, f"{generator_id}.py"))
            except OSError:
                pass

        names = []
        primary = entry.get("primary_feature")
        if isinstance(primary, str) and primary:
            names.append(primary)
        for item in entry.get("features") or []:
            if isinstance(item, str) and item and item not in names:
                names.append(item)
        for item in entry.get("feature_ids") or []:
            if isinstance(item, str) and item and item not in names:
                names.append(item)
        for name in names:
            feature_programs.setdefault(str(name), code)

        seed_paths = []
        for seed_entry in seeds.values():
            if not isinstance(seed_entry, dict):
                continue
            if seed_entry.get("generator_id") != generator_id:
                continue
            path = seed_entry.get("path")
            if isinstance(path, str) and path:
                seed_paths.append(path)

        parent_id = entry.get("parent_generator_id")
        if isinstance(parent_id, str) and parent_id and parent_id != generator_id:
            parent_name = f"{parent_id}.py"
            child_name = f"{generator_id}.py"
            children = relationship.setdefault(parent_name, [])
            if child_name not in children:
                children.append(child_name)

        manifest["generators"][generator_id] = {
            "generator_id": generator_id,
            "generator_py": os.path.join("generators", f"{generator_id}.py"),
            "format": entry.get("format"),
            "feature_id": entry.get("feature_id"),
            "feature_ids": list(entry.get("feature_ids") or []),
            "features": list(entry.get("features") or []),
            "primary_feature": entry.get("primary_feature"),
            "generation_mode": entry.get("generation_mode"),
            "generation_strategy": entry.get("generation_strategy"),
            "mutation_source": entry.get("mutation_source"),
            "parent_generator_id": parent_id,
            "seed_count": len(seed_paths),
            "seed_paths": seed_paths,
            "updated_ts": int(entry.get("created_ts") or time.time()),
        }

    _atomic_write_json(os.path.join(state_dir, "feature_programs.json"), feature_programs)
    _atomic_write_json(os.path.join(mutation_log_dir, "relationship.json"), relationship)
    _atomic_write_json(os.path.join(state_dir, "generators_manifest.json"), manifest)
    return {
        "state_dir": state_dir,
        "feature_programs": os.path.join(state_dir, "feature_programs.json"),
        "relationship": os.path.join(mutation_log_dir, "relationship.json"),
        "manifest": os.path.join(state_dir, "generators_manifest.json"),
        "generator_count": len(manifest["generators"]),
        "feature_program_count": len(feature_programs),
    }


@contextlib.contextmanager
def _temporary_cwd(path):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(old)


def _g2fuzz_source_dir(source_dir=None):
    path = source_dir or os.environ.get("G2FUZZ_SOURCE_DIR") or DEFAULT_G2FUZZ_SOURCE_DIR
    if not os.path.isabs(path):
        path = os.path.join(_base_dir(), path)
    return os.path.abspath(path)


def _load_g2fuzz_modules(source_dir=None, model=None, module_url=None, api_key=None,
                         max_tokens=None, request_timeout=None, http_retries=None,
                         allow_pip_install=False):
    source_dir = _g2fuzz_source_dir(source_dir)
    if not os.path.isdir(source_dir):
        raise RuntimeError(f"G2FUZZ source dir not found: {source_dir}")
    if source_dir not in sys.path:
        sys.path.insert(0, source_dir)
    with _temporary_cwd(source_dir):
        program_gen = importlib.import_module("program_gen")
        generator_mutation = importlib.import_module("generator_mutation")
        g2func = importlib.import_module("py_utils.func")

    def llm_messages_bridge(request_model, messages, temperature):
        return _llm_messages_bridge(
            request_model or model,
            messages,
            temperature,
            module_url=module_url,
            api_key=api_key,
            max_tokens=max_tokens,
            request_timeout=request_timeout,
            http_retries=http_retries,
        )

    def llm_bridge(request_model, prompt, temperature):
        return llm_messages_bridge(request_model, [{"role": "user", "content": prompt}], temperature)

    g2func.llm_messages = llm_messages_bridge
    g2func.llm = llm_bridge
    if not allow_pip_install:
        g2func.pip_debug = lambda *_args, **_kwargs: 0

    # program_gen relies on `from py_utils.func import *` in its __main__ path.
    # When imported as a module we inject the same public names explicitly.
    for name in dir(g2func):
        if not name.startswith("_"):
            setattr(program_gen, name, getattr(g2func, name))
    program_gen.json = json
    program_gen.random = importlib.import_module("random")
    program_gen.time = time
    return {
        "source_dir": source_dir,
        "program_gen": program_gen,
        "generator_mutation": generator_mutation,
        "func": g2func,
    }


def _llm_messages_bridge(model, messages, temperature, module_url=None, api_key=None,
                         max_tokens=None,
                         request_timeout=None, http_retries=None):
    import seed_generator_builder as sgb

    model = sgb._normalize_model_name(model)
    api_key = sgb._api_key_for_model(model, api_key)
    timeout = float(request_timeout or os.environ.get("AFL_LLM_SEED_REQUEST_TIMEOUT", 60) or 60)
    retries = _safe_int(http_retries if http_retries is not None else os.environ.get("AFL_LLM_SEED_HTTP_RETRIES"), 0)
    client = sgb._create_client(
        model,
        api_key,
        timeout=timeout,
        max_retries=max(0, retries),
        module_url=module_url,
    )
    kwargs = {
        "model": model,
        "messages": messages,
        "temperature": float(temperature if temperature is not None else 0.7),
        "max_tokens": _safe_int(max_tokens if max_tokens is not None else os.environ.get("AFL_LLM_SEED_MAX_TOKENS"), 65536),
    }
    if sgb._is_glm_model(model):
        kwargs["thinking"] = {"type": "disabled"}
    elif sgb._is_deepseek_model(model):
        kwargs["extra_body"] = {"thinking": {"type": "disabled"}}
    if not sgb._is_glm_model(model):
        kwargs.update({
            "top_p": 0.95,
            "stream": False,
            "stop": None,
            "frequency_penalty": 0,
            "presence_penalty": 0,
        })
    with sgb.SerializedLLMRequest("g2fuzz-native", int(time.time())):
        response = client.chat.completions.create(**kwargs)
    return sgb._response_content(response)


def _parse_g2_feature_line(name, value=None, epoch=0):
    text = str(value if value is not None else name).strip()
    match = re.match(r"^\s*\d+\.\s*([^:]+?)\s*:\s*(.*)$", text)
    if match:
        feature_name = match.group(1).strip()
        description = match.group(2).strip() or text
    else:
        feature_name = str(name or "").strip()
        description = text
    import seed_generator_builder as sgb

    return {
        "id": sgb._feature_id_from_name(feature_name),
        "name": feature_name[:160],
        "description": description[:1200],
        "epoch_added": int(epoch or 0),
        "status": "pending",
        "source": "g2fuzz_native",
    }


def _known_feature_strings(feature_pool):
    lines = []
    for item in feature_pool or []:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("id") or "").strip()
        desc = str(item.get("description") or "").strip()
        if name:
            lines.append(f"{name}: {desc}" if desc else name)
    return lines


def request_g2fuzz_features(file_format, known_features=None, max_features=20,
                            model=None, module_url=None, api_key=None,
                            max_tokens=None, feature_attempts=3, request_timeout=None,
                            http_retries=None, source_dir=None):
    import seed_generator_builder as sgb

    resolved_model = sgb._normalize_model_name(model)
    modules = _load_g2fuzz_modules(
        source_dir=source_dir,
        model=resolved_model,
        module_url=module_url,
        api_key=api_key,
        max_tokens=max_tokens,
        request_timeout=request_timeout,
        http_retries=http_retries,
    )
    g2func = modules["func"]
    known_features = list(known_features or [])
    if known_features:
        messages = g2func.messages_for_feature_reask(file_format, str(known_features))
    else:
        messages = g2func.messages_for_feature(file_format)
    feature_map, raw_output = g2func.reask_for_feature(
        messages,
        g2func.extract_res_for_feature,
        max(1, int(feature_attempts or 1)),
        resolved_model,
        0.7,
    )
    if not feature_map:
        raise RuntimeError("G2FUZZ native feature discovery returned no features")
    features = []
    seen = set()
    for name, line in feature_map.items():
        feature = _parse_g2_feature_line(name, line)
        if feature["id"] in seen:
            continue
        seen.add(feature["id"])
        features.append(feature)
        if max_features and len(features) >= max(1, int(max_features)):
            break
    return features, raw_output, modules["source_dir"]


def _load_generator_code(output_dir, generator_id):
    if not generator_id:
        return None
    path = os.path.join(output_dir, f"{generator_id}.py")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def _load_compat_generator_code(output_dir, py_name):
    if not py_name:
        return None
    path = os.path.join(_g2fuzz_state_dir(output_dir), "generators", os.path.basename(py_name))
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError:
        generator_id = str(py_name)
        if generator_id.endswith(".py"):
            generator_id = generator_id[:-3]
        return _load_generator_code(output_dir, generator_id)


def _generator_id_from_py_name(name):
    text = str(name or "").strip()
    if text.endswith(".py"):
        text = text[:-3]
    return text


def _relationship_pattern_pairs(output_dir, generators, file_format, target_parent=None):
    relationship_path = os.path.join(_g2fuzz_state_dir(output_dir), "mutation_log", "relationship.json")
    relationship = _load_json_dict(relationship_path)
    if not relationship:
        return []
    pairs = []
    target_parent_id = target_parent.get("generator_id") if isinstance(target_parent, dict) else None
    for parent_name, children in relationship.items():
        parent_id = _generator_id_from_py_name(parent_name)
        parent_entry = generators.get(parent_id) if isinstance(generators, dict) else None
        if isinstance(parent_entry, dict) and str(parent_entry.get("format") or "").lower() != str(file_format or "").lower():
            continue
        if not isinstance(children, list):
            continue
        ori_code = _load_compat_generator_code(output_dir, parent_name)
        if not ori_code:
            continue
        for child_name in children:
            child_id = _generator_id_from_py_name(child_name)
            child_entry = generators.get(child_id) if isinstance(generators, dict) else None
            if isinstance(child_entry, dict) and str(child_entry.get("format") or "").lower() != str(file_format or "").lower():
                continue
            mut_code = _load_compat_generator_code(output_dir, child_name)
            if not mut_code:
                continue
            weight = 1.0
            if isinstance(child_entry, dict):
                weight += float(child_entry.get("finds", 0) or 0) * 4.0
                weight += float(child_entry.get("afl_import_accepted", 0) or 0) * 8.0
            if target_parent_id and target_parent_id == parent_id:
                weight += 2.0
            pairs.append({
                "original_generator_id": parent_id,
                "mutated_generator_id": child_id,
                "original_code": ori_code,
                "mutated_code": mut_code,
                "weight": weight,
                "source": "g2fuzz_relationship",
            })
    return pairs


def _select_pattern_pair(output_dir, metadata_path, file_format, target_parent=None):
    import seed_generator_builder as sgb

    metadata = sgb._load_json_dict(metadata_path)
    generators = metadata.get("generators", {}) if isinstance(metadata, dict) else {}
    if not isinstance(generators, dict):
        generators = {}
    pairs = _relationship_pattern_pairs(output_dir, generators, file_format, target_parent=target_parent)
    if pairs:
        weights = [max(0.1, item.get("weight", 1.0)) for item in pairs]
        try:
            return random.choices(pairs, weights=weights, k=1)[0]
        except Exception:
            return random.choice(pairs)
    for child_id, child in generators.items():
        if not isinstance(child, dict):
            continue
        if str(child.get("format") or "").lower() != str(file_format or "").lower():
            continue
        parent_id = child.get("parent_generator_id")
        if not parent_id or parent_id == child_id:
            continue
        parent = generators.get(parent_id)
        if not isinstance(parent, dict):
            continue
        ori_code = _load_generator_code(output_dir, parent_id)
        mut_code = _load_generator_code(output_dir, child_id)
        if not ori_code or not mut_code:
            continue
        weight = 1.0 + float(child.get("finds", 0) or 0) * 4.0
        if isinstance(target_parent, dict) and target_parent.get("generator_id") == parent_id:
            weight += 2.0
        pairs.append({
            "original_generator_id": parent_id,
            "mutated_generator_id": child_id,
            "original_code": ori_code,
            "mutated_code": mut_code,
            "weight": weight,
            "source": "seed_metadata_parent_child",
        })
    if not pairs:
        return None
    weights = [max(0.1, item.get("weight", 1.0)) for item in pairs]
    try:
        return random.choices(pairs, weights=weights, k=1)[0]
    except Exception:
        return random.choice(pairs)


def _g2_code_messages(prompt):
    return [
        {
            "role": "system",
            "content": (
                "You are an advanced Language Model assistant that can generate, "
                "execute, and evaluate code. Please use Markdown syntax to "
                "represent code blocks."
            ),
        },
        {"role": "user", "content": prompt},
    ]


def _generator_messages(modules, file_format, feature, parent_generator=None,
                        strategy="rare-feature", output_dir=None,
                        metadata_path=None):
    g2func = modules["func"]
    generator_mutation = modules["generator_mutation"]
    feature_name = str(feature.get("name") or feature.get("id") or "").strip()
    feature_description = str(feature.get("description") or feature_name).strip()
    meta = {
        "generation_strategy": strategy,
        "mutation_source": "g2fuzz_input_generator_synthesis",
    }
    if parent_generator and strategy == "pattern-combine" and output_dir and metadata_path:
        pattern = _select_pattern_pair(output_dir, metadata_path, file_format, parent_generator)
        if pattern:
            parent_code = str(parent_generator.get("generator_code") or "")
            prompt = generator_mutation.pattern_based_mutation_prompt
            prompt = prompt.replace("<ORI>", pattern["original_code"])
            prompt = prompt.replace("<MUT>", pattern["mutated_code"])
            prompt = prompt.replace("<TARGET_CODE>", parent_code)
            prompt += (
                "\n\nWhen applying this mutation pattern, prefer a generated "
                f"{file_format} file that also exercises this target feature if "
                f"compatible: {feature_name}: {feature_description}\n"
            )
            meta.update({
                "mutation_source": "g2fuzz_pattern_based_mutation",
                "pattern_original_generator_id": pattern["original_generator_id"],
                "pattern_mutated_generator_id": pattern["mutated_generator_id"],
                "pattern_source": pattern.get("source"),
            })
            return _g2_code_messages(prompt), meta
    if parent_generator and strategy == "feature-havoc":
        parent_code = str(parent_generator.get("generator_code") or "")
        prompt = generator_mutation.generator_mutation_feature_prompt_init
        prompt = prompt.replace("<FROMAT>", file_format)
        prompt = prompt.replace("<TARGET_GENERATOR>", parent_code)
        prompt += (
            "\n\nPrefer adding or strengthening this concrete file feature while "
            "keeping the output as one Python code block:\n"
            f"{feature_name}: {feature_description}\n"
        )
        meta["mutation_source"] = "g2fuzz_predefined_feature_mutation"
        return _g2_code_messages(prompt), meta
    if parent_generator and strategy == "structure-havoc":
        parent_code = str(parent_generator.get("generator_code") or "")
        prompt = generator_mutation.generator_mutation_structure_prompt_init
        prompt = prompt.replace("<FROMAT>", file_format)
        prompt = prompt.replace("<TARGET_GENERATOR>", parent_code)
        prompt += (
            "\n\nPrefer adding or strengthening parser-deep structure around "
            "this concrete target if compatible, while keeping the output as "
            "one Python code block:\n"
            f"{feature_name}: {feature_description}\n"
        )
        meta["mutation_source"] = "g2fuzz_predefined_structure_mutation"
        return _g2_code_messages(prompt), meta
    if parent_generator:
        parent_code = str(parent_generator.get("generator_code") or "")
        meta["mutation_source"] = "g2fuzz_rare_feature_directed_mutation"
        return g2func.messages_for_generator_mutation(
            file_format,
            feature_name,
            feature_description,
            parent_code,
        ), meta
    return g2func.messages_for_code_gen(file_format, f"{feature_name}: {feature_description}"), meta


def request_g2fuzz_generator_code(file_format, feature, parent_generator=None,
                                  model=None, module_url=None, api_key=None,
                                  max_tokens=None, attempts=3, self_debug_attempts=3,
                                  request_timeout=None, http_retries=None,
                                  source_dir=None, work_dir=None,
                                  strategy="rare-feature", output_dir=None,
                                  metadata_path=None):
    import seed_generator_builder as sgb

    resolved_model = sgb._normalize_model_name(model)
    modules = _load_g2fuzz_modules(
        source_dir=source_dir,
        model=resolved_model,
        module_url=module_url,
        api_key=api_key,
        max_tokens=max_tokens,
        request_timeout=request_timeout,
        http_retries=http_retries,
    )
    g2func = modules["func"]
    messages, mutation_meta = _generator_messages(
        modules,
        file_format,
        feature,
        parent_generator,
        strategy=strategy,
        output_dir=output_dir,
        metadata_path=metadata_path,
    )
    code = g2func.reask(
        messages,
        g2func.extract_res_for_code_gen,
        max(1, int(attempts or 1)),
        0.7,
        resolved_model,
    )
    if not code:
        raise RuntimeError("G2FUZZ native generator synthesis returned no code")
    work_dir = work_dir or os.path.join(_base_dir(), "generated_seed_data", "g2fuzz", "debug_work")
    os.makedirs(os.path.join(work_dir, "tmp"), exist_ok=True)
    repaired = g2func.self_debug(
        code,
        max(1, int(self_debug_attempts or 1)),
        resolved_model,
        temperature=0.2,
        output_path=work_dir,
    )
    if not repaired:
        raise RuntimeError("G2FUZZ native self_debug failed to produce executable code")
    return repaired, modules["source_dir"], mutation_meta


def _candidate_from_g2fuzz_code(file_format, feature, code, parent_generator=None, epoch=0,
                                generation_mode="initial", mutation_meta=None):
    import seed_generator_builder as sgb

    feature_name = str(feature.get("name") or feature.get("id") or "feature").strip()
    feature_id = sgb._feature_id_from_name(feature.get("id") or feature_name)
    feature_ids = [feature_id]
    feature_names = [feature_name]
    if parent_generator:
        for value in parent_generator.get("feature_ids") or []:
            fid = sgb._feature_id_from_name(value)
            if fid and fid not in feature_ids:
                feature_ids.append(fid)
        for value in parent_generator.get("features") or []:
            text = str(value or "").strip()
            if text and text not in feature_names:
                feature_names.append(text)
    generation_mode = "mutation" if generation_mode == "mutation" else "initial"
    mutation_meta = mutation_meta if isinstance(mutation_meta, dict) else {}
    generation_strategy = (
        mutation_meta.get("generation_strategy")
        or ("mutation" if generation_mode == "mutation" else "initial")
    )
    mutation_source = (
        mutation_meta.get("mutation_source")
        or (
            "g2fuzz_generator_mutation"
            if generation_mode == "mutation"
            else "g2fuzz_input_generator_synthesis"
        )
    )
    code = _sanitize_g2fuzz_generator_code(code)
    candidate = {
        "version": 1,
        "kind": sgb.GENERATOR_KIND,
        "format": str(file_format or "elf").lower(),
        "feature_id": feature_id,
        "primary_feature_id": feature_id,
        "primary_feature": feature_name[:200],
        "feature_description": str(feature.get("description") or "").strip()[:1200],
        "features": feature_names,
        "feature_ids": feature_ids,
        "generator_code": code.strip() + "\n",
        "expected_outputs": [],
        "generation_mode": generation_mode,
        "generation_strategy": generation_strategy,
        "mutation_source": mutation_source,
        "parent_generator_id": (parent_generator or {}).get("generator_id"),
        "epoch": int(epoch or 0),
        "source": "g2fuzz_native",
    }
    for key in (
        "pattern_original_generator_id",
        "pattern_mutated_generator_id",
        "pattern_source",
    ):
        if mutation_meta.get(key):
            candidate[key] = mutation_meta[key]
    return candidate


class _G2FuzzGeneratorSanitizer(ast.NodeTransformer):
    """Drop noisy/non-essential statements from G2FUZZ-generated scripts."""

    removable_expr_calls = {"print", "os.chmod"}

    @staticmethod
    def _ensure_body(node):
        if hasattr(node, "body") and not node.body:
            node.body = [ast.Pass()]
        if hasattr(node, "orelse") and node.orelse == []:
            node.orelse = []
        if hasattr(node, "finalbody") and node.finalbody == []:
            node.finalbody = []
        return node

    def visit_Expr(self, node):
        node = self.generic_visit(node)
        value = getattr(node, "value", None)
        if isinstance(value, ast.Call):
            name = _ast_call_name(value.func)
            leaf = name.rsplit(".", 1)[-1] if name else ""
            if name in self.removable_expr_calls or leaf == "print":
                return None
        return node

    def visit_FunctionDef(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_AsyncFunctionDef(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_ClassDef(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_If(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_For(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_While(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_With(self, node):
        return self._ensure_body(self.generic_visit(node))

    def visit_Try(self, node):
        node = self.generic_visit(node)
        self._ensure_body(node)
        for handler in getattr(node, "handlers", []) or []:
            if not handler.body:
                handler.body = [ast.Pass()]
        return node


def _ast_call_name(func):
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        base = _ast_call_name(func.value)
        return f"{base}.{func.attr}" if base else func.attr
    return ""


def _sanitize_g2fuzz_generator_code(code):
    text = str(code or "").strip()
    if not text:
        return text
    try:
        tree = ast.parse(text, filename="<g2fuzz_generator>")
    except SyntaxError:
        return text
    tree = _G2FuzzGeneratorSanitizer().visit(tree)
    ast.fix_missing_locations(tree)
    try:
        return ast.unparse(tree).strip() + "\n"
    except Exception:
        return text


def build_one_g2fuzz_generator(file_format, input_summary, executor, output_dir,
                               seeds_output, metadata_path, feature,
                               max_files, max_size, timeout_sec,
                               model=None, module_url=None, api_key=None,
                               max_tokens=None, attempts=3, self_debug_attempts=3,
                               request_timeout=None, http_retries=None,
                               parent_generator=None, epoch=0,
                               smoke_mode="auto", source_dir=None,
                               generation_mode="initial", strategy="rare-feature"):
    import seed_generator_builder as sgb

    work_dir = os.path.join(os.path.dirname(os.path.abspath(output_dir)), "g2fuzz_debug_work")
    code, source, mutation_meta = request_g2fuzz_generator_code(
        file_format,
        feature,
        parent_generator=parent_generator,
        model=model,
        module_url=module_url,
        api_key=api_key,
        max_tokens=max_tokens,
        attempts=attempts,
        self_debug_attempts=self_debug_attempts,
        request_timeout=request_timeout,
        http_retries=http_retries,
        source_dir=source_dir,
        work_dir=work_dir,
        strategy=strategy,
        output_dir=output_dir,
        metadata_path=metadata_path,
    )
    candidate = _candidate_from_g2fuzz_code(
        file_format,
        feature,
        code,
        parent_generator=parent_generator,
        epoch=epoch,
        generation_mode=generation_mode,
        mutation_meta=mutation_meta,
    )
    generator_id, seeds = sgb.run_generator(
        candidate,
        executor,
        seeds_output,
        metadata_path,
        input_summary,
        max_files,
        max_size,
        timeout_sec,
        smoke_mode=smoke_mode,
    )
    py_path, json_path = sgb.save_generator(output_dir, candidate, generator_id, input_summary, seeds)
    compat_state = _update_g2fuzz_compat_state(output_dir, generator_id, py_path, candidate, seeds)
    return {
        "generator_id": generator_id,
        "generator_py": py_path,
        "generator_json": json_path,
        "g2fuzz_compat": compat_state,
        "seeds": seeds,
        "candidate": candidate,
        "attempt": 1,
        "failures": [],
        "g2fuzz_source_dir": source,
    }


def build_g2fuzz_native_generators(file_format, input_summary, executor, output_dir,
                                   seeds_output, metadata_path, feature_pool_path,
                                   max_files, max_size, timeout_sec,
                                   model=None, module_url=None, api_key=None,
                                   max_tokens=None, attempts=3,
                                   feature_attempts=3, epochs=3,
                                   max_features=20, request_timeout=None,
                                   http_retries=None, smoke_mode="auto",
                                   source_dir=None):
    import seed_generator_builder as sgb

    epochs = max(1, int(epochs or 1))
    max_features = max(1, int(max_features or 20))
    feature_pool = []
    results = []
    failures = []
    raw_feature_outputs = []
    target_selections = []
    parent_selections = []

    for epoch in range(epochs):
        remaining = max_features - len(feature_pool)
        if remaining > 0:
            try:
                new_features, raw_output, source = request_g2fuzz_features(
                    file_format,
                    known_features=_known_feature_strings(feature_pool),
                    max_features=remaining,
                    model=model,
                    module_url=module_url,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    feature_attempts=feature_attempts,
                    request_timeout=request_timeout,
                    http_retries=http_retries,
                    source_dir=source_dir,
                )
                raw_feature_outputs.append(raw_output)
                feature_pool = sgb._merge_feature_pool(feature_pool, new_features, max_features)
                sgb.save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
            except Exception as exc:
                failures.append({"epoch": epoch, "stage": "g2fuzz_feature", "error": _short_error(exc)})
                if epoch == 0 and not feature_pool:
                    raise

        pending = [item for item in feature_pool if item.get("status") not in {"success", "failed"}]
        epoch_targets = list(pending)
        epoch_target_selection = {
            "epoch": epoch,
            "source": "pending_features",
            "selected": [
                {
                    "feature_id": item.get("id"),
                    "state": item.get("status"),
                    "reasons": ["pending_initial_generator"],
                }
                for item in epoch_targets
            ],
            "candidate_count": len(epoch_targets),
        }
        parents = []
        parent = None
        generation_mode = "initial"
        strategy = "initial"
        if epoch > 0:
            parents = sgb._load_parent_generators(output_dir, metadata_path, file_format)
            seed_dir = os.path.dirname(os.path.abspath(metadata_path))
            parent, parent_selection = _weighted_parent_generator(parents, seed_dir)
            if parent is None:
                parent = sgb._choose_parent_generator(parents)
                parent_selection = {
                    "source": "legacy_parent_fallback",
                    "selected": {"generator_id": (parent or {}).get("generator_id")},
                    "candidate_count": len(parents),
                }
            parent_selection["epoch"] = epoch
            parent_selections.append(parent_selection)
            if parent:
                generation_mode = "mutation"
                strategy = "feature-havoc" if epoch % 2 else "structure-havoc"
                if not epoch_targets:
                    epoch_targets, epoch_target_selection = _weighted_sample_features(
                        feature_pool,
                        seed_dir,
                        max(1, min(len(feature_pool) or 1, max_files or 1)),
                        parent_generator=parent,
                    )
                    epoch_target_selection["epoch"] = epoch
            else:
                strategy = "initial"
        if epoch_targets:
            target_selections.append(epoch_target_selection)
        for feature in epoch_targets:
            try:
                result = build_one_g2fuzz_generator(
                    file_format,
                    input_summary,
                    executor,
                    output_dir,
                    seeds_output,
                    metadata_path,
                    feature,
                    max_files,
                    max_size,
                    timeout_sec,
                    model=model,
                    module_url=module_url,
                    api_key=api_key,
                    max_tokens=max_tokens,
                    attempts=attempts,
                    self_debug_attempts=attempts,
                    request_timeout=request_timeout,
                    http_retries=http_retries,
                    parent_generator=parent,
                    epoch=epoch,
                    smoke_mode=smoke_mode,
                    source_dir=source_dir,
                    generation_mode=generation_mode,
                    strategy=strategy,
                )
                result["target_selection"] = epoch_target_selection
                feature["status"] = "success"
                feature["generator_id"] = result["generator_id"]
                sgb._mark_feature_metadata(
                    metadata_path,
                    file_format,
                    feature,
                    "success",
                    generator_id=result["generator_id"],
                )
                results.append(result)
            except Exception as exc:
                feature["status"] = "failed"
                feature["error"] = _short_error(exc)
                sgb._mark_feature_metadata(metadata_path, file_format, feature, "failed")
                failures.append({
                    "epoch": epoch,
                    "feature": feature.get("name"),
                    "stage": "g2fuzz_generator",
                    "error": feature["error"],
                })
            sgb.save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)

    if not results:
        raise RuntimeError(
            "G2FUZZ native mode failed to build any smoke-valid generator: "
            f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
        )
    return {
        "mode": "g2fuzz-native",
        "feature_pool": feature_pool,
        "results": results,
        "failures": failures,
        "raw_feature_outputs": raw_feature_outputs[-3:],
        "target_selections": target_selections[-8:],
        "parent_selections": parent_selections[-8:],
        "g2fuzz_source_dir": _g2fuzz_source_dir(source_dir),
    }


def _load_feature_scores_payload(seed_dir):
    path = os.path.join(seed_dir, "feature_scores.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _load_feature_scores_targets(seed_dir, key):
    payload = _load_feature_scores_payload(seed_dir)
    values = payload.get(key)
    return [str(item) for item in values] if isinstance(values, list) else []


def _feature_score_entry(payload, feature_id):
    features = payload.get("features") if isinstance(payload, dict) else {}
    if not isinstance(features, dict):
        return {}
    entry = features.get(feature_id)
    return entry if isinstance(entry, dict) else {}


def _safe_weight(value, default=1.0):
    try:
        weight = float(value)
    except (TypeError, ValueError):
        weight = default
    return max(0.05, weight)


def _safe_nonnegative(value, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        number = default
    return max(0.0, number)


def _weighted_parent_generator(parents, seed_dir):
    if not parents:
        return None, {"source": "feature_scores_parent", "candidate_count": 0}
    import seed_generator_builder as sgb

    payload = _load_feature_scores_payload(seed_dir)
    features = payload.get("features") if isinstance(payload, dict) else {}
    if not isinstance(features, dict):
        features = {}
    recommended = {
        sgb._feature_id_from_name(item)
        for item in (payload.get("recommended_seed_targets") or [])
        if isinstance(item, str) and item
    }
    parked = {
        sgb._feature_id_from_name(item)
        for item in (payload.get("parked_features") or [])
        if isinstance(item, str) and item
    }
    parent_feedback = payload.get("parent_generator_feedback")
    if not isinstance(parent_feedback, dict):
        parent_feedback = {}
    candidates = []
    for parent in parents:
        if not isinstance(parent, dict):
            continue
        generator_id = str(parent.get("generator_id") or "").strip()
        parent_ids = [
            sgb._feature_id_from_name(item)
            for item in (parent.get("feature_ids") or [])
            if isinstance(item, str) and item
        ]
        if not parent_ids:
            parent_ids = [
                sgb._feature_id_from_name(item)
                for item in (parent.get("features") or [])
                if isinstance(item, str) and item
            ]
        weight = 1.0
        reasons = []
        if any(feature_id in recommended for feature_id in parent_ids):
            weight *= 3.0
            reasons.append("contains_recommended_seed_feature")
        score_weights = []
        states = []
        for feature_id in parent_ids:
            entry = _feature_score_entry(payload, feature_id)
            if not isinstance(entry, dict):
                continue
            score_weights.append(_safe_weight(entry.get("weight"), 1.0))
            state = entry.get("state")
            if isinstance(state, str) and state:
                states.append(state)
        if score_weights:
            weight *= max(score_weights)
            reasons.append("feature_score_weight")
        if any(state in {"active", "exploit"} for state in states):
            weight *= 2.0
            reasons.append("contains_active_feature")
        if parent_ids and all(feature_id in parked for feature_id in parent_ids):
            weight *= 0.05
            reasons.append("all_features_parked")
        try:
            finds = int(parent.get("finds", 0) or 0)
        except (TypeError, ValueError):
            finds = 0
        if finds > 0:
            weight *= 1.0 + min(finds, 10)
            reasons.append("parent_has_finds")
        feedback = parent_feedback.get(generator_id)
        if isinstance(feedback, dict):
            feedback_score = _safe_nonnegative(feedback.get("score"), 0.0)
            if feedback_score > 0.0:
                weight *= 1.0 + min(feedback_score, 60.0) / 10.0
                reasons.append("parent_feedback_score")
            accepted = _safe_nonnegative(feedback.get("child_seed_accepted"), 0.0)
            if accepted > 0.0:
                weight *= 1.0 + min(accepted, 10.0)
                reasons.append("parent_child_seed_accepted")
            child_finds = _safe_nonnegative(feedback.get("child_generator_finds"), 0.0)
            if child_finds > 0.0:
                weight *= 1.0 + min(child_finds, 10.0)
                reasons.append("parent_child_finds")
            published = _safe_nonnegative(feedback.get("child_seed_published"), 0.0)
            if published >= 20.0 and accepted <= 0.0:
                weight *= 0.35
                reasons.append("parent_children_published_without_acceptance")
        try:
            calls = int(parent.get("stage_calls", 0) or 0)
        except (TypeError, ValueError):
            calls = 0
        weight /= 1.0 + calls * 0.02
        candidates.append({
            "parent": parent,
            "generator_id": generator_id or parent.get("generator_id"),
            "feature_ids": parent_ids,
            "weight": round(max(weight, 0.01), 4),
            "reasons": reasons,
        })
    if not candidates:
        return None, {"source": "feature_scores_parent", "candidate_count": 0}
    try:
        choice = random.choices(candidates, weights=[item["weight"] for item in candidates], k=1)[0]
    except Exception:
        choice = candidates[0]
    return choice["parent"], {
        "source": "feature_scores_parent",
        "selected": {
            "generator_id": choice.get("generator_id"),
            "feature_ids": choice.get("feature_ids"),
            "weight": choice.get("weight"),
            "reasons": choice.get("reasons") or [],
        },
        "candidate_count": len(candidates),
        "top_candidates": sorted(
            [
                {
                    "generator_id": item.get("generator_id"),
                    "feature_ids": item.get("feature_ids"),
                    "weight": item.get("weight"),
                    "reasons": item.get("reasons") or [],
                }
                for item in candidates
            ],
            key=lambda item: item["weight"],
            reverse=True,
        )[:8],
        "recommended_seed_targets": sorted(recommended)[:16],
        "parked_features": sorted(parked)[:16],
    }


def _weighted_sample_features(feature_pool, seed_dir, batch_size, parent_generator=None):
    import seed_generator_builder as sgb

    payload = _load_feature_scores_payload(seed_dir)
    recommended = [
        sgb._feature_id_from_name(item)
        for item in (payload.get("recommended_seed_targets") or [])
        if isinstance(item, str) and item
    ]
    recommended_set = set(recommended)
    parked = {
        sgb._feature_id_from_name(item)
        for item in (payload.get("parked_features") or [])
        if isinstance(item, str) and item
    }
    parent_ids = set()
    if isinstance(parent_generator, dict):
        parent_ids = {
            sgb._feature_id_from_name(item)
            for item in (parent_generator.get("feature_ids") or [])
            if isinstance(item, str) and item
        }
    by_id = {}
    for item in feature_pool or []:
        if not isinstance(item, dict):
            continue
        feature_id = sgb._feature_id_from_name(item.get("id") or item.get("name"))
        if feature_id and feature_id not in by_id:
            current = dict(item)
            current["id"] = feature_id
            by_id[feature_id] = current

    ordered_ids = [feature_id for feature_id in recommended if feature_id in by_id]
    for feature_id in sorted(by_id):
        if feature_id not in ordered_ids:
            ordered_ids.append(feature_id)

    candidates = []
    for feature_id in ordered_ids:
        if feature_id in parked:
            continue
        feature = by_id.get(feature_id)
        if not feature:
            continue
        score = _feature_score_entry(payload, feature_id)
        if score.get("state") == "parked":
            continue
        weight = _safe_weight(score.get("weight"), 1.0)
        reasons = []
        if feature_id in recommended_set:
            weight *= 3.0
            reasons.append("recommended_seed_target")
        if feature_id in parent_ids:
            weight *= 0.35
            reasons.append("already_in_parent")
        state = score.get("state")
        if state:
            reasons.append(f"state:{state}")
        candidates.append({
            "feature": feature,
            "feature_id": feature_id,
            "weight": round(weight, 4),
            "score_weight": score.get("weight"),
            "state": state,
            "reasons": reasons,
        })

    selected = []
    remaining = list(candidates)
    limit = max(1, int(batch_size or 1))
    while remaining and len(selected) < limit:
        weights = [item["weight"] for item in remaining]
        try:
            choice = random.choices(remaining, weights=weights, k=1)[0]
        except Exception:
            choice = remaining[0]
        selected.append(choice)
        remaining = [item for item in remaining if item["feature_id"] != choice["feature_id"]]

    if not selected:
        fallback = [
            {"feature": dict(item), "feature_id": sgb._feature_id_from_name(item.get("id") or item.get("name")),
             "weight": 1.0, "score_weight": None, "state": None, "reasons": ["fallback_no_feature_scores"]}
            for item in sgb._choose_incremental_features(feature_pool, limit, parent_generator)
            if isinstance(item, dict)
        ]
        selected = fallback

    return [item["feature"] for item in selected], {
        "source": "feature_scores_weighted",
        "recommended_seed_targets": recommended[:16],
        "parked_features": sorted(parked)[:16],
        "selected": [
            {
                "feature_id": item["feature_id"],
                "weight": item["weight"],
                "score_weight": item.get("score_weight"),
                "state": item.get("state"),
                "reasons": item.get("reasons") or [],
            }
            for item in selected
        ],
        "candidate_count": len(candidates),
    }


def build_g2fuzz_native_incremental(file_format, input_summary, executor, output_dir,
                                    seeds_output, metadata_path, feature_pool_path,
                                    max_files, max_size, timeout_sec,
                                    model=None, module_url=None, api_key=None,
                                    max_tokens=None, attempts=3,
                                    feature_attempts=3, request_timeout=None,
                                    http_retries=None, smoke_mode="auto",
                                    strategy="rare-feature", feature_batch=2,
                                    parent_generator="auto", candidate_json=None,
                                    source_dir=None):
    del candidate_json
    import seed_generator_builder as sgb

    feature_batch = max(1, int(feature_batch or 1))
    feature_pool = sgb._load_feature_pool(feature_pool_path, file_format)
    original_ids = {item.get("id") for item in feature_pool if isinstance(item, dict)}
    failures = []
    added_features = []
    raw_feature_outputs = []
    target_selection = {}
    if strategy == "rare-feature" or not feature_pool:
        try:
            new_features, raw_output, _source = request_g2fuzz_features(
                file_format,
                known_features=_known_feature_strings(feature_pool),
                max_features=feature_batch,
                model=model,
                module_url=module_url,
                api_key=api_key,
                max_tokens=max_tokens,
                feature_attempts=feature_attempts,
                request_timeout=request_timeout,
                http_retries=http_retries,
                source_dir=source_dir,
            )
            raw_feature_outputs.append(raw_output)
            feature_pool = sgb._merge_feature_pool(feature_pool, new_features, None)
            added_features = [
                item for item in feature_pool
                if item.get("id") not in original_ids
            ][:feature_batch]
            sgb.save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
        except Exception as exc:
            failures.append({"stage": "g2fuzz_incremental_feature", "error": _short_error(exc)})
            if not feature_pool:
                raise

    parents = sgb._load_parent_generators(output_dir, metadata_path, file_format)
    selected_parent = sgb._select_parent_by_id(parents, parent_generator)
    parent_selection = {}
    if selected_parent is None and parent_generator == "auto":
        seed_dir = os.path.dirname(os.path.abspath(metadata_path))
        selected_parent, parent_selection = _weighted_parent_generator(parents, seed_dir)
        if selected_parent is None:
            selected_parent = sgb._choose_parent_generator(parents)
            parent_selection = {
                "source": "legacy_parent_fallback",
                "selected": {"generator_id": (selected_parent or {}).get("generator_id")},
                "candidate_count": len(parents),
            }
    elif selected_parent is not None:
        parent_selection = {
            "source": "explicit_parent",
            "selected": {"generator_id": selected_parent.get("generator_id")},
            "candidate_count": len(parents),
        }

    if added_features:
        target_features = added_features
        target_selection = {
            "source": "new_rare_features",
            "selected": [
                {
                    "feature_id": item.get("id"),
                    "weight": None,
                    "score_weight": None,
                    "state": item.get("status"),
                    "reasons": ["new_feature"],
                }
                for item in added_features
            ],
            "candidate_count": len(added_features),
        }
    else:
        seed_dir = os.path.dirname(os.path.abspath(metadata_path))
        target_features, target_selection = _weighted_sample_features(
            feature_pool,
            seed_dir,
            feature_batch,
            parent_generator=selected_parent,
        )

    results = []
    for feature in target_features[:feature_batch]:
        generation_mode = "mutation" if selected_parent else "initial"
        try:
            result = build_one_g2fuzz_generator(
                file_format,
                input_summary,
                executor,
                output_dir,
                seeds_output,
                metadata_path,
                feature,
                max_files,
                max_size,
                timeout_sec,
                model=model,
                module_url=module_url,
                api_key=api_key,
                max_tokens=max_tokens,
                attempts=attempts,
                self_debug_attempts=attempts,
                request_timeout=request_timeout,
                http_retries=http_retries,
                parent_generator=selected_parent if generation_mode == "mutation" else None,
                epoch=int(time.time()),
                smoke_mode=smoke_mode,
                source_dir=source_dir,
                generation_mode=generation_mode,
                strategy=strategy,
            )
            feature["status"] = "success"
            feature["generator_id"] = result["generator_id"]
            sgb._mark_feature_metadata(
                metadata_path,
                file_format,
                feature,
                "success",
                generator_id=result["generator_id"],
            )
            results.append(result)
        except Exception as exc:
            failures.append({
                "feature": feature.get("name"),
                "stage": "g2fuzz_incremental_generator",
                "error": _short_error(exc),
            })
    sgb.save_feature_pool(feature_pool_path, file_format, input_summary, feature_pool)
    if not results and not failures:
        failures.append({"stage": "g2fuzz_incremental", "error": "no target features selected"})
    if not results:
        raise RuntimeError(
            "G2FUZZ native incremental mode failed to build any smoke-valid generator: "
            f"{json.dumps(failures, ensure_ascii=True, sort_keys=True)}"
        )
    return {
        "mode": "g2fuzz-native-incremental",
        "strategy": strategy,
        "feature_pool": feature_pool,
        "new_features": added_features,
        "results": results,
        "failures": failures,
        "parent_generator_id": (selected_parent or {}).get("generator_id"),
        "parent_selection": parent_selection,
        "target_selection": target_selection,
        "raw_feature_outputs": raw_feature_outputs[-3:],
        "g2fuzz_source_dir": _g2fuzz_source_dir(source_dir),
    }
