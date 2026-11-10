"""PLACEHOLDER: deterministic executor used only by offline integration tests."""

MAX_OUTPUT_SIZE = 1048576
DEFAULT_PROFILE = {}
DEFAULT_PLAN = {"ops": [{"op": "fixture_flip_0"}]}


def fixture_flip(buf, op, profile, max_size):
    if not buf:
        return False
    mask = 1 << int(op["op"][-1])
    buf[0] ^= mask
    return True


OP_HANDLERS = {
    "fixture_flip_0": fixture_flip,
    "fixture_flip_1": fixture_flip,
    "fixture_flip_2": fixture_flip,
    "fixture_flip_3": fixture_flip,
    "fixture_flip_4": fixture_flip,
    "fixture_flip_5": fixture_flip,
    "fixture_flip_6": fixture_flip,
    "fixture_flip_7": fixture_flip,
}


def execute_template_plan(data, plan=None, profile=None, max_size=None):
    if max_size is None:
        max_size = MAX_OUTPUT_SIZE
    buf = bytearray(data[:max_size])
    for op in (plan or DEFAULT_PLAN)["ops"]:
        OP_HANDLERS[op["op"]](buf, op, profile or DEFAULT_PROFILE, max_size)
    return bytes(buf[:max_size])


def mutate(data):
    return execute_template_plan(data)
