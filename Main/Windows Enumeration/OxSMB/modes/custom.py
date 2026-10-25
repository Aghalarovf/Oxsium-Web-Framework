MODE_PROFILE = {
    "name": "custom",
    "threads": 10,
    "connect_timeout": 5.0,
    "read_timeout": 5.0,
    "retries": 1,
    "jitter_min": 0.0,
    "jitter_max": 0.0,
    "modules": [],
}


def build_profile(module_names, threads=None, connect_timeout=None, read_timeout=None, retries=None):
    profile = dict(MODE_PROFILE)
    profile["modules"] = list(module_names)
    if threads is not None:
        profile["threads"] = threads
    if connect_timeout is not None:
        profile["connect_timeout"] = connect_timeout
    if read_timeout is not None:
        profile["read_timeout"] = read_timeout
    if retries is not None:
        profile["retries"] = retries
    return profile
