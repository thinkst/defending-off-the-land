#!/usr/bin/env python3

# Script to generate a registry monitoring policy
# (C) 2024 Thinkst Applied Research, PTY.
# Author: Jacob Torrey

import toml, re, glob

def extract_registry_keys(query : str) -> list[str]:
    '''
    Extracts each mentioned registry key path from the TOML query
    Returns: List of extracted keys
    '''
    reg_path_re = re.compile(r'registry.path : \((?:\s|[^\)])*\)')
    quoted_re = re.compile(r'"(.*?)"')
    if re.search(reg_path_re, query) is None:
        return []
    raw_keys = re.findall(quoted_re, re.search(reg_path_re, query).group())
    keys = []
    for k in raw_keys:
        keys.append(re.sub(r'^MACHINE', 'HKLM', re.sub(r'^\\REGISTRY\\', '', k.replace("\\\\", "\\"))))
    return list(set(keys))

def load_toml_file(filename : str) -> dict:
    with open(filename) as fp:
        return toml.load(fp)

def get_registry_keys_to_watch(rules_dir : str = 'rules/rules/windows/') -> list[str]:
    toml_files = glob.glob(rules_dir + '*registry*.toml')
    keys = []
    for file in toml_files:
        r = load_toml_file(file)
        keys += extract_registry_keys(r['rule']['query'])
    return list(set(keys))