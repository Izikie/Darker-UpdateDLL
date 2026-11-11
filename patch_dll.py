#!/usr/bin/env python3
"""Patch resource data from extract_darker.py into a copy of a Hammer++ DLL.

Windows only. Dry run by default; --apply writes a separate patched DLL.
py patch_dll.py hammerplusplus_dll.dll patch_resources
py patch_dll.py hammerplusplus_dll.dll patch_resources --apply
Use --force only after manually checking resource ID compatibility.
"""
import argparse
import ctypes
import hashlib
import json
import shutil
import struct
from ctypes import wintypes
from pathlib import Path

RT_ICON, RT_BITMAP, RT_GROUP_ICON = 3, 2, 14


def get_resources(path):
    import pefile
    pe = pefile.PE(str(path))
    result = {}
    try:
        root = getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', None)
        if not root:
            raise ValueError('Target DLL has no resources')
        for t in root.entries:
            if t.name is not None:
                continue
            for n in t.directory.entries:
                if n.name is not None:
                    continue
                for lang in n.directory.entries:
                    meta = lang.data.struct
                    result[(t.id, n.id, lang.id)] = pe.get_data(meta.OffsetToData, meta.Size)
    finally:
        pe.close()
    return result


def bitmap_info(buf):
    if len(buf) < 16:
        return None
    header_size = struct.unpack_from('<I', buf)[0]
    if header_size == 12 and len(buf) >= 12:
        width, height, planes, bpp = struct.unpack_from('<HHHH', buf, 4)
        return width, height, bpp
    if header_size >= 40 and len(buf) >= 40:
        width, height, planes, bpp = struct.unpack_from('<iiHH', buf, 4)
        return abs(width), abs(height), bpp
    return None


def group_refs(raw):
    if len(raw) < 6:
        raise ValueError('Truncated group icon')
    reserved, kind, count = struct.unpack_from('<HHH', raw, 0)
    if reserved != 0 or kind != 1 or len(raw) != 6 + count * 14:
        raise ValueError('Invalid icon group')
    return [struct.unpack_from('<H', raw, 6 + i * 14 + 12)[0] for i in range(count)]


def win_update(path, modifications):
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    begin = kernel.BeginUpdateResourceW
    begin.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
    begin.restype = wintypes.HANDLE
    update = kernel.UpdateResourceW
    update.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, wintypes.WORD, ctypes.c_void_p, wintypes.DWORD]
    update.restype = wintypes.BOOL
    end = kernel.EndUpdateResourceW
    end.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    end.restype = wintypes.BOOL
    handle = begin(str(path.resolve()), False)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    committed = False
    try:
        for (typ, rid, lang), data in modifications.items():
            storage = ctypes.create_string_buffer(data)
            if not update(handle, ctypes.c_void_p(typ), ctypes.c_void_p(rid), lang, storage, len(data)):
                raise ctypes.WinError(ctypes.get_last_error())
        if not end(handle, False):
            raise ctypes.WinError(ctypes.get_last_error())
        committed = True
    finally:
        if not committed:
            end(handle, True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('target', type=Path, help='Unmodified/new Hammer++ DLL')
    ap.add_argument('assets', type=Path, help='Folder produced by extract_darker.py')
    ap.add_argument('--apply', action='store_true', help='Actually write a patched COPY')
    ap.add_argument('--force', action='store_true', help='Allow missing resource IDs or bitmap geometry mismatch (unsafe)')
    ap.add_argument('-o', '--output', type=Path, help='Output file (default: <target>.patched.dll)')
    args = ap.parse_args()
    if not hasattr(ctypes, 'WinDLL'):
        ap.error('Patching requires Windows (UpdateResourceW).')
    manifest = json.loads((args.assets / 'manifest.json').read_text(encoding='utf-8'))
    if manifest.get('format') != 1:
        raise ValueError('Unsupported manifest format')
    target = get_resources(args.target)
    incoming = {}
    for entry in manifest['resources']:
        key = entry['type'], entry['id'], entry['lang']
        raw = (args.assets / entry['file']).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry['sha256']:
            raise ValueError(f'Hash mismatch: {entry["file"]}')
        incoming[key] = raw
    changes = {}
    errors = []
    for key, raw in incoming.items():
        typ, rid, lang = key
        if typ != RT_BITMAP:
            continue
        previous = target.get(key)
        if previous is None and not args.force:
            errors.append(f'Bitmap {rid}, language {lang} missing from target')
            continue
        if previous is not None:
            old_info, new_info = bitmap_info(previous), bitmap_info(raw)
            if (old_info is None or new_info is None or old_info != new_info) and not args.force:
                errors.append(f'Bitmap {rid}: geometry/depth mismatch {old_info} vs {new_info}')
                continue
        if previous != raw:
            changes[key] = raw
    groups = {key: raw for key, raw in incoming.items() if key[0] == RT_GROUP_ICON}
    used_ids = {rid for (typ, rid, lang) in target if typ == RT_ICON}
    next_id = 1
    for key, raw in sorted(groups.items()):
        typ, group_id, lang = key
        if key not in target and not args.force:
            errors.append(f'Icon group {group_id}, language {lang} missing from target')
            continue
        new_group = bytearray(raw)
        linked = {}
        try:
            for i, old_id in enumerate(group_refs(raw)):
                match = (RT_ICON, old_id, lang)
                if match not in incoming:
                    candidates = [k for k in incoming if k[0] == RT_ICON and k[1] == old_id]
                    if len(candidates) != 1:
                        raise ValueError(f'Icon {old_id} not found uniquely in assets')
                    match = candidates[0]
                if match not in linked:
                    while next_id in used_ids:
                        next_id += 1
                    if next_id > 65535:
                        raise ValueError('No free icon IDs')
                    linked[match] = next_id
                    used_ids.add(next_id)
                    next_id += 1
                    changes[(RT_ICON, linked[match], lang)] = incoming[match]
                struct.pack_into('<H', new_group, 6 + i * 14 + 12, linked[match])
        except ValueError as exc:
            errors.append(f'Icon group {group_id}: {exc}')
            continue
        changes[key] = bytes(new_group)
    if errors:
        for error in errors:
            print('ERROR:', error)
        raise SystemExit('Aborted: incompatible resources. Nothing was written. Review IDs; --force is risky.')
    for key in sorted(changes):
        print(f'PATCH RT_{ {2:"BITMAP",3:"ICON",14:"GROUP_ICON"}[key[0]]} id={key[1]} lang={key[2]}')
    if not changes:
        print('No resource changes necessary.')
        return
    output = args.output or args.target.with_name(args.target.stem + '.patched.dll')
    if output.resolve() == args.target.resolve():
        raise SystemExit('Output must differ from target; this tool never overwrites the original')
    if output.exists():
        raise SystemExit(f'Output already exists: {output}')
    if not args.apply:
        print(f'DRY RUN. To write {output}, rerun with --apply.')
        return
    shutil.copy2(args.target, output)
    try:
        win_update(output, changes)
        verified = get_resources(output)
        for key, data in changes.items():
            if verified.get(key) != data:
                raise ValueError(f'Post-patch verification failed: {key}')
    except Exception:
        output.unlink(missing_ok=True)
        raise
    print(f'Patched copy written: {output.resolve()}')
    print('Resource IDs across Hammer++ versions are not guaranteed stable. Test this copy before relying on it.')

if __name__ == '__main__':
    main()
