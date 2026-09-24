"""Observe libzip descriptor inheritance using only a generated, harmless archive."""

import argparse
import ctypes
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile


def matching_descriptors(device, inode):
    matches = []
    for name in os.listdir('/proc/self/fd'):
        try:
            descriptor = int(name)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) == (device, inode):
                matches.append(descriptor)
        except OSError:
            pass
    return sorted(matches)


def child_observation(info):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), '--child',
         str(info.st_dev), str(info.st_ino)],
        close_fds=False, capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


def descriptor_is_closed(fd):
    try:
        os.fstat(fd)
    except OSError as error:
        if error.errno == errno.EBADF:
            return True
        raise
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--child', nargs=2, type=int)
    parser.add_argument('--library')
    parser.add_argument('--expect', choices=['exposed', 'protected'], default='exposed')
    args = parser.parse_args()
    if args.child:
        print(json.dumps(matching_descriptors(*args.child)))
        return
    lib = ctypes.CDLL(str(Path(args.library).resolve()), use_errno=True)
    lib.zip_fdopen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
    lib.zip_fdopen.restype = ctypes.c_void_p
    lib.zip_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
    lib.zip_open.restype = ctypes.c_void_p
    lib.zip_discard.argtypes = [ctypes.c_void_p]
    lib.zip_discard.restype = None
    lib.zip_fopen.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint]
    lib.zip_fopen.restype = ctypes.c_void_p
    lib.zip_fclose.argtypes = [ctypes.c_void_p]
    lib.zip_fclose.restype = ctypes.c_int
    report = {'expect': args.expect, 'cases': []}
    with tempfile.TemporaryDirectory(prefix='libzip-cloexec-') as directory:
        archive = Path(directory) / 'harmless.zip'
        invalid = Path(directory) / 'invalid.zip'
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_STORED) as writer:
            writer.writestr('sample.txt', 'This generated archive contains no user data.\n')
        invalid.write_bytes(b'Not an archive.\n')
        for method in ['zip_fdopen', 'zip_open']:
            error = ctypes.c_int(-1)
            original = os.open(archive, os.O_RDONLY | os.O_CLOEXEC)
            info = os.fstat(original)
            assert not os.get_inheritable(original)
            assert child_observation(info) == [], 'original descriptor leaked before libzip'
            if method == 'zip_fdopen':
                handle = lib.zip_fdopen(original, 0, ctypes.byref(error))
            else:
                os.close(original)
                handle = lib.zip_open(os.fsencode(archive), 0, ctypes.byref(error))
            assert handle, (method, error.value)
            entry = None
            try:
                if method == 'zip_fdopen':
                    assert descriptor_is_closed(original), 'ownership not transferred'
                entry = lib.zip_fopen(handle, b'sample.txt', 0)
                assert entry, method
                descriptors = matching_descriptors(info.st_dev, info.st_ino)
                assert len(descriptors) == 1, descriptors
                inherited = child_observation(info)
                flags = fcntl.fcntl(descriptors[0], fcntl.F_GETFD)
                report['cases'].append({'method': method, 'descriptorFlags': flags,
                                        'inheritedDescriptors': inherited})
                if method == 'zip_fdopen':
                    report['cases'][-1]['originalClosed'] = True
                should_leak = method == 'zip_fdopen' and args.expect == 'exposed'
                assert bool(inherited) == should_leak, report['cases'][-1]
                assert bool(flags & fcntl.FD_CLOEXEC) != should_leak, report['cases'][-1]
            finally:
                if entry:
                    assert lib.zip_fclose(entry) == 0
                lib.zip_discard(handle)
            assert matching_descriptors(info.st_dev, info.st_ino) == [], 'discard leaked fd'
        for filename, flags, expected_error in [(invalid, 0, 19), (archive, 1, 18)]:
            original = os.open(filename, os.O_RDONLY | os.O_CLOEXEC)
            info = os.fstat(original)
            error = ctypes.c_int(-1)
            try:
                handle = lib.zip_fdopen(original, flags, ctypes.byref(error))
                if handle:
                    lib.zip_discard(handle)
                    raise AssertionError('invalid input unexpectedly accepted')
                assert error.value == expected_error, error.value
                assert not descriptor_is_closed(original)
                assert not os.get_inheritable(original)
                assert matching_descriptors(info.st_dev, info.st_ino) == [original]
                assert child_observation(info) == []
                report['cases'].append({'method': 'zip_fdopen failure', 'flags': flags,
                                        'error': error.value, 'originalPreserved': True})
            finally:
                os.close(original)
        fd = os.open(archive, os.O_RDONLY)
        os.close(fd)
        error = ctypes.c_int(-1)
        assert not lib.zip_fdopen(fd, 0, ctypes.byref(error))
        assert error.value == 11, error.value
        report['cases'].append({'method': 'closed descriptor', 'error': error.value})
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
