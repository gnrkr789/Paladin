"""Trusted launch adapter; imported project bytes remain untrusted."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import sys
import time
import types

sys.dont_write_bytecode = True

PIP_RUNTIME = '/opt/pip-runtime'
PIP_RUNTIME_VERSION = '23.2.1'
CHECKOUT = '/work/case/hgsource'
# Architecture, clone and clone3 numbers for supported seccomp targets.
SECCOMP_ARCHES = {'x86_64': (0xC000003E, 56, 435), 'aarch64': (0xC00000B7, 220, 435)}
CLONE_UNTRACED = 0x00800000


class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(SockFilter))]


def seccomp_program(machine):
    """Deny untraceable process creation; strace -f cannot follow it."""
    arch, clone, clone3 = SECCOMP_ARCHES[machine]
    load, jeq, jge, jset, ret = 0x20, 0x15, 0x35, 0x45, 0x06
    return [(load, 0, 0, 4),                  # 0: arch
            (jeq, 0, 7, arch),                # 1: foreign arch -> kill
            (load, 0, 0, 0),                  # 2: syscall number
            (jge, 5, 0, 0x40000000),          # 3: x32 ABI -> kill
            (jeq, 5, 0, clone3),              # 4: clone3 -> ENOSYS (flags are opaque)
            (jeq, 0, 2, clone),               # 5: not clone -> allow
            (load, 0, 0, 16),                 # 6: clone flags, low word
            (jset, 3, 0, CLONE_UNTRACED),     # 7: untraced -> EPERM
            (ret, 0, 0, 0x7FFF0000),          # 8: allow
            (ret, 0, 0, 0x80000000),          # 9: kill process
            (ret, 0, 0, 0x00050000 | 38),     # 10: ENOSYS
            (ret, 0, 0, 0x00050000 | 1)]      # 11: EPERM


def install_seccomp():
    machine = os.uname().machine
    if machine not in SECCOMP_ARCHES:
        raise RuntimeError('unsupported_seccomp_architecture')
    program = seccomp_program(machine)
    filters = (SockFilter * len(program))(*[SockFilter(*item) for item in program])
    fprog = SockFprog(len(program), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(22, 2, ctypes.byref(fprog), 0, 0) != 0:
        raise RuntimeError('seccomp_install_failed:' + str(ctypes.get_errno()))


def publish_pid():
    pending = Path('/work/target.pid.tmp')
    pending.write_text(str(os.getpid()), encoding='ascii')
    os.replace(pending, '/work/target.pid')


def cookiecutter(case):
    package = types.ModuleType('cookiecutter')
    package.__path__ = []
    exceptions = types.ModuleType('cookiecutter.exceptions')
    for name in ('RepositoryCloneFailed', 'RepositoryNotFound', 'UnknownRepoType', 'VCSNotInstalled'):
        setattr(exceptions, name, type(name, (Exception,), {}))
    utilities = types.ModuleType('cookiecutter.utils')
    utilities.make_sure_path_exists = lambda path: os.makedirs(path, exist_ok=True)
    utilities.prompt_and_delete = lambda *args, **kwargs: True
    sys.modules.update({'cookiecutter': package, 'cookiecutter.exceptions': exceptions,
                        'cookiecutter.utils': utilities})
    spec = importlib.util.spec_from_file_location('paladin_target_vcs', '/work/source.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.clone(case['kind'] + '+/fixtures/' + case['kind'] + 'source',
                 checkout=case['value'], clone_to_dir='/work/case', no_input=True)


def pip_mercurial(case):
    """Load supplied mercurial.py as pip._internal.vcs.mercurial on pinned pip internals."""
    if case['kind'] != 'hg':
        raise ValueError('unsupported_case_kind')
    sys.path.insert(0, PIP_RUNTIME)
    import pip
    if pip.__version__ != PIP_RUNTIME_VERSION or not pip.__file__.startswith(PIP_RUNTIME + '/'):
        raise RuntimeError('pip_runtime_mismatch')
    import pip._internal  # noqa: F401  initializes pip logging classes
    # Avoid the bundled vcs package initializer, which imports pip's own mercurial.py.
    vcs = types.ModuleType('pip._internal.vcs')
    vcs.__path__ = [PIP_RUNTIME + '/pip/_internal/vcs']
    sys.modules['pip._internal.vcs'] = vcs
    from pip._internal.utils.misc import HiddenText
    import pip._internal.vcs.versioncontrol  # noqa: F401
    name = 'pip._internal.vcs.mercurial'
    spec = importlib.util.spec_from_file_location(name, '/work/source.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    os.makedirs('/work/case', exist_ok=True)
    backend = module.Mercurial()
    backend.fetch_new(CHECKOUT, HiddenText('/fixtures/hgsource', redacted='****'),
                      module.Mercurial.make_rev_options(case['value']), verbosity=0)


ADAPTERS = {'cookiecutter': cookiecutter, 'pip-mercurial': pip_mercurial}


def main():
    install_seccomp()
    publish_pid()
    while not Path('/work/start').exists():
        time.sleep(0.01)
    case = json.loads(Path('/work/case.json').read_text(encoding='ascii'))
    adapter = Path('/work/adapter').read_text(encoding='ascii')
    if adapter not in ADAPTERS:
        raise ValueError('unsupported_adapter')
    ADAPTERS[adapter](case)


if __name__ == '__main__':
    main()
