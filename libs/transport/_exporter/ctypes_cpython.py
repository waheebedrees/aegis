# SPDX-License-Identifier: MIT
# Copyright (c) 2025-2026 Waheeb Edress ewaheeb02@gmail.com
"""
RFC 9266 TLS channel binding via ctypes.
Computes TLS exported keying material (EKM) by calling
``SSL_export_keying_material`` through ctypes, so asyncio users can obtain a
32-byte channel binding without switching the transport to pyOpenSSL.

References
----------
RFC 5705 — Keying Material Exporters for TLS
    https://www.rfc-editor.org/rfc/rfc5705
    Specifies the generic exporter API and the "label must not contain NUL"
    rule (§4) enforced by ``_coerce_bytes`` below.

RFC 8446 §7.5 — TLS 1.3 Exporters
    https://www.rfc-editor.org/rfc/rfc8446#section-7.5
    Defines how TLS 1.3 derives exporter values from the exporter_master_secret
    via two HKDF-Expand-Label steps. ``rfc8446_exporter`` in ``self_tests``
    implements this to verify our output independently of OpenSSL.

RFC 9266 — Channel Bindings for TLS 1.3 (tls-exporter)
    https://www.rfc-editor.org/rfc/rfc9266
    Fixes the label (``b"EXPORTER-Channel-Binding"``), the context (empty
    bytes, but with ``use_context=1``), and the length (32 bytes).

OpenSSL ``SSL_export_keying_material``
    https://www.openssl.org/docs/man3.0/man3/SSL_export_keying_material.html
    Signature and ``use_context`` semantics relied on by ``native_exporter``.

CPython ``Modules/_ssl.c`` — ``PySSLSocket`` layout
    https://github.com/python/cpython/blob/main/Modules/_ssl.c
    The struct layout ``{PyObject_HEAD; PyObject *Socket; SSL *ssl; ...}`` is
    what ``_SSL_PTR_OFFSET`` is derived from. This is NOT a stable ABI.

``SSL*`` extraction caveat
--------------------------
The offset into CPython's ``PySSLSocket`` is hardcoded. If a future CPython
release changes the struct layout, extraction will read garbage. The
``_sanity_check_ssl`` call after extraction catches most drift via
``SSL_is_init_finished`` and ``SSL_get_version`` — if those return
plausible values, the pointer is almost certainly a real ``SSL*``. There is
no stronger check available without a CPython-supported public API.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import ssl
import sys
import threading
from typing import Optional

log = logging.getLogger(__name__)

#
# RFC 9266 §3: label = "EXPORTER-Channel-Binding", context = "" (empty),
#              use_context = 1, length = 32.
# Do not change these without changing both peers.

RFC9266_LABEL = b"EXPORTER-Channel-Binding"
RFC9266_CONTEXT = b""
RFC9266_LENGTH = 32

# OpenSSL rejects length 0 (see SSL_export_keying_material man page); cap the
# upper bound to avoid absurd allocations from a caller-controlled length.
_MIN_LENGTH = 1
_MAX_LENGTH = 1 << 16

_LOAD_HINT = (
    "If this process links a non-system OpenSSL (pyenv, conda, nix, "
    "homebrew, statically-linked), set SPIFFETLS_LIBSSL_PATH to the full "
    "path of the libssl actually used by the ssl module."
)


class ChannelBindingError(Exception):
    """No mechanism could produce a binding, or the binding failed."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail

 
# libssl discovery
#
# The single biggest hazard here is loading a *different* libssl than the one
# CPython's _ssl module is using: the SSL* pointer we extract has been
# allocated by library A, and we call into library B. That is undefined
# behaviour and typically segfaults.
#
# Mitigation, in priority order:
#   1. SPIFFETLS_LIBSSL_PATH explicitly set by the operator.
#   2. The libssl already mapped into this process (Linux /proc/self/maps,
#      macOS dyld image list).
#   3. find_library / soname lookup, with a loud warning — this is the only
#      path where we cannot guarantee identity with _ssl's libssl.


def _loaded_libssl_paths() -> list[str]:
    """Best-effort list of full paths of libssl currently mapped in-process.

    Linux: /proc/self/maps lists every mapped object with its full path.
        See proc(5) — "maps" format, field 6 is the pathname.
    macOS: dyld exports ``_dyld_image_count`` / ``_dyld_get_image_name``,
        documented in <mach-o/dyld.h>.
    """
    paths: list[str] = []

    def _consider(path: str) -> None:
        base = os.path.basename(path)
        if base.startswith("libssl") and (".so" in base or ".dylib" in base):
            try:
                rp = os.path.realpath(path)
            except OSError:
                return
            if rp not in paths:
                paths.append(rp)

    try:
        if sys.platform.startswith("linux"):
            with open("/proc/self/maps", "r",
                      encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.rstrip("\n").split(None, 5)
                    if len(parts) < 6:
                        continue
                    _consider(parts[5])
        elif sys.platform == "darwin":
            # Try the main executable first, then libdyld explicitly.
            # On some macOS versions CDLL(None) does not re-export the
            # _dyld_* symbols; libdyld.dylib is where they actually live.
            for lib_name in (None, "libdyld.dylib", "/usr/lib/libdyld.dylib"):
                try:
                    libc = ctypes.CDLL(lib_name)
                    count = libc._dyld_image_count
                    count.restype = ctypes.c_uint32
                    name = libc._dyld_get_image_name
                    name.argtypes = [ctypes.c_uint32]
                    name.restype = ctypes.c_char_p
                    for i in range(count()):
                        raw = name(i)
                        if raw:
                            _consider(raw.decode("utf-8", "replace"))
                    break  # success
                except (AttributeError, OSError) as e:  # pragma: no cover
                    log.debug("dyld enumeration via %r unavailable: %s",
                              lib_name, e)
                    continue
    except Exception as e:  # pragma: no cover - best effort
        log.debug("could not enumerate loaded libssl: %s", e)

    return paths


def _try_cdll(path: str) -> Optional[ctypes.CDLL]:
    try:
        return ctypes.CDLL(path)
    except OSError as e:
        log.warning("failed to dlopen %s: %s", path, e)
        return None


def _load_windows() -> ctypes.CDLL:
    """Load libssl on Windows without launching a second copy.

    ``GetModuleHandleW`` returns a handle to an already-loaded module without
    incrementing its reference count, which is what we want: we want the
    same DLL that ``_ssl`` is using.  Loading by filename could pick up a
    different DLL from a different directory on PATH.

    Reference: GetModuleHandleW — Windows SDK documentation.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetModuleHandleW.restype = ctypes.c_void_p

    # Include ARM64 variants (Windows on ARM is a real deployment target).
    for name in (
        "libssl-3", "libssl-3-x64", "libssl-3-arm64",
        "libssl-1_1", "libssl-1_1-x64", "libssl-1_1-arm64",
    ):
        h = kernel32.GetModuleHandleW(name)
        if h:
            log.info("using already-loaded libssl module: %s", name)
            try:
                return ctypes.CDLL(name, handle=h)
            except OSError as e:
                log.warning("CDLL(%s, handle=%x) failed: %s", name, h, e)

    for name in (
        "libssl-3-x64.dll", "libssl-3-arm64.dll", "libssl-3.dll",
        "libssl-1_1-x64.dll", "libssl-1_1-arm64.dll", "libssl-1_1.dll",
    ):
        lib = _try_cdll(name)
        if lib is not None:
            log.warning(
                "loaded libssl by name (%s); ensure this is the same DLL "
                "used by the ssl module", name,
            )
            return lib

    raise ChannelBindingError("LIBSSL_NOT_FOUND", _LOAD_HINT)


def _load_posix() -> ctypes.CDLL:
    env = os.environ.get("SPIFFETLS_LIBSSL_PATH")
    if env:
        lib = _try_cdll(env)
        if lib is not None:
            log.info("loaded libssl from SPIFFETLS_LIBSSL_PATH=%s", env)
            return lib
        log.error("SPIFFETLS_LIBSSL_PATH=%s could not be loaded", env)

    for path in _loaded_libssl_paths():
        lib = _try_cdll(path)
        if lib is not None:
            log.info("loaded libssl from mapped path: %s", path)
            return lib

    # Last resort — identity with _ssl's libssl is no longer guaranteed.
    candidates: list[str] = []
    found = ctypes.util.find_library("ssl")
    if found:
        candidates.append(found)
    if sys.platform == "darwin":
        candidates += ["libssl.3.dylib", "libssl.1.1.dylib", "libssl.dylib"]
    else:
        candidates += ["libssl.so.3", "libssl.so.1.1", "libssl.so"]

    last_err: Optional[Exception] = None
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
        except OSError as e:
            last_err = e
            continue
        log.warning(
            "falling back to name lookup for libssl (%s); if this differs "
            "from the libssl used by _ssl, the process may crash", name,
        )
        return lib

    raise ChannelBindingError(
        "LIBSSL_NOT_FOUND", f"{last_err}. {_LOAD_HINT}"
    )


_ssl_lib: Optional[ctypes.CDLL] = None
_ssl_lib_lock = threading.Lock()



def _get_ssl_lib() -> ctypes.CDLL:
    global _ssl_lib
    if _ssl_lib is not None:
        return _ssl_lib
    with _ssl_lib_lock:
        if _ssl_lib is not None:
            return _ssl_lib
        lib = _load_windows() if os.name == "nt" else _load_posix()
        _configure_prototypes(lib)
        _ssl_lib = lib
        return lib


def _configure_prototypes(lib: ctypes.CDLL) -> None:
    """Bind signatures for the OpenSSL functions we call.

    Signature reference:
        https://www.openssl.org/docs/man3.0/man3/SSL_export_keying_material.html
    """
    try:
        export = lib.SSL_export_keying_material
    except AttributeError as e:
        raise ChannelBindingError(
            "EXPORT_FN_MISSING",
            "libssl does not export SSL_export_keying_material "
            "(OpenSSL >= 1.0.2 required)",
        ) from e

    export.argtypes = [
        ctypes.c_void_p,                    # SSL *s
        ctypes.c_void_p,                    # unsigned char *out
        ctypes.c_size_t,                    # size_t olen
        ctypes.c_char_p,                    # const char *label
        ctypes.c_size_t,                    # size_t llen
        ctypes.c_char_p,                    # const unsigned char *context
        ctypes.c_size_t,                    # size_t contextlen
        ctypes.c_int,                       # int use_context
    ]
    export.restype = ctypes.c_int

    # Optional introspection helpers — present on OpenSSL 1.1+/3.x.
    for name, restype in (
        ("SSL_get_version", ctypes.c_char_p),
        ("SSL_is_init_finished", ctypes.c_int),
        ("SSL_get_shutdown", ctypes.c_int),
    ):
        try:
            fn = getattr(lib, name)
        except AttributeError:
            continue
        fn.argtypes = [ctypes.c_void_p]
        fn.restype = restype


# ================== SSL* extraction 
#
# CPython Modules/_ssl.c declares PySSLSocket as (simplified):
#
#     typedef struct {
#         PyObject_HEAD          //  object header: refcount + type
#         PyObject *Socket;      //  weakref to the Python socket
#         SSL *ssl;              //  ← the pointer we want
#         ...
#     } PySSLSocket;
#
# CPython source:
#   https://github.com/python/cpython/blob/main/Modules/_ssl.c
#   (search for "PySSLSocket" — the ssl field is the third member)
#
# On current CPython (3.8–3.13, including free-threaded builds that keep the
# PyObject_HEAD layout), the SSL* sits at:
#     id(_sslobj) + object.__basicsize__ + sizeof(void*)
#
# This is NOT a stable ABI. We guard it as defensively as we can, but a
# future interpreter layout change would silently return garbage. The
# _sanity_check_ssl() below is what catches most such drift at runtime.

_SSL_PTR_OFFSET = object.__basicsize__ + ctypes.sizeof(ctypes.c_void_p)


def _ssl_pointer(ssl_obj: ssl.SSLSocket | ssl.SSLObject) -> int:
    if not isinstance(ssl_obj, (ssl.SSLSocket, ssl.SSLObject)):
        raise ChannelBindingError(
            "WRONG_TYPE",
            f"expected ssl.SSLSocket, got {type(ssl_obj).__name__}",
        )
    inner = getattr(ssl_obj, "_sslobj", None)
    if inner is None:
        raise ChannelBindingError(
            "SSL_OBJECT_NONE",
            "socket is not wrapped or has been unwrapped/closed",
        )

    ptr = ctypes.c_void_p.from_address(id(inner) + _SSL_PTR_OFFSET).value
    if not ptr:
        raise ChannelBindingError("SSL_PTR_NULL", "SSL* is NULL")
    return ptr


def _sanity_check_ssl(ptr: int) -> None:
    """Best-effort validation that ``ptr`` points at a live, handshaken SSL*."""
    lib = _get_ssl_lib()

    # SSL_is_init_finished: returns 1 once the handshake completes.
    # https://www.openssl.org/docs/man3.0/man3/SSL_is_init_finished.html
    is_init = getattr(lib, "SSL_is_init_finished", None)
    if is_init is not None:
        try:
            if not is_init(ptr):
                raise ChannelBindingError(
                    "HANDSHAKE_INCOMPLETE",
                    "TLS handshake has not completed; cannot export "
                    "keying material",
                )
        except ChannelBindingError:
            raise
        except Exception as e:  # pragma: no cover
            log.debug("SSL_is_init_finished check skipped: %s", e)

    # SSL_get_version: returns the negotiated protocol name, or NULL.
    # https://www.openssl.org/docs/man3.0/man3/SSL_get_version.html
    get_version = getattr(lib, "SSL_get_version", None)
    if get_version is not None:
        try:
            version = get_version(ptr)
        except Exception as e:  # pragma: no cover
            raise ChannelBindingError(
                "SSL_PTR_INVALID",
                f"SSL_get_version failed on extracted pointer: {e}",
            ) from e
        if not version:
            raise ChannelBindingError(
                "SSL_PTR_INVALID", "SSL_get_version returned NULL"
            )

    # SSL_get_shutdown: non-zero once shutdown has been initiated.
    # https://www.openssl.org/docs/man3.0/man3/SSL_get_shutdown.html
    get_shutdown = getattr(lib, "SSL_get_shutdown", None)
    if get_shutdown is not None:
        try:
            if get_shutdown(ptr) != 0:
                log.warning(
                    "SSL session has shutdown flags set; export may still "
                    "succeed but the peer may already have closed"
                )
        except Exception:  # pragma: no cover
            pass




def _coerce_bytes(
    name: str, value: bytes | bytearray | str,
) -> bytes:
    """Coerce a str/bytes/bytearray argument to bytes. Only ChannelBindingError
    escapes — callers must never see UnicodeEncodeError."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        try:
            return value.encode("ascii")
        except UnicodeEncodeError as e:
            raise ChannelBindingError(
                "BAD_ARGUMENT",
                f"{name} must be ASCII; rejected at {e.start}: "
                f"{e.object[e.start:e.start+8]!r}",
            ) from None
    raise ChannelBindingError(
        "BAD_ARGUMENT",
        f"{name} must be str or bytes, got {type(value).__name__}",
    )



def native_exporter(
    ssl_obj: ssl.SSLSocket | ssl.SSLObject,
    length: int = RFC9266_LENGTH,
    label: bytes | str = RFC9266_LABEL,
    context: bytes | str | None = RFC9266_CONTEXT,
) -> bytes:
    """Compute TLS exported keying material (RFC 5705 / RFC 8446 / RFC 9266).

    Args:
        ssl_obj: A live ``ssl.SSLSocket`` or ``ssl.SSLObject`` whose handshake
                 has completed.
        length:  Number of bytes to export, 1..65536.
        label:   Exporter label. RFC 9266 uses ``b"EXPORTER-Channel-Binding"``.
                 Must not contain NUL (RFC 5705 §4).
        context: Exporter context. RFC 9266 uses the empty byte string
                 (``b""``) *with* ``use_context=1``. Pass ``None`` only for
                 legacy RFC 5705 uses; it is wrong for RFC 9266.

    Raises:
        ChannelBindingError: on any setup, precondition, or export failure.
    """
    if not isinstance(length, int) or isinstance(length, bool) \
            or not (_MIN_LENGTH <= length <= _MAX_LENGTH):
        raise ChannelBindingError(
            "BAD_LENGTH",
            f"length must be int in [{_MIN_LENGTH}, {_MAX_LENGTH}], "
            f"got {length!r}",
        )

    label_b = _coerce_bytes("label", label)
    if not label_b:
        raise ChannelBindingError(
            "BAD_LABEL", "label must not be empty",
        )
    # RFC 5705 §4: "The label must be a string literal (i.e., it must not
    # contain null bytes)." Embedded NULs would produce a different exporter
    # value than a peer implementing the spec strictly.
    if b"\x00" in label_b:
        raise ChannelBindingError(
            "BAD_LABEL",
            "label must not contain NUL bytes (RFC 5705 §4)",
        )

    ctx_b = b"" if context is None else _coerce_bytes("context", context)
    use_ctx = 0 if context is None else 1

    lib = _get_ssl_lib()
    ptr = _ssl_pointer(ssl_obj)
    _sanity_check_ssl(ptr)

    out = ctypes.create_string_buffer(length)
    rc = lib.SSL_export_keying_material(
        ptr,
        out,
        length,
        label_b,
        len(label_b),
        ctx_b,
        len(ctx_b),
        use_ctx,
    )
    if rc != 1:
        raise ChannelBindingError(
            "EXPORT_FAILED",
            f"SSL_export_keying_material returned {rc} "
            f"(length={length}, label={label_b!r}, ctx={ctx_b!r}, "
            f"use_ctx={use_ctx})",
        )
    return out.raw[:length]


def is_supported() -> tuple[bool, str]:
    """Return ``(supported, reason)``. Never raises.

    Use this to decide whether to accept connections at all, before the
    first handshake, rather than discovering the problem on connection N.
    """
    try:
        _get_ssl_lib()
    except ChannelBindingError as e:
        return False, f"{e.code}: {e.detail}"
    except Exception as e:  # pragma: no cover
        return False, f"{type(e).__name__}: {e}"
    return True, ""


def libssl_version() -> str:
    """Return the version string of the libssl actually in use.

    Diagnostics aid: if this disagrees with ``ssl.OPENSSL_VERSION``, the
    wrong libssl was loaded and channel binding will produce inconsistent
    values across peers.
    """
    lib = _get_ssl_lib()
    try:
        fn = lib.OpenSSL_version
    except AttributeError:
        return "unknown (OpenSSL_version not exported)"
    # OPENSSL_VERSION == 0: full version string.
    # https://www.openssl.org/docs/man3.0/man3/OpenSSL_version.html
    fn.argtypes = [ctypes.c_int]
    fn.restype = ctypes.c_char_p
    raw = fn(0)
    return raw.decode("utf-8", "replace") if raw else "unknown"



import ctypes

_RAW_LEN = 32


def derive_session_secrets(
    ssl_obj,
    *,
    alpn: str,
    length: int = _RAW_LEN,
    label: bytes = RFC9266_LABEL,
    context: bytes = RFC9266_CONTEXT,
    compile_session_secrets,
):
    """Extract exporter → split → zero C buffer → return split only.

    The raw exporter NEVER becomes a Python bytes object and never leaves
    this frame. On return, the C buffer holding it is zeroed.
    """
    if length != _RAW_LEN:
        raise ChannelBindingError("BAD_LENGTH", "exporter length must be 32")

    lib = _get_ssl_lib()
    out = ctypes.create_string_buffer(_RAW_LEN)   # mutable, zeroable
    try:
        # _ssl_pointer returns (inner, ptr); keeping `inner` referenced
        # prevents use-after-free during the C call.
        inner, ptr = _ssl_pointer(ssl_obj) # type: ignore
        _sanity_check_ssl(ptr)

        ctx_b = b"" if context is None else _coerce_bytes("context", context)
        use_ctx = 0 if context is None else 1
        label_b = _coerce_bytes("label", label)

        rc = lib.SSL_export_keying_material(
            ptr, out, _RAW_LEN,
            label_b, len(label_b),
            ctx_b, len(ctx_b), use_ctx,
        )
        if rc != 1:
            raise ChannelBindingError("EXPORT_FAILED", str(rc))

        # Split from the C buffer directly; no Python bytes copy.
        mv = memoryview(out).cast("B")[:_RAW_LEN]
        try:
            return compile_session_secrets(mv, alpn=alpn)
        finally:
            # Release the view so the buffer can be written again.
            mv.release()
    finally:
        # Zero the C buffer even on exception.
        ctypes.memset(out, 0, _RAW_LEN)
        del inner  # type: ignore # drop the last reference to the SSL object

def self_tests():
    """Run every self-test. Prints progress; raises on first failure."""
    import asyncio
    import datetime
    import os
    import queue
    import socket
    import ssl
    import subprocess
    import sys
    import tempfile
    import textwrap
    import threading
    import time

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
    from cryptography.x509.oid import NameOID

    HOST = "127.0.0.1"
    PORT = 0
    ADD = (HOST, PORT)

    # RFC 8446 §7.1 / §7.5 primitives 
    #
    # RFC 8446 §7.1 — HKDF-Expand-Label:
    #     struct {
    #         uint16 length;
    #         opaque label<7..255> = "tls13 " + Label;
    #         opaque context<0..255>;
    #     } HkdfLabel;
    #
    # RFC 8446 §7.5 — Exporter:
    #     TLS-Exporter(Label, Context, Length) =
    #         HKDF-Expand-Label(
    #             Derive-Secret(exporter_master_secret, Label, ""),
    #             "exporter", Hash(Context), Length)
    #
    # Two stages — Derive-Secret itself is an HKDF-Expand-Label with an
    # empty-context hash. Do not collapse the two steps.

    def _hash(hash_alg, data: bytes) -> bytes:
        h = hashes.Hash(hash_alg)
        h.update(data)
        return h.finalize()

    def _hkdf_expand_label(
        hash_alg, secret, label: bytes, ctx_hash: bytes, out_len: int
    ) -> bytes:
        full_label = b"tls13 " + label
        if len(full_label) > 255:
            raise ValueError("label too long")
        if len(ctx_hash) > 255:
            raise ValueError("context too long")
        info = (
            out_len.to_bytes(2, "big")
            + bytes([len(full_label)]) + full_label
            + bytes([len(ctx_hash)]) + ctx_hash
        )
        return HKDFExpand(algorithm=hash_alg, length=out_len, info=info).derive(
            secret
        )

    def hash_for_cipher(name: str):
        if name.endswith("_SHA384"):
            return hashes.SHA384()
        if name.endswith("_SHA256"):
            return hashes.SHA256()
        raise ValueError(f"unsupported TLS 1.3 cipher: {name}")

    def rfc8446_exporter(
        exporter_master_secret: bytes,
        label: bytes,
        context: bytes,
        length: int,
        hash_algo,
    ) -> bytes:
        hash_len = hash_algo.digest_size
        empty_hash = _hash(hash_algo, b"")
        derived = _hkdf_expand_label(
            hash_algo, exporter_master_secret, label, empty_hash, hash_len
        )
        ctx_hash = _hash(hash_algo, context)
        return _hkdf_expand_label(
            hash_algo, derived, b"exporter", ctx_hash, length
        )


    def make_self_signed():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "cb-test")]
        )
        now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        d = tempfile.mkdtemp(prefix="cb-test")
        cert_path = os.path.join(d, "cert.pem")
        key_path = os.path.join(d, "key.pem")
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        return cert_path, key_path

    def make_ctx(
        server_keylog: str, client_keylog: str
    ) -> tuple[ssl.SSLContext, ssl.SSLContext]:
        cert, key = make_self_signed()

        def mk(proto, keylog):
            c = ssl.SSLContext(proto)
            c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
            c.verify_mode = ssl.CERT_REQUIRED
            c.load_cert_chain(cert, key)
            c.load_verify_locations(cert)
            c.keylog_filename = keylog
            return c

        s = mk(ssl.PROTOCOL_TLS_SERVER, server_keylog)
        c = mk(ssl.PROTOCOL_TLS_CLIENT, client_keylog)
        c.check_hostname = False
        return s, c

    def exporter_master_secret(keylog_path: str) -> bytes:
        """Read exporter_master_secret from the keylog.

        For TLS 1.3, ``SSLSocket.session.id`` is empty, so we cannot use it
        to look up the entry. This test has exactly one connection, so
        there is exactly one EXPORTER_SECRET line.
        """
        with open(keylog_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) == 3 and parts[0] == "EXPORTER_SECRET":
                    return bytes.fromhex(parts[2])
        raise RuntimeError(f"no EXPORTER_SECRET in keylog: {keylog_path!r}")

    class TLSSession:
        def __init__(self):
            self.server_keylog = tempfile.mkstemp(prefix="cb-srv-")[1]
            self.client_keylog = tempfile.mkstemp(prefix="cb-cli-")[1]
            server_ctx, client_ctx = make_ctx(
                self.server_keylog, self.client_keylog
            )
            self.ready = queue.Queue()
            self.result = {"release": threading.Event()}
            self._thread = threading.Thread(
                target=self.server_loop, args=(server_ctx,), daemon=True
            )
            self._thread.start()
            port = self.ready.get(timeout=5)
            self.client_sock = client_ctx.wrap_socket(
                socket.create_connection((HOST, port)),
                server_hostname="cb-test",
            )
            for _ in range(2000):
                if "sslsock" in self.result or "error" in self.result:
                    break
                time.sleep(0.001)
            if "error" in self.result:
                self.close()
                raise self.result["error"]  # type: ignore
            self.server_sock = self.result["sslsock"]

        def server_loop(self, server_ctx: ssl.SSLContext):
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(ADD)
            srv.listen(1)
            self.ready.put(srv.getsockname()[1])
            try:
                raw, _ = srv.accept()
                try:
                    tls = server_ctx.wrap_socket(raw, server_side=True)
                except Exception as e:
                    self.result["error"] = e  # type: ignore
                    return
                try:
                    self.result["sslsock"] = tls  # type: ignore
                    self.result["release"].wait(timeout=10)
                finally:
                    try:
                        tls.close()
                    except Exception:
                        pass
            finally:
                srv.close()

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.close()

        def close(self):
            self.result["release"].set()
            self._thread.join(timeout=5)
            try:
                self.client_sock.close()
            except Exception:
                pass
            for path in [self.server_keylog, self.client_keylog]:
                try:
                    os.unlink(path)
                except Exception:
                    pass


    def test_matches_on_both_sides():
        with TLSSession() as s:
            cb_client = native_exporter(s.client_sock)
            cb_server = native_exporter(s.server_sock)  # type: ignore
        assert cb_client == cb_server, (
            f"client and server disagree:\n"
            f"  client: {cb_client.hex()}\n"
            f"  server: {cb_server.hex()}\n"
        )

    def test_deterministic_on_same_session():
        with TLSSession() as s:
            a = native_exporter(s.client_sock)
            b = native_exporter(s.client_sock)
            c = native_exporter(s.server_sock)  # type: ignore
        assert a == b, f"client not deterministic {a.hex()} != {b.hex()}"
        assert a == c, f"client != server {a.hex()} != {c.hex()}"

    def test_differs_across_sessions():
        with TLSSession() as s:
            cb1 = native_exporter(s.client_sock)
        with TLSSession() as s:
            cb2 = native_exporter(s.client_sock)
        assert cb1 != cb2, (
            f"same value across distinct sessions — not session-derived:\n"
            f"  session 1: {cb1.hex()}\n"
            f"  session 2: {cb2.hex()}\n"
        )

    def test_label_separation():
        with TLSSession() as s:
            a = native_exporter(
                s.client_sock,
                label=b"EXPORTER-Channel-Binding",
                context=b"",
                length=32,
            )
            b = native_exporter(
                s.client_sock,
                label=b"some-other-label",
                context=b"",
                length=32,
            )
        assert a != b, "different labels same output — label is ignored"

        with TLSSession() as s:
            a = native_exporter(s.client_sock, context=b"L", length=32)
            b = native_exporter(s.client_sock, context=b"ctx", length=32)
        assert a != b, "different context same output — context is ignored"

        with TLSSession() as s:
            cb = native_exporter(s.client_sock)
        assert isinstance(cb, bytes), f"expected bytes, got {type(cb).__name__}"
        assert len(cb) == RFC9266_LENGTH == 32, (
            f"expected {RFC9266_LENGTH} bytes, got {len(cb)}"
        )

    def test_before_handshake_raises():
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.bind(ADD)
        srv.listen(1)
        port = srv.getsockname()[1]

        def _idle_accept():
            try:
                srv.accept()
                time.sleep(0.5)
            finally:
                srv.close()

        threading.Thread(target=_idle_accept, daemon=True).start()

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        raw = socket.create_connection((HOST, port))
        tls = ctx.wrap_socket(raw, do_handshake_on_connect=False)
        try:
            try:
                native_exporter(tls)
                assert False, "expected HANDSHAKE_INCOMPLETE"
            except ChannelBindingError as e:
                assert e.code == "HANDSHAKE_INCOMPLETE", (
                    f"expected HANDSHAKE_INCOMPLETE, got {e.code}"
                )
        finally:
            tls.close()

    def test_label_rejects_nul():
        """RFC 5705 §4: the label must not contain NUL bytes."""
        try:
            native_exporter(None, label=b"bad\x00label")  # type: ignore[arg-type]
            assert False, "expected BAD_LABEL"
        except ChannelBindingError as e:
            assert e.code == "BAD_LABEL", e.code

    def test_label_rejects_non_ascii():
        try:
            native_exporter(None, label="café")  # type: ignore[arg-type]
            assert False, "expected BAD_ARGUMENT"
        except ChannelBindingError as e:
            assert e.code == "BAD_ARGUMENT", e.code

    def test_matches_independent_derivation():
        """The only test that proves correctness: compare native output
        against the value derived from exporter_master_secret using RFC
        8446 §7.5. No ssl.SSLSocket.export_keying_material involved."""
        with TLSSession() as s:
            ems = exporter_master_secret(s.client_keylog)
            cipher_name = s.client_sock.cipher()[0]  # type: ignore
            hash_algo = hash_for_cipher(cipher_name)
            expected = rfc8446_exporter(
                exporter_master_secret=ems,
                label=b"EXPORTER-Channel-Binding",
                context=b"",
                length=32,
                hash_algo=hash_algo,
            )
            actual_client = native_exporter(s.client_sock)
            actual_server = native_exporter(s.server_sock)  # type: ignore
            print(f"  cipher:              {cipher_name}")
            print(f"  hash:                {hash_algo.name}")
            print(f"  exporter_master_sec: {ems.hex()[:32]}...")
            print(f"  expected (computed): {expected.hex()}")
            print(f"  actual (client):     {actual_client.hex()}")
            print(f"  actual (server):     {actual_server.hex()}")
            print(
                f"  match:               "
                f"{expected == actual_client == actual_server}"
            )
            assert actual_client == expected, (
                f"native_exporter produced the WRONG exporter value.\n"
                f"  expected (RFC 8446 derivation): {expected.hex()}\n"
                f"  actual   (your function):       {actual_client.hex()}\n"
                f"This means the ctypes plumbing is wrong: wrong SSL* offset, "
                f"wrong libssl, wrong function prototype, or the value is "
                f"being read after context invalidation."
            )
            assert actual_server == expected, (
                f"server side produced a different wrong value: "
                f"{actual_server.hex()} != {expected.hex()}"
            )

    def test_4_cross_process():
        """Two separate OS processes, each opening its own TLS session to
        the same server, each computing the CB for its own socket.
        Proves there is no per-process state leak in the ctypes layer."""
        SRC_DIR = os.path.dirname(os.path.abspath(__file__))
        # Load the module by file path in the subprocess so this test works
        # whether the file is run as ``python native_exporter.py`` or imported
        # as ``aegis.transport.native_exporter``. ``__name__`` is
        # ``"__main__"`` in the first case, which is not importable.
        module_path = os.path.abspath(__file__)

        _CLIENT_SCRIPT = textwrap.dedent("""
        import importlib.util, os, socket, ssl, sys
        spec = importlib.util.spec_from_file_location(
            "_ne", os.environ["AEGIS_NATIVE_EXPORTER_PATH"]
        )
        ne = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ne)

        cert_path = sys.argv[1]; key_path = sys.argv[2]
        port = int(sys.argv[3])

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(cert_path, key_path)
        ctx.load_verify_locations(cert_path)

        raw = socket.create_connection(("127.0.0.1", port))
        tls = ctx.wrap_socket(raw, server_hostname="cb-dep")
        cb = ne.native_exporter(tls)
        sys.stdout.write(cb.hex())
        tls.close()
        """)

        cp, kp = make_self_signed()
        keylog = tempfile.mkstemp(prefix="cb-xproc-")[1]

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_cert_chain(cp, kp)
        ctx.load_verify_locations(cp)
        ctx.keylog_filename = keylog

        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]

        server_cbs: list[bytes] = []
        done = threading.Event()

        def accept_loop():
            try:
                while len(server_cbs) < 2:
                    raw, _ = srv.accept()
                    tls = ctx.wrap_socket(raw, server_side=True)
                    server_cbs.append(native_exporter(tls))
                    tls.close()
            finally:
                done.set()

        threading.Thread(target=accept_loop, daemon=True).start()

        env = dict(os.environ, AEGIS_NATIVE_EXPORTER_PATH=module_path)
        client_outputs: list[bytes] = []
        for _ in range(2):
            r = subprocess.run(
                [sys.executable, "-c", _CLIENT_SCRIPT, cp, kp, str(port)],
                capture_output=True,
                text=True,
                timeout=20,
                cwd=SRC_DIR,
                env=env,
            )
            if r.returncode != 0:
                raise AssertionError(
                    f"client subprocess failed:\n"
                    f"stdout: {r.stdout}\nstderr: {r.stderr}"
                )
            client_outputs.append(bytes.fromhex(r.stdout.strip()))

        done.wait(timeout=5)
        srv.close()

        assert len(server_cbs) == 2, (
            f"server saw {len(server_cbs)} connections"
        )
        for i, (cb_cli, cb_srv) in enumerate(zip(client_outputs, server_cbs)):
            assert cb_cli == cb_srv, (
                f"process boundary broke CB agreement on connection {i}:\n"
                f"  client: {cb_cli.hex()}\n"
                f"  server: {cb_srv.hex()}"
            )
        assert client_outputs[0] != client_outputs[1], (
            "two separate clients produced the same CB"
        )

    def test_asyncio_ssl_object_matches_rfc8446():
        fd, keylog = tempfile.mkstemp(prefix="cb-keylog")
        os.close(fd)

        sctx = cctx = None
        try:
            sctx, cctx = make_ctx(keylog, keylog)

            async def run():
                got: dict = {}
                done = asyncio.Event()

                async def on_conn(reader, writer):
                    so = writer.get_extra_info("ssl_object")
                    got["type"] = type(so)
                    got["server"] = native_exporter(so)
                    done.set()
                    await reader.read()
                    writer.close()

                srv = await asyncio.start_server(on_conn, HOST, 0, ssl=sctx)
                port = srv.sockets[0].getsockname()[1]
                r, w = await asyncio.open_connection(
                    HOST, port, ssl=cctx, server_hostname="cb-test"
                )
                so = w.get_extra_info("ssl_object")
                got["client"] = native_exporter(so)
                got["cipher"] = so.cipher()[0]
                await asyncio.wait_for(done.wait(), 5)
                w.close()
                await w.wait_closed()
                srv.close()
                await srv.wait_closed()
                return got

            got = asyncio.run(run())
            assert got["type"] is ssl.SSLObject, got["type"]

            ems = None
            with open(keylog) as f:
                for line in f:
                    p = line.split()
                    if len(p) == 3 and p[0] == "EXPORTER_SECRET":
                        ems = bytes.fromhex(p[2])
                        break
            assert ems, "no EXPORTER_SECRET in keylog"

            h = (
                hashes.SHA384()
                if "SHA384" in got["cipher"]
                else hashes.SHA256()
            )
            expected = rfc8446_exporter(
                ems, RFC9266_LABEL, RFC9266_CONTEXT, RFC9266_LENGTH, h
            )
            actual_client = got["client"]
            actual_server = got["server"]
            cipher_name = got["cipher"]
            print(f"  cipher:              {cipher_name}")
            print(f"  hash:                {h.name}")
            print(f"  exporter_master_sec: {ems.hex()[:32]}...")
            print(f"  expected (computed): {expected.hex()}")
            print(f"  actual (client):     {actual_client.hex()}")
            print(f"  actual (server):     {actual_server.hex()}")
            print(
                f"  match:               "
                f"{expected == actual_client == actual_server}"
            )

            assert actual_client == expected, (
                f"native_exporter produced the WRONG exporter value.\n"
                f"  expected (RFC 8446 derivation): {expected.hex()}\n"
                f"  actual   (your function):       {actual_client.hex()}\n"
                f"This means the ctypes plumbing is wrong: wrong SSL* offset, "
                f"wrong libssl, wrong function prototype, or the value is "
                f"being read after context invalidation."
            )
            assert actual_server == expected, (
                f"server side produced a different wrong value: "
                f"{actual_server.hex()} != {expected.hex()}"
            )
        finally:
            # Windows: SSLContext keeps the keylog FILE* open. Setting
            # keylog_filename=None calls fclose() on it, releasing the
            # handle so unlink can succeed. On POSIX this is unnecessary
            # but harmless.
            for c in (sctx, cctx):
                if c is not None:
                    try:
                        c.keylog_filename = None # type: ignore
                    except Exception:
                        pass
            try:
                os.unlink(keylog)
            except OSError as e:
                log.warning(
                    "could not unlink %s; temp file leaked: %s", keylog, e
                )

    test_matches_on_both_sides()
    test_deterministic_on_same_session()
    test_differs_across_sessions()
    test_label_separation()
    test_before_handshake_raises()
    test_label_rejects_nul()
    test_label_rejects_non_ascii()
    test_matches_independent_derivation()
    test_4_cross_process()
    test_asyncio_ssl_object_matches_rfc8446()


if __name__ == "__main__":
    self_tests()