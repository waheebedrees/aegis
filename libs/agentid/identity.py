"""
memory-first SPIFFE identity layer.
Questions this module answers:
    1. Who am I right now?                 IdentityService.current
    2. What TLS contexts do I use?         snapshot.server_ctx / client_ctx
    3. How do I rotate without downtime?   snapshot swap (recommended)

CAVEAT — asyncio.start_server(ssl=ctx):
    That API pins the SSLContext object. SSLContextHolder.reload() mutates
    it so leaf certs rotate, but the trust store still accumulates.
    Prefer accept + wrap_socket using IdentityService.current.server_ctx.
"""
from __future__ import annotations
import hashlib

import asyncio
import datetime
import hmac
import logging
import os
import ssl
import tempfile
import threading
import urllib.parse
from dataclasses import dataclass
from typing import (
    Any,
    Awaitable,
    Callable,
    Iterator,
    Optional,
    Protocol,
    Sequence,
    Union,
)
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key

__all__ = [
    "IdentityError",
    "SpiffeId",
    "IdentitySnapshot",
    "SVIDMaterial",
    "IdentityService",
    "SSLContextHolder",
    "SVIDWatcher",
    "fetch_only",
    "load",
    "materialize",
    "check_health",
    "Bootstrap",
    "bootstrap",
]

log = logging.getLogger("aegis.identity")
ALPN = "aegis/v1"


PrivateKeyTypes = Union[
    ec.EllipticCurvePrivateKey,
    ed25519.Ed25519PrivateKey,
    rsa.RSAPrivateKey,
]
PublicKeyTypes = Union[
    ec.EllipticCurvePublicKey,
    ed25519.Ed25519PublicKey,
    rsa.RSAPublicKey,
]



class IdentityError(Exception):
    """Infrastructure failure (Workload API, PEM, socket). Map to 503, not 400."""

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail



@dataclass(frozen=True, slots=True)
class SpiffeId:
    uri: str
    trust_domain: str
    path: str

    @classmethod
    def parse(cls, uri: str) -> "SpiffeId":
        if not isinstance(uri, str) or not uri or len(uri) > 2048:
            raise IdentityError("INVALID_SPIFFE_ID", "bad length or type")
        parsed = urllib.parse.urlsplit(uri)
        if parsed.scheme != "spiffe":
            raise IdentityError("INVALID_SPIFFE_ID",
                                f"scheme={parsed.scheme!r}")
        if parsed.query or parsed.fragment or parsed.username or parsed.port:
            raise IdentityError("INVALID_SPIFFE_ID",
                                "forbidden URI components")
        td = parsed.netloc
        if (
            not td
            or len(td) > 255
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789._-" for c in td)
        ):
            raise IdentityError("INVALID_SPIFFE_ID",
                                f"invalid trust domain {td!r}")
        if not parsed.path or parsed.path.endswith("/") or "//" in parsed.path:
            raise IdentityError("INVALID_SPIFFE_ID",
                                f"invalid path {parsed.path!r}")
        for seg in parsed.path.split("/")[1:]:
            if seg in ("", ".", ".."):
                raise IdentityError("INVALID_SPIFFE_ID",
                                    f"dot segment in {uri!r}")
        return cls(uri=f"spiffe://{td}{parsed.path}", trust_domain=td, path=parsed.path)

    def __str__(self) -> str:
        return self.uri



def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _cert_not_after(cert: x509.Certificate) -> datetime.datetime:
    if hasattr(cert, "not_valid_after_utc"):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)


def _cert_not_before(cert: x509.Certificate) -> datetime.datetime:
    if hasattr(cert, "not_valid_before_utc"):
        return cert.not_valid_before_utc
    return cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)


def _cert_expiry_ts(cert: x509.Certificate) -> int:
    return int(_cert_not_after(cert).timestamp())


def _spki_bytes(key: object) -> bytes:
    return key.public_bytes(  # type: ignore[union-attr]
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _public_keys_equal(a: object, b: object) -> bool:
    try:
        return hmac.compare_digest(_spki_bytes(a), _spki_bytes(b))
    except Exception:
        return False



def _load_workload_client():
    try:
        from spiffe import WorkloadApiClient as _C # type: ignore
        return _C
    except ImportError:
        pass
    try:
        from spiffe.workloadapi.client import Client as _C # type: ignore
        return _C
    except ImportError:
        pass
    try:
        from pyspiffe.workloadapi.default_workload_api_client import ( # type: ignore
            DefaultWorkloadApiClient as _C,
        )
        return _C
    except ImportError:
        pass
    raise IdentityError(
        "PY_SPIFFE_MISSING",
        "install py-spiffe (pip install spiffe or pyspiffe)",
    )


def _workload_socket(socket_path: str | None = None) -> str:
    sock = socket_path or os.environ.get("SPIFFE_ENDPOINT_SOCKET")
    if not sock:
        raise IdentityError(
            "SPIFFE_SOCKET_REQUIRED",
            "set SPIFFE_ENDPOINT_SOCKET or pass socket_path "
            "(e.g. unix:///run/spire/sockets/agent.sock)",
        )
    return sock


def _make_client(socket_path: str | None = None):
    return _load_workload_client()(socket_path=_workload_socket(socket_path))



def _cert_to_pem(cert) -> bytes:
    if isinstance(cert, x509.Certificate):
        return cert.public_bytes(serialization.Encoding.PEM)
    if isinstance(cert, (bytes, bytearray)):
        raw = bytes(cert)
        if raw.startswith(b"-----BEGIN"):
            return raw
        return x509.load_der_x509_certificate(raw).public_bytes(
            serialization.Encoding.PEM
        )
    for attr in ("pem", "to_pem"):
        val = getattr(cert, attr, None)
        if callable(val):
            out = val()
            return out.encode("ascii") if isinstance(out, str) else bytes(out) # type: ignore
        if isinstance(val, str):
            return val.encode("ascii")
        if isinstance(val, (bytes, bytearray)):
            return bytes(val)
    if hasattr(cert, "public_bytes"):
        return cert.public_bytes(serialization.Encoding.PEM)
    raise IdentityError("SVID_CERT_UNKNOWN", type(cert).__name__)


def _extract_chain(svid) -> list:
    for name in ("cert_chain", "certificates", "certs"):
        chain = getattr(svid, name, None)
        if chain is not None:
            return list(chain)
    raise IdentityError("SVID_NO_CHAIN", type(svid).__name__)


def _extract_private_key(svid) -> PrivateKeyTypes:
    raw = getattr(svid, "private_key", None)
    if raw is None:
        raise IdentityError("SVID_NO_KEY", type(svid).__name__)
    if isinstance(raw, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        blob = bytes(raw)
        if blob.startswith(b"-----BEGIN"):
            key = serialization.load_pem_private_key(blob, password=None)
        else:
            key = load_der_private_key(blob, password=None)
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
            raise IdentityError("SVID_KEY_UNKNOWN", type(key).__name__)
        return key
    if hasattr(raw, "private_bytes"):
        pem = raw.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
            raise IdentityError("SVID_KEY_UNKNOWN", type(key).__name__)
        return key
    raise IdentityError("SVID_KEY_UNKNOWN", type(raw).__name__)


def _private_key_pem(key: PrivateKeyTypes) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _leaf_cert(cert) -> x509.Certificate:
    if isinstance(cert, x509.Certificate):
        return cert
    pem = _cert_to_pem(cert)
    return x509.load_pem_x509_certificate(pem)


def _spiffe_id_from_cert(cert: x509.Certificate) -> SpiffeId:
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound as e:
        raise IdentityError("SVID_NO_SAN", "") from e
    uris = [
        u
        for u in san.get_values_for_type(x509.UniformResourceIdentifier)
        if u.startswith("spiffe://")
    ]
    if len(uris) != 1:
        raise IdentityError("SVID_BAD_SPIFFE_COUNT", str(len(uris)))
    return SpiffeId.parse(uris[0])


def _spiffe_id_from_svid(svid, leaf: x509.Certificate) -> SpiffeId:
    raw = getattr(svid, "spiffe_id", None)
    if raw is not None:
        uri = getattr(raw, "uri", None) or str(raw)
        parsed = SpiffeId.parse(uri)
        cert_id = _spiffe_id_from_cert(leaf)
        if parsed != cert_id:
            raise IdentityError(
                "SVID_ID_MISMATCH",
                f"workload id {parsed.uri} != cert SAN {cert_id.uri}",
            )
        return parsed
    return _spiffe_id_from_cert(leaf)


def _validate_leaf(leaf: x509.Certificate, key: PrivateKeyTypes, now: datetime.datetime) -> None:
    skew = datetime.timedelta(seconds=5)
    if not (_cert_not_before(leaf) - skew <= now <= _cert_not_after(leaf) + skew):
        raise IdentityError("SVID_EXPIRED", _cert_not_after(leaf).isoformat())
    try:
        bc = leaf.extensions.get_extension_for_class(
            x509.BasicConstraints).value
        if bc.ca:
            raise IdentityError("CA_CERT_FORBIDDEN",
                                "leaf X.509-SVID must have CA=False")
    except x509.ExtensionNotFound:
        pass
    if isinstance(key.public_key(), dsa.DSAPublicKey):
        raise IdentityError("UNSUPPORTED_KEY_TYPE", "DSA")
    if not _public_keys_equal(leaf.public_key(), key.public_key()):
        raise IdentityError("SVID_KEY_MISMATCH",
                            "private key does not match leaf certificate")


def _base_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols([ALPN])
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def server_ctx(*, certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = _base_context(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    ctx.num_tickets = 0  # Disable TLS 1.3 session resumption
    return ctx


def client_ctx(*, certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = _base_context(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    ctx.check_hostname = False  # Identity is validated via SPIFFE URI SAN pinned in wrap()
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    return ctx

def _build_tls13_contexts(
    cert_pem: bytes,
    key_pem: bytes,
    bundle_pem: bytes,
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    if not bundle_pem.strip():
        raise IdentityError("EMPTY_TRUST_BUNDLE", "")
    tmpdir = tempfile.mkdtemp(prefix="aegis-svid-")
    os.chmod(tmpdir, 0o700)
    cert_file = os.path.join(tmpdir, "svid.pem")
    key_file = os.path.join(tmpdir, "svid.key")
    bundle_file = os.path.join(tmpdir, "bundle.pem")

    def _write(path: str, data: bytes, mode: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(
            os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags, mode)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
    try:
        _write(cert_file, cert_pem, 0o600)
        _write(key_file, key_pem, 0o600)
        _write(bundle_file, bundle_pem, 0o644)
        return (
            server_ctx(certfile=cert_file, keyfile=key_file, cafile=bundle_file),
            client_ctx(certfile=cert_file, keyfile=key_file, cafile=bundle_file)
        )
    finally:
        for p in (key_file, cert_file, bundle_file):
            try:
                os.unlink(p)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass




@dataclass(frozen=True, slots=True)
class IdentitySnapshot:
    spiffe: SpiffeId
    credential_id: str             # x509-sha256:<hex sha256 of leaf DER>
    bundle_digest: str             # sha256:<hex sha256 of bundle PEM>
    private_key_id: str
    private_key: PrivateKeyTypes
    leaf_cert_der: bytes
    trust_anchors: tuple[x509.Certificate, ...]
    server_ctx: ssl.SSLContext
    client_ctx: ssl.SSLContext
    expires_at: datetime.datetime
    @property
    def remain(self) -> float:
        """Seconds until expiry; negative once the SVID has expired."""
        return (self.expires_at - _utc_now()).total_seconds()
    
    @property
    def spiffe_id(self) -> str:
        return self.spiffe.uri

    @property
    def trust_domain(self) -> str:
        return self.spiffe.trust_domain

    @classmethod
    def from_pem(cls, cert_pem: bytes, key_pem: bytes, bundle_pem: bytes) -> "IdentitySnapshot":
        certs = x509.load_pem_x509_certificates(cert_pem)
        if not certs:
            raise IdentityError("EMPTY_SVID_CHAIN", "")
        leaf = certs[0]
        key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(key, (ec.EllipticCurvePrivateKey, ed25519.Ed25519PrivateKey, rsa.RSAPrivateKey)):
            raise IdentityError("UNSUPPORTED_PRIVATE_KEY", type(key).__name__)
        now = _utc_now()
        _validate_leaf(leaf, key, now)
        spiffe = _spiffe_id_from_cert(leaf)
        anchors = tuple(x509.load_pem_x509_certificates(bundle_pem))
        if not anchors:
            raise IdentityError("EMPTY_TRUST_BUNDLE", "")
        server_ctx, client_ctx = _build_tls13_contexts(
            cert_pem, key_pem, bundle_pem)
        credential_id = "x509-sha256:" + hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
        bundle_digest = "sha256:" + hashlib.sha256(bundle_pem).hexdigest()
        key_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        private_key_id = "key-sha256:" + hashlib.sha256(key_der).hexdigest()

        return cls(
            spiffe=spiffe,
            private_key=key,
            private_key_id=private_key_id,
            credential_id=credential_id,
            bundle_digest=bundle_digest,
            leaf_cert_der=leaf.public_bytes(serialization.Encoding.DER),
            trust_anchors=anchors,
            server_ctx=server_ctx,
            client_ctx=client_ctx,
            expires_at=_cert_not_after(leaf),
        )

    @classmethod
    def from_workload(cls, svid, bundles) -> "IdentitySnapshot":
        chain = _extract_chain(svid)
        if not chain:
            raise IdentityError("SVID_EMPTY_CHAIN", "")
        leaf = _leaf_cert(chain[0])
        key = _extract_private_key(svid)
        now = _utc_now()
        _validate_leaf(leaf, key, now)
        spiffe = _spiffe_id_from_svid(svid, leaf)
        cert_pem = b"".join(_cert_to_pem(c) for c in chain)
        key_pem = _private_key_pem(key)
        td = svid.spiffe_id.trust_domain
        bundle = bundles.get_bundle_for_trust_domain(td)
        if bundle is None or not bundle.x509_authorities:
            raise IdentityError( "ANCHOR_INCONSISTENT",f"no bundle for {td!r}")

        bundle_pem = b"".join(
            a.public_bytes(serialization.Encoding.PEM)
            for a in bundle.x509_authorities
        )
        anchors = tuple(x509.load_pem_x509_certificates(bundle_pem))
        if not anchors:
            raise IdentityError("EMPTY_TRUST_BUNDLE", spiffe.trust_domain)
        server_ctx, client_ctx = _build_tls13_contexts(
            cert_pem, key_pem, bundle_pem)
        credential_id = "x509-sha256:" + hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
        bundle_digest = "sha256:" + hashlib.sha256(bundle_pem).hexdigest()


        key_der = key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        private_key_id = "key-sha256:" + hashlib.sha256(key_der).hexdigest()

        return cls(
            spiffe=spiffe,
            private_key=key,
            private_key_id=private_key_id,
            credential_id=credential_id,
            bundle_digest=bundle_digest,
            leaf_cert_der=leaf.public_bytes(serialization.Encoding.DER),
            trust_anchors=anchors,
            server_ctx=server_ctx,
            client_ctx=client_ctx,
            expires_at=_cert_not_after(leaf),
        )


# Disk material is optional (debug / HEALTHCHECK sidecars). Not used for TLS.

@dataclass(frozen=True, slots=True)
class SVIDMaterial:
    spiffe_id: str
    trust_domain: str
    cert_path: str
    key_path: str
    bundle_path: str
    expires_at: int


def _write_secure(path: os.PathLike[str] | str, data: bytes, mode: int) -> None:
    path = os.fspath(path)
    parent, name = os.path.split(path)
    fd, tmp = tempfile.mkstemp(prefix=name + ".", dir=parent)
    try:
        os.write(fd, data)
        os.fsync(fd)
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        dir_fd = os.open(parent, dir_flags)
    except OSError:
        return
    try:
        os.fsync(dir_fd)
    except OSError:
        pass
    finally:
        os.close(dir_fd)


def materialize(svid, bundles, *, out_dir: str) -> SVIDMaterial:
    """Write PEMs for debugging. Prefer IdentitySnapshot.from_workload() for TLS."""
    if not out_dir:
        raise IdentityError("SVID_DIR_REQUIRED", "pass out_dir explicitly")
    snap = IdentitySnapshot.from_workload(svid, bundles)
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    cert_path = os.path.join(out_dir, "svid.pem")
    key_path = os.path.join(out_dir, "svid.key")
    bundle_path = os.path.join(out_dir, "bundle.pem")
    chain_pem = b"".join(
        x509.load_der_x509_certificate(
            snap.leaf_cert_der).public_bytes(serialization.Encoding.PEM)
        for _ in (0,)
    )
    # Reconstruct cert PEM from the SVID we just validated:
    # from_workload already discarded the extra chain PEMs; re-fetch via files
    # is debug-only. Write leaf + anchors.
    _write_secure(cert_path, chain_pem, 0o600)
    _write_secure(key_path, _private_key_pem(snap.private_key), 0o600)
    bundle_pem = b"".join(a.public_bytes(serialization.Encoding.PEM)
                          for a in snap.trust_anchors)
    _write_secure(bundle_path, bundle_pem, 0o644)
    return SVIDMaterial(
        spiffe_id=snap.spiffe_id,
        trust_domain=snap.trust_domain,
        cert_path=cert_path,
        key_path=key_path,
        bundle_path=bundle_path,
        expires_at=int(snap.expires_at.timestamp()),
    )


def fetch_only(*, socket_path: str | None = None) -> tuple[str, int]:
    """Health/readiness: identity only, no files, no SSLContext."""
    client = _make_client(socket_path)
    svid = client.fetch_x509_svid()
    chain = _extract_chain(svid)
    if not chain:
        raise IdentityError("SVID_EMPTY_CHAIN", "")
    leaf = _leaf_cert(chain[0])
    spiffe = _spiffe_id_from_svid(svid, leaf)
    print(f"{spiffe=}")
    return spiffe.uri, _cert_expiry_ts(leaf)


def load(*, out_dir: str, socket_path: str | None = None) -> SVIDMaterial:
    if not out_dir:
        raise IdentityError("SVID_DIR_REQUIRED", "do not default to /tmp")
    client = _make_client(socket_path)
    return materialize(client.fetch_x509_svid(), client.fetch_x509_bundles(), out_dir=out_dir)



OnSnapshot = Callable[[IdentitySnapshot], Awaitable[None] | None]


def _unpack_watch_item(item) -> tuple[Any, Any]:
    if isinstance(item, tuple) and len(item) == 2:
        return item[0], item[1]
    svid = getattr(item, "default_svid", None) or getattr(item, "svid", item)
    bundles = (
        getattr(item, "bundle_set", None)
        or getattr(item, "x509_bundle_set", None)
        or getattr(item, "bundles", item)
    )
    return svid, bundles


class SVIDWatcher:
    """
    One dedicated OS thread blocked on watch_x509_context().

    py-spiffe's iterator has no cancel. stop() sets a flag; if SPIRE is
    idle until the next SVID, the thread may live until process exit.
    Do not construct more than one SVIDWatcher per process.
    """

    def __init__(
        self,
        *,
        on_snapshot: OnSnapshot,
        socket_path: str | None = None,
        allow_id_change: bool = False,
    ) -> None:
        self._on_snapshot = on_snapshot
        self._socket_path = socket_path
        self._allow_id_change = allow_id_change
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._known_id: Optional[SpiffeId] = None

    async def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("watcher already started")
        self._stop.clear()
        self._loop = asyncio.get_running_loop()
        self._thread = threading.Thread(
            target=self._run, name="svid-watcher", daemon=True
        )
        self._thread.start()

    async def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is None:
            return
        await asyncio.get_running_loop().run_in_executor(None, thread.join, timeout)

    def _run(self) -> None:
        backoff = 1.0
        while not self._stop.is_set():
            try:
                self._watch_once()
                backoff = 1.0
            except Exception as e:
                log.warning("svid watch restarting: %s: %s",
                            type(e).__name__, e)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
    def _dispatch(self, snap: IdentitySnapshot) -> None:
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        result = self._on_snapshot(snap)
        
        if asyncio.iscoroutine(result):
            fut = asyncio.run_coroutine_threadsafe(result, loop)
            try:
                fut.result(timeout=30)
            except Exception:
                log.exception("on_snapshot failed")


    def _watch_once(self) -> None:
        from spiffe import X509Source           # type: ignore # HPE spiffe package

        sock = _workload_socket(self._socket_path)
        # __init__ blocks until the first update (or raises on timeout/error)
        source = X509Source(socket_path=sock, timeout_in_seconds=30.0)
        try:
            # 1) initial snapshot
            ctx = source.get_x509_context()
            svid, bundles = _unpack_watch_item(ctx)
            snap = IdentitySnapshot.from_workload(svid, bundles)
            if self._known_id is None:
                self._known_id = snap.spiffe
            elif snap.spiffe != self._known_id and not self._allow_id_change:
                raise IdentityError(
                    "IDENTITY_CHANGED_ON_ROTATION",
                    f"{self._known_id.uri} -> {snap.spiffe.uri}",
                )
            self._dispatch(snap)

            # 2) rotation callbacks
            def on_update() -> None:
                if self._stop.is_set():
                    return
                try:
                    ctx = source.get_x509_context()
                    svid, bundles = _unpack_watch_item(ctx)
                    snap = IdentitySnapshot.from_workload(svid, bundles)
                    self._dispatch(snap)
                except Exception:
                    log.exception("ignoring bad SVID update")


            source.subscribe_for_updates(on_update)
            try:
                while not self._stop.is_set():

                    if source.is_closed():
                        log.warning("X509Source closed: %r",
                                    getattr(source, "_error", None))
                        raise IdentityError(
                            "SOURCE_CLOSED",
                            "X509Source closed by underlying Workload API error",
                        )
                    self._stop.wait(1.0)
            finally:
                source.unsubscribe_for_updates(on_update)
                
        finally:
            source.close()


class IdentityService:
    """
    Holds the current IdentitySnapshot.

    New connections must read `current` at accept/connect time so they
    pick up rotated contexts. Existing TLS sessions keep the handshake
    they already completed.
    """

    def __init__(self, snapshot: IdentitySnapshot) -> None:
        self._lock = threading.Lock()
        self._snapshot = snapshot
        self._watchers: list[Callable[[IdentitySnapshot], None]] = []
        self._watcher: Optional[SVIDWatcher] = None

    @property
    def current(self) -> IdentitySnapshot:
        with self._lock:
            return self._snapshot

    @classmethod
    def from_pem(cls, cert_pem: bytes, key_pem: bytes, bundle_pem: bytes) -> "IdentityService":
        return cls(IdentitySnapshot.from_pem(cert_pem, key_pem, bundle_pem))

    @classmethod
    def fetch(cls, *, socket_path: str | None = None) -> "IdentityService":
        client = _make_client(socket_path)
        snap = IdentitySnapshot.from_workload(
            client.fetch_x509_svid(), client.fetch_x509_bundles()
        )
        return cls(snap)

    def subscribe(self, fn: Callable[[IdentitySnapshot], None]) -> None:
        self._watchers.append(fn)

    def install(self, snapshot: IdentitySnapshot) -> None:
        with self._lock:
            prev = self._snapshot
            if snapshot.spiffe != prev.spiffe:
                raise IdentityError(
                    "IDENTITY_CHANGED_ON_ROTATION",
                    f"{prev.spiffe.uri} -> {snapshot.spiffe.uri}",
                )
            if snapshot.credential_id == prev.credential_id:
                return              # ← same SVID, nothing to notify
            self._snapshot = snapshot
            
        log.info(
            "svid rotated: %s credential_id=%s bundle_digest=%s remain=%.0fs",
            snapshot.spiffe.uri,
            snapshot.credential_id,
            snapshot.bundle_digest,
            snapshot.remain,
        )
        for fn in list(self._watchers):
            try:
                fn(snapshot)
            except Exception:
                log.exception("identity subscriber failed")
                
    async def start_watch(self, *, socket_path: str | None = None) -> None:
        if self._watcher is not None:
            raise RuntimeError("already watching")

        async def _on(snap: IdentitySnapshot) -> None:
            self.install(snap)

        self._watcher = SVIDWatcher(on_snapshot=_on, socket_path=socket_path)
        await self._watcher.start()

    async def stop(self, timeout: float = 5.0) -> None:
        if self._watcher is not None:
            await self._watcher.stop(timeout=timeout)
            self._watcher = None



class SSLContextHolder:
    """
    Mutates the same SSLContext objects.

    Leaf rotation works. Trust-bundle replacement does NOT: OpenSSL
    appends CAs. Restart the process after a SPIRE CA change, or use
    IdentityService with per-connection wrap_socket.
    """

    def __init__(self, snapshot: IdentitySnapshot) -> None:
        self._lock = threading.RLock()
        self._snapshot = snapshot
        self._server = snapshot.server_ctx
        self._client = snapshot.client_ctx

    @property
    def server(self) -> ssl.SSLContext:
        return self._server

    @property
    def client(self) -> ssl.SSLContext:
        return self._client

    @property
    def snapshot(self) -> IdentitySnapshot:
        with self._lock:
            return self._snapshot

    def reload_from_snapshot(self, snapshot: IdentitySnapshot) -> None:
        """Replace leaf cert/key. Bundle is appended, not replaced."""
        tmpdir = tempfile.mkdtemp(prefix="aegis-reload-")
        os.chmod(tmpdir, 0o700)
        cert_file = os.path.join(tmpdir, "svid.pem")
        key_file = os.path.join(tmpdir, "svid.key")
        bundle_file = os.path.join(tmpdir, "bundle.pem")
        try:
            leaf_pem = x509.load_der_x509_certificate(snapshot.leaf_cert_der).public_bytes(
                serialization.Encoding.PEM
            )
            with open(os.open(cert_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(leaf_pem)
            with open(os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
                f.write(_private_key_pem(snapshot.private_key))
            with open(os.open(bundle_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644), "wb") as f:
                for a in snapshot.trust_anchors:
                    f.write(a.public_bytes(serialization.Encoding.PEM))
            with self._lock:
                for ctx in (self._server, self._client):
                    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
                    ctx.set_alpn_protocols(ALPN)
                    ctx.load_verify_locations(cafile=bundle_file)
                self._snapshot = snapshot
        finally:
            for p in (key_file, cert_file, bundle_file):
                try:
                    os.unlink(p)
                except OSError:
                    pass
            try:
                os.rmdir(tmpdir)
            except OSError:
                pass


async def check_health(*, timeout: float = 5.0, socket_path: str | None = None) -> bool:
    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(
                None, lambda: fetch_only(socket_path=socket_path)
            ),
            timeout=timeout,
        )
        return True
    except Exception:
        return False


@dataclass(slots=True)
class Bootstrap:
    identity: IdentityService
    ssl: SSLContextHolder

    @property
    def spiffe_id(self) -> str:
        return self.identity.current.spiffe_id

    @property
    def svid(self) -> IdentitySnapshot:
        return self.identity.current

    async def stop(self) -> None:
        await self.identity.stop()


async def bootstrap(
    *,
    socket_path: str | None = None,
    fetch_timeout: float = 30.0,
    watch: bool = True,
) -> Bootstrap:
    """
    Fetch SVID, build TLS 1.3 contexts, optionally start rotation.

    Fails fast if the Workload API is unreachable.
    """
    ident = await asyncio.wait_for(
        asyncio.get_running_loop().run_in_executor(
            None, lambda: IdentityService.fetch(socket_path=socket_path)
        ),
        timeout=fetch_timeout,
    )
    holder = SSLContextHolder(ident.current)
    ident.subscribe(holder.reload_from_snapshot)
    if watch:
        await ident.start_watch(socket_path=socket_path)
    return Bootstrap(identity=ident, ssl=holder)


async def cli() -> int:
    identity = await bootstrap()
    snap = identity.identity
    log.info(f"{snap.current.bundle_digest=}")
    log.info(f"{snap.current.credential_id=}")
    
    log.info(f"{snap.current.remain=}")
    return 0 if await check_health() else 1




def line(tag: str, snap: IdentitySnapshot) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
    print(
        f"{now} {tag:<7} "
        f"cred={snap.credential_id[12:24]}… "
        f"bundle={snap.bundle_digest[7:19]}… "
        f"remain={snap.remain:6.1f}s",
        flush=True,
    )


async def main() -> None:
    boot = await bootstrap(watch=True)
    line("initial", boot.identity.current)

    async def on_rotate(snap: IdentitySnapshot) -> None:
        line("ROTATE", snap)


    def on(s):
         asyncio.create_task(on_rotate(s))
    
    boot.identity.subscribe(on)

    try:
        await asyncio.Event().wait()          # run forever
    finally:
        await boot.stop()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
