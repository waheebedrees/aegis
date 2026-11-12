"""mTLS handshake verification, SPIFFE identity,
and one-way separation of the TLS exporter into independent secrets.

Fail-closed rules:
  * TLS 1.3 only. The RFC 9266 exporter binding is only sound on 1.2 with
    extended master secret, which cannot be verified from Python, so 1.2 is
    not offered as an option at all.
  * The SSLObject's context must be inspectable AND CERT_REQUIRED, and the
    stack must report a verified peer certificate. Neither check degrades to
    "skip" when an attribute is missing.
  * Separate stream secrets per direction, so a peer cannot replay our own
    chunks back at us.
"""


from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, timezone
import hashlib
import hmac
import ssl
import time
from cryptography import x509

from typing import Callable, Optional, Protocol, runtime_checkable

__all__ = [
    "ALPN",
    "TRUST_DOMAIN",
    "SPIFFE_URI_PREFIX",
    "EXPORTER_LABEL",
    "EXPORTER_CONTEXT",
    "EXPORTER_LENGTH",
    "SUPPORTED_TLS_VERSIONS",
    "Authorizer",
    "TransportSetupError",
    "TlsPolicy",
    "DEFAULT_TLS_POLICY",
    "PeerVerifier",
    "SpiffeAdapter",
    "TlsConnection",
    "SessionSecrets",
    "cert_validity",
    "extract_spiffe_id",
    "split_exporter",
    
]


# ALPN is a *string*. set_alpn_protocols() requires Iterable[str] and
# selected_alpn_protocol() returns str | None. Never make this bytes.
ALPN = "aegis/v1"
TRUST_DOMAIN = "aegis"
SPIFFE_URI_PREFIX = "spiffe://"

# RFC 9266 section 3 channel-binding exporter parameters.
EXPORTER_LABEL = b"EXPORTER-Channel-Binding"
EXPORTER_CONTEXT = b""          # RFC 9266: empty context, use_context=1
EXPORTER_LENGTH = 32

SUPPORTED_TLS_VERSIONS: frozenset[str] = frozenset({"TLSv1.3"})
_FORBIDDEN_CIPHER_TOKENS = ("NULL", "ANON", "EXPORT", "RC4", "3DES", "DES", "MD5", "CBC")

_MAX_SPIFFE_URI = 2048
_MAX_TRUST_DOMAIN = 255

Authorizer = Callable[[str], bool]

class TransportSetupError(Exception):
    __slots__ = ("code", "detail")

    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail

@dataclass(frozen=True, slots=True)
class TlsPolicy:
    """Immutable local transport policy."""

    allowed_versions: frozenset[str] = SUPPORTED_TLS_VERSIONS
    allowed_alpns: tuple[str, ...] = (ALPN,)
    exporter_label: bytes = EXPORTER_LABEL
    exporter_context: bytes = EXPORTER_CONTEXT
    clock_skew_s: float = 30.0

    def __post_init__(self) -> None:
        if not self.allowed_versions or not (self.allowed_versions <= SUPPORTED_TLS_VERSIONS):
            raise ValueError(
                f"only {sorted(SUPPORTED_TLS_VERSIONS)} are supported; "
                f"got {sorted(self.allowed_versions)!r}"
            )
        if not self.allowed_alpns or any(
            not isinstance(a, str) or not a or not a.isascii() or len(a) > 255
            for a in self.allowed_alpns
        ):
            raise ValueError("allowed_alpns must be non-empty ASCII strings")
        if not isinstance(self.exporter_label, bytes) or not self.exporter_label:
            raise ValueError("exporter_label must be non-empty bytes")
        if not isinstance(self.exporter_context, bytes):
            raise ValueError("exporter_context must be bytes")
        if type(self.clock_skew_s) not in (int, float) or not 0 <= self.clock_skew_s <= 300:
            raise ValueError("clock_skew_s must be a number in 0..300")


DEFAULT_TLS_POLICY = TlsPolicy()




@runtime_checkable
class PeerVerifier(Protocol):
    """Local peer-certificate verifier."""

    def verify_peer(self, cert: x509.Certificate) -> str: ...



@dataclass(frozen=True, slots=True)
class SessionSecrets:
    """Domain-separated outputs of the TLS exporter.

    channel_binding may be published in PoPs and audit records. The two stream
    secrets are independent of it and of each other; neither can be derived
    from a disclosed channel_binding.
    """

    channel_binding: bytes = field(repr=False)
    stream_ikm_c2s: bytes = field(repr=False)
    stream_ikm_s2c: bytes = field(repr=False)

    def for_role(self, is_client: bool) -> tuple[bytes, bytes]:
        """Return (send_ikm, recv_ikm) for this endpoint."""
        if is_client:
            return self.stream_ikm_c2s, self.stream_ikm_s2c
        return self.stream_ikm_s2c, self.stream_ikm_c2s



def cert_validity(cert: x509.Certificate) -> tuple[float, float]:
    """Return (not_before, not_after) as POSIX UTC seconds."""
    try:
        nb = cert.not_valid_before_utc
        na = cert.not_valid_after_utc
    except AttributeError:
        nb = cert.not_valid_before.replace(tzinfo=UTC)
        na = cert.not_valid_after.replace(tzinfo=UTC)
    return nb.timestamp(), na.timestamp()


def _parse_spiffe_uri(uri: str) -> tuple[str, str]:
    """Validate spiffe://<trust-domain>/<path> and return (td, path)."""
    if not isinstance(uri, str) or not uri.startswith(SPIFFE_URI_PREFIX):
        raise TransportSetupError("URI is not a SPIFFE ID")
    if len(uri) > _MAX_SPIFFE_URI or any(ord(c) <= 0x20 or ord(c) >= 0x7F for c in uri):
        raise TransportSetupError("invalid characters or length in SPIFFE ID")
    if "?" in uri or "#" in uri or "@" in uri or "%" in uri:
        raise TransportSetupError("SPIFFE ID must not contain userinfo, escapes, "
                                  "query, or fragment")
    rest = uri[len(SPIFFE_URI_PREFIX):]
    trust_domain, sep, path = rest.partition("/")
    if not trust_domain or len(trust_domain) > _MAX_TRUST_DOMAIN or not sep or not path:
        raise TransportSetupError("SPIFFE ID requires trust domain and workload path")
    if trust_domain != trust_domain.lower():
        raise TransportSetupError("SPIFFE trust domain must be lowercase")
    if any(seg in ("", ".", "..") for seg in path.split("/")):
        raise TransportSetupError("SPIFFE ID contains invalid path segment")
    return trust_domain, path


def extract_spiffe_id(cert: x509.Certificate) -> str:
    """Extract the single SPIFFE URI SAN from an already chain-verified cert."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
    except x509.ExtensionNotFound:
        raise TransportSetupError("peer certificate missing SAN extension") from None
    except Exception as exc:
        raise TransportSetupError(
            f"peer certificate SAN parse failed: {type(exc).__name__}"
        ) from None

    ids = [u for u in uris if isinstance(u, str) and u.startswith(SPIFFE_URI_PREFIX)]
    if len(ids) != 1:
        raise TransportSetupError(f"expected exactly one SPIFFE URI SAN, got {len(ids)}")
    _parse_spiffe_uri(ids[0])
    return ids[0]



def split_exporter(raw_exporter: bytes, *, alpn: str = ALPN) -> SessionSecrets:
    """HKDF-style split of the raw 32-byte exporter into three secrets.

    One-way domain separation: recording channel_binding in PoPs or audit logs
    reveals nothing about either stream secret, and the two directions are
    independent so chunks cannot be reflected.
    """
    if not isinstance(raw_exporter, (bytes, bytearray)) or len(raw_exporter) != EXPORTER_LENGTH:
        raise TransportSetupError("raw exporter must be exactly 32 bytes")
    if not isinstance(alpn, str) or not alpn.isascii() or not alpn:
        raise TransportSetupError("alpn must be a non-empty ASCII string")
    salt = b"aegis-exporter-root-v4:" + alpn.encode("ascii")
    prk = hmac.new(salt, bytes(raw_exporter), hashlib.sha256).digest()
    return SessionSecrets(
        channel_binding=hmac.new(prk, b"aegis-cb-v4\x01", hashlib.sha256).digest(),
        stream_ikm_c2s=hmac.new(prk, b"aegis-stream-c2s-v4\x02", hashlib.sha256).digest(),
        stream_ikm_s2c=hmac.new(prk, b"aegis-stream-s2c-v4\x03", hashlib.sha256).digest(),
    )


def _derive_session_secrets(
    sslsock: ssl.SSLObject,
    policy: TlsPolicy,
    alpn: str,
) -> SessionSecrets:
    """Derive and immediately consume the TLS exporter.

    The raw 32-byte exporter is never returned, stored, or passed across an
    API boundary. It lives only inside this function as a mutable buffer,
    which is zeroed in `finally` before the function returns.

    CPython limitation: `native_exporter` returns an immutable `bytes`
    object, which may remain in memory until garbage collection. The
    `bytearray` we control is scrubbed, but the caller of `native_exporter`
    cannot zero the original `bytes`. If the threat model requires strict
    zeroization, change `native_exporter` to write into a caller-supplied
    `bytearray` and call it with `bytearray(EXPORTER_LENGTH)`.
    """
    from libs.transport._exporter import native_exporter

    raw = native_exporter(
        sslsock,
        EXPORTER_LENGTH,
        policy.exporter_label,
        context=policy.exporter_context,
    )
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != EXPORTER_LENGTH:
        raise TransportSetupError("exporter must return exactly 32 raw bytes")

    # Copy into a scrubable buffer, then drop the last reference to the
    # immutable original. From this point on, the only reachable copy is
    # `scratch`, which we zero in `finally`.
    scratch = bytearray(raw)
    del raw

    try:
        salt = b"aegis-exporter-root-v4:" + alpn.encode("ascii")
        prk = hmac.new(salt, bytes(scratch), hashlib.sha256).digest()
        return SessionSecrets(
            channel_binding=hmac.new(
                prk, b"aegis-cb-v4\x01", hashlib.sha256
            ).digest(),
            stream_ikm_c2s=hmac.new(
                prk, b"aegis-stream-c2s-v4\x02", hashlib.sha256
            ).digest(),
            stream_ikm_s2c=hmac.new(
                prk, b"aegis-stream-s2c-v4\x03", hashlib.sha256
            ).digest(),
        )
    finally:
        # Zero the buffer we own. `prk` is `bytes` and cannot be scrubbed,
        # but it goes out of scope when this frame exits. The three derived
        # outputs are the only secrets that leave this function.
        scratch[:] = b"\x00" * EXPORTER_LENGTH



@dataclass(frozen=True, slots=True)
class SpiffeAdapter:
    """SPIFFE mTLS peer verifier: trust domain, ACL, and no self-loop."""

    peer_id: str
    authorize: Authorizer
    target_node_id: str | None = None
    trust_domain: str = TRUST_DOMAIN

    def __post_init__(self) -> None:
        # peer_id must be a *fully formed* SPIFFE ID. Previously any non-empty
        # string passed, which silently disabled the self-loop check below.
        if not isinstance(self.peer_id, str) or not self.peer_id:
            raise ValueError("peer_id must be a non-empty string")
        _parse_spiffe_uri(self.peer_id)

        if not callable(self.authorize):
            raise TypeError("authorize must be callable")

        if not isinstance(self.trust_domain, str) or not self.trust_domain:
            raise ValueError("trust_domain must be a non-empty string")
        # Reuse the SPIFFE URI validator so lowercase / length / character
        # rules are enforced by the same code path that checks peer certs.
        # The trailing "/_" is a throwaway path — only the authority matters.
        td, _ = _parse_spiffe_uri(f"{SPIFFE_URI_PREFIX}{self.trust_domain}/_")
        if td != self.trust_domain:
            raise ValueError(
                f"trust_domain must be a bare lowercase authority: "
                f"{self.trust_domain!r}"
            )

        if self.target_node_id is not None:
            # A typo here used to surface as "peer identity mismatch" at
            # handshake time; reject at construction instead.
            if not isinstance(self.target_node_id, str) or not self.target_node_id:
                raise ValueError("target_node_id must be a non-empty string")
            _parse_spiffe_uri(self.target_node_id)

    def check_trust_domain(self, spiffe_id: str) -> str:
        td, _ = _parse_spiffe_uri(spiffe_id)
        if td != self.trust_domain:
            raise TransportSetupError(
                f"trust domain {td!r} != expected {self.trust_domain!r}"
            )
        return td

    def verify_peer(self, cert: x509.Certificate) -> str:
        spiffe_id = extract_spiffe_id(cert)          # already URI-validated
        self.check_trust_domain(spiffe_id)

        # Self-loop: both sides are now guaranteed to be full SPIFFE IDs,
        # so this comparison actually fires.
        if spiffe_id == self.peer_id:
            raise TransportSetupError("self-connection rejected")

        # Pin before authorize. When the caller already knows the one peer
        # they want, don't hand a wrong identity to the authorizer — it may
        # log, rate-limit, or otherwise have side effects.
        if self.target_node_id is not None and spiffe_id != self.target_node_id:
            raise TransportSetupError("peer identity mismatch")

        try:
            allowed = self.authorize(spiffe_id)
        except Exception as exc:
            raise TransportSetupError(
                f"authorizer raised {type(exc).__name__}"
            ) from None
        if allowed is not True:
            raise TransportSetupError(f"peer not authorized: {spiffe_id!r}")

        return spiffe_id

    
def make_adapter(
    peer_id: str,
    authorize: Authorizer,
    target_node_id: str | None = None,
    *,
    trust_domain: str,
) -> SpiffeAdapter:
    return SpiffeAdapter(
        peer_id=peer_id,
        target_node_id=target_node_id,
        authorize=authorize,
        trust_domain=trust_domain,
    )
    

@dataclass(frozen=True, slots=True)
class TlsConnection:
    """Immutable snapshot of a verified peer identity and separated secrets."""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    tls_object: object = field(repr=False)
    peer_id: str
    alpn: str
    tls_version: str
    secrets: SessionSecrets = field(repr=False)
    not_before: float
    not_after: float

    @property
    def channel_binding(self) -> bytes:
        """Public channel-binding bytes. Never exposes a stream secret."""
        return self.secrets.channel_binding

    @classmethod
    def wrap(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        adapter: PeerVerifier,
        policy: TlsPolicy = DEFAULT_TLS_POLICY,
        now: Optional[float] = None,
    ) -> "TlsConnection":
        """Verify a completed TLS handshake; close the writer on any failure."""
        try:
            return cls._verify(
                reader, writer,
                adapter=adapter,
                policy=policy,
                now=time.time() if now is None else now,
            )
        except TransportSetupError:
            writer.close()
            raise
        except BaseException as exc:
            writer.close()
            if isinstance(exc, Exception):
                raise TransportSetupError(type(exc).__name__) from exc
            raise

    @classmethod
    async def awrap(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        adapter: PeerVerifier,
        policy: TlsPolicy = DEFAULT_TLS_POLICY,
        now: Optional[float] = None,
    ) -> "TlsConnection":
        """Async variant of wrap that also awaits transport close on failure."""
        try:
            return cls.wrap(
                reader, writer,
                adapter=adapter,
                policy=policy,
                now=now,
            )
        except BaseException:
            try:
                await writer.wait_closed()
            except Exception:
                pass
            raise

    @classmethod
    def _verify(
        cls,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        *,
        adapter: PeerVerifier,
        policy: TlsPolicy,
        now: float,
    ) -> "TlsConnection":
        """Check order, cheapest first, no fail-open branch:
            1. TLS present and a cipher negotiated (handshake complete)
            2. Cipher not on the forbidden list
            3. TLS version in the allowed set
            4. ALPN negotiated and allowed
            5. Context inspectable AND CERT_REQUIRED
            6. Stack reports a verified peer certificate (dict + DER)
            7. Certificate validity window with bounded skew
            8. Peer identity, trust domain, ACL, expected-peer pin
            9. Exporter extraction and one-way split; raw exporter discarded
        """
        if not isinstance(adapter, PeerVerifier):
            raise TransportSetupError("adapter must implement verify_peer")

        sslsock = writer.get_extra_info("ssl_object")
        if not isinstance(sslsock, ssl.SSLObject):
            raise TransportSetupError("socket is not TLS")

        # 1-2. Handshake complete and acceptable cipher.
        cipher_info = sslsock.cipher()
        if not cipher_info or not cipher_info[0]:
            raise TransportSetupError("no cipher negotiated")
        cipher_upper = str(cipher_info[0]).upper()
        if any(tok in cipher_upper for tok in _FORBIDDEN_CIPHER_TOKENS):
            raise TransportSetupError(f"forbidden cipher: {cipher_info[0]}")

        # 3. TLS version.
        version = sslsock.version()
        if version not in policy.allowed_versions:
            raise TransportSetupError(
                f"TLS version {version!r} not in {sorted(policy.allowed_versions)}"
            )

        # 4. ALPN.
        negotiated_alpn = sslsock.selected_alpn_protocol()
        if negotiated_alpn is None or negotiated_alpn not in policy.allowed_alpns:
            raise TransportSetupError(
                f"ALPN mismatch: got {negotiated_alpn!r}, "
                f"allowed {policy.allowed_alpns!r}"
            )

        # 5. Strict mTLS context mode. Missing context is fatal, not skipped:
        #    getpeercert() returns an attacker-supplied cert under CERT_NONE.
        ctx = getattr(sslsock, "context", None)
        if not isinstance(ctx, ssl.SSLContext):
            raise TransportSetupError("TLS context is not inspectable")
        if ctx.verify_mode != ssl.CERT_REQUIRED:
            raise TransportSetupError("SSLContext.verify_mode must be CERT_REQUIRED")
        if ctx.check_hostname:
            # SPIFFE identity is URI-SAN based; DNS hostname checking must be
            # off, and leaving it on silently changes which SANs matter.
            raise TransportSetupError("check_hostname must be False for SPIFFE mTLS")

        # 6. Verified peer certificate. The dict form is empty unless OpenSSL
        #    actually completed chain verification; the DER form is not.
        if not sslsock.getpeercert():
            raise TransportSetupError("peer certificate not verified by TLS stack")
        der = sslsock.getpeercert(binary_form=True)
        if not der:
            raise TransportSetupError("no peer certificate presented")
        try:
            cert = x509.load_der_x509_certificate(der)
        except Exception as exc:
            raise TransportSetupError(
                f"peer certificate DER parse failed: {type(exc).__name__}"
            ) from None

        # 7. Validity window.
        not_before, not_after = cert_validity(cert)
        if not_after <= not_before:
            raise TransportSetupError("peer certificate has an empty validity window")
        if now + policy.clock_skew_s < not_before:
            raise TransportSetupError("peer certificate not yet valid")
        if now - policy.clock_skew_s > not_after:
            raise TransportSetupError("peer certificate expired")

        # 8. Identity and authorization.
        peer_id = adapter.verify_peer(cert)
        if not isinstance(peer_id, str) or not peer_id:
            raise TransportSetupError("verifier returned an invalid peer id")
        # 9. Exporter split. The raw exporter never leaves this frame.
        secrets_ = _derive_session_secrets(sslsock, policy, negotiated_alpn)


        return cls(
            reader=reader,
            writer=writer,
            tls_object=sslsock,
            peer_id=peer_id,
            alpn=negotiated_alpn,
            tls_version=version,
            secrets=secrets_,
            not_before=not_before,
            not_after=not_after,
        )

    




