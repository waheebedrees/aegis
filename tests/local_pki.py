

from __future__ import annotations

import asyncio
from datetime import datetime, UTC, timedelta
import sys 
import os
from dataclasses import dataclass
from pathlib import Path
import ssl
import tempfile
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from typing import Callable, Collection, Iterable, Mapping, Optional

# ALPN is a *string*. set_alpn_protocols() requires Iterable[str] and
# selected_alpn_protocol() returns str | None. Never make this bytes.
ALPN = "aegis/v1"
TRUST_DOMAIN = "aegis"
SPIFFE_URI_PREFIX = "spiffe://"


Authorizer = Callable[[str], bool]


def authorize_id(spiffe_id: str) -> Authorizer:
    """Accept exactly one SPIFFE ID. Use for client dialing one known server."""
    if not spiffe_id.startswith("spiffe://"):
        raise ValueError(f"not a spiffe id: {spiffe_id!r}")
    return lambda peer: peer == spiffe_id

def authorize_one_of(ids: Iterable[str]) -> Authorizer:
    """Accept any of a fixed set. Use for server with N known nodes."""
    allowed = frozenset(ids)
    if not allowed:
        raise ValueError("empty allowlist; use authorize_member_of or accept nothing explicitly")
    for i in allowed:
        if not i.startswith("spiffe://"):
            raise ValueError(f"not a spiffe id: {i!r}")
    return lambda peer: peer in allowed

def authorize_member_of(trust_domain: str) -> Authorizer:
    """Accept any workload in a trust domain. e.g. 'spiffe://aegis-test'."""
    td = trust_domain.rstrip("/")
    if not td.startswith("spiffe://"):
        raise ValueError(f"not a trust domain: {trust_domain!r}")
    prefix = td + "/"
    return lambda peer: peer.startswith(prefix)



def utcnow() -> datetime:
    return datetime.now(UTC)


def pem(cert: x509.Certificate, key: ec.EllipticCurvePrivateKey):
    return (
    cert.public_bytes(serialization.Encoding.PEM),
    key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )




def _harden(fd, path):
    try:
        os.fchmod(fd, 0o600)  # no-op fallback below
    except (OSError, AttributeError, NotImplementedError):
        if sys.platform == "win32":
            try:
                _harden_windows(Path(path))
            except Exception as exc:
                raise OSError(f"could not harden {path} on Windows") from exc
        else:
            raise

def _harden_windows(path: Path) -> None:
    import win32security, ntsecuritycon # type: ignore
    import win32api # type: ignore

    sd = win32security.SECURITY_DESCRIPTOR()
    sd.SetSecurityDescriptorDacl(1, None, 0)  # type: ignore # NULL DACL == deny everyone
    # Then grant only the current user:
    user, _domain, _type = win32security.LookupAccountName(
        None, win32api.GetUserName()
    )
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION,
        ntsecuritycon.FILE_ALL_ACCESS,
        user,
    )
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(
        str(path), win32security.DACL_SECURITY_INFORMATION, sd
    )

def write_secret(path: Path, data: bytes, *, mode: int = 0o600) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(str(path), flags, mode)

    try:
        if mode == 0o600:
            _harden(fd, str(path))
        with os.fdopen(fd, "wb") as f:   # fdopen takes ownership of fd
            fd = -1                      # so the except branch does not double-close
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return str(path)




@dataclass(frozen=True, slots=True)
class CertFiles:
    cert_path: str
    key_path: str
    spiffe_id: str 
    trust_domain:str

@dataclass(frozen=True, slots=True)
class LocalSSL:
    spiffe_id: str 
    server_ssl: ssl.SSLContext | None = None
    client_ssl: ssl.SSLContext | None = None





@dataclass(frozen=True, slots=True)
class Endpoint:
    host: str
    port: int
    spiffe_id: str




@dataclass(frozen=True, slots=True)
class NodeSpec:
    role: str
    host: str
    port: int
    spiffe_id: str
    nodes: dict
    certs: CertFiles
    trust_domain: str 
    server_ssl: ssl.SSLContext | None = None
    client_ssl: ssl.SSLContext | None = None
    enrollment_max_skew: int = 30
    
    @property
    def name(self):
        return self.role
    
    @property 
    def node_spiffe(self):
        return f"{SPIFFE_URI_PREFIX}{self.trust_domain}"

    def get_node_spiffe_id(self, name):
        spiffe_id= self.nodes.get(name)
        if spiffe_id is None:
            raise ValueError("spiffe_id not register")
        return spiffe_id

    def allowd(self):
        return authorize_one_of({ e for e in self.nodes.values()})

    def server_adapter(self):
        from libs.transport.tls import make_adapter
        return make_adapter(
            peer_id=self.spiffe_id,
            trust_domain=self.trust_domain,
            authorize=self.allowd(),
            target_node_id=None,
        )

    
    
    def client_adapter(self, target_id):
        from libs.transport.tls import make_adapter
        spiffe_id = self.get_node_spiffe_id(target_id)
        return make_adapter(
            peer_id=self.spiffe_id,
            trust_domain=self.trust_domain,
            authorize=authorize_id(spiffe_id),
            target_node_id=spiffe_id,
        )



def _base_context(ctx: ssl.SSLContext) -> ssl.SSLContext:
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols([ALPN])
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def server_ssl_context(*, certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = _base_context(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER))
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    ctx.num_tickets = 0  # Disable TLS 1.3 session resumption
    return ctx


def client_ssl_context(*, certfile: str, keyfile: str, cafile: str) -> ssl.SSLContext:
    ctx = _base_context(ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT))
    ctx.check_hostname = False  # Identity is validated via SPIFFE URI SAN pinned in wrap()
    ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
    ctx.load_verify_locations(cafile=cafile)
    return ctx


def issue_leaf(
    tmp_path: Path,
    *, 
    name: str, 
    trust_domain: str, 
    spiffe_id: str, 
    ca_key, 
    ca_cert,
    not_after_seconds: float | None = None,
) -> CertFiles:
    
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    not_after = (
        now + timedelta(seconds=not_after_seconds)
        if not_after_seconds is not None
        else now + timedelta(days=1)
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(spiffe_id)]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True, content_commitment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem, key_pem = pem(cert, key)
    path = tmp_path / f"{name}"
    cert_path = write_secret(Path(f"{path}.cert.pem"), cert_pem)
    key_path = write_secret(Path(f"{path}.key.pem"), key_pem)

    return CertFiles(
        cert_path=cert_path,
        key_path=key_path,
        spiffe_id=spiffe_id,
        trust_domain=trust_domain,
    )

def generate_node_ca(
    tmp_path: Path,
    node_id: str = "aegis-test-ca",
    validity_days: int = 3650,
    *,
    not_after_seconds_from_now: Optional[float] = None,
):
    key = ec.generate_private_key(ec.SECP256R1())
    now = utcnow()

    if not_after_seconds_from_now is not None:
        not_after = now + timedelta(seconds=not_after_seconds_from_now)
        # X.509 requires not_before < not_after. If the CA already expired,
        # backdate not_before so the window is coherent (a "valid for 1
        # minute, ended 60 minutes ago" cert is legal; "begins after it
        # ends" is not).
        not_before = min(now, not_after - timedelta(minutes=1))
    else:
        not_before = now
        not_after = now + timedelta(days=validity_days)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "local-org"),
        x509.NameAttribute(NameOID.COMMON_NAME, node_id),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_agreement=False,
                key_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                data_encipherment=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_pem, key_pem = pem(cert, key)
    cert_path = write_secret(tmp_path / ".ca.cert.pem", cert_pem)
    return cert, key, cert_path



class PKI:
    def __init__(
        self,
        tmp_path: Path,
        nodes,
        trust_domain: str = "aegis-test",
        *,
        ca_not_after_seconds_from_now: Optional[float] = None,
    ) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.tmp_path = tmp_path
        self.trust_domain = trust_domain
        self._node_spiffe = f"{SPIFFE_URI_PREFIX}{trust_domain}"
        self.ca_cert, self.ca_key, self.ca_cert_path = generate_node_ca(
            self.tmp_path,
            self._node_spiffe,
            not_after_seconds_from_now=ca_not_after_seconds_from_now,
        )
        self._nodes = {name: f"{self._node_spiffe}/{name}" for name in nodes}
    def get_node_spiffe_id(self, name):
        spiffe_id= self._nodes.get(name)
        if spiffe_id is None:
            raise ValueError("spiffe_id not register")
        return spiffe_id

    def make_cert(self, name, agent_not_after_seconds: float | None = None) -> CertFiles:
        spiffe_id= self.get_node_spiffe_id(name)
        return issue_leaf(
            tmp_path=self.tmp_path,
            name=name,
            spiffe_id=spiffe_id,
            ca_key=self.ca_key,
            ca_cert=self.ca_cert,
            not_after_seconds=agent_not_after_seconds,
            trust_domain=self.trust_domain,
        )

    def make_node(self, name, host, port,  agent_not_after_seconds: float | None = None):

        spiffe_id= self.get_node_spiffe_id(name)
        certs = self.make_cert(name, agent_not_after_seconds)
        server_ssl = server_ssl_context(
            certfile=certs.cert_path,
            keyfile=certs.key_path,
            cafile=self.ca_cert_path,
        )
        client_ssl = client_ssl_context(
            certfile=certs.cert_path,
            keyfile=certs.key_path,
            cafile=self.ca_cert_path,
        )   
        return NodeSpec(
            role=name,
            certs=certs,
            spiffe_id=spiffe_id,
            host=host, 
            port=port,
            server_ssl=server_ssl,
            nodes= self._nodes,
            trust_domain=self.trust_domain,
            client_ssl=client_ssl,
        )
    

