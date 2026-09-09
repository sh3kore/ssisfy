#!/usr/bin/env python3
"""Unified SSIS security analyzer for authorized offline assessments.

Current capabilities include SSIS protection-level fingerprinting, password-based
XML Encryption decryption, offline DPAPI decryption, artifact extraction, and
optional secret sidecar generation.
"""
from __future__ import annotations

import argparse
import base64
import json
import string
import xml.etree.ElementTree as ET
from xml.dom import minidom
import zipfile
from dataclasses import asdict, dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

try:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1
    from Crypto.Protocol.KDF import PBKDF2
except ImportError as exc:
    raise SystemExit("Install dependency first: pip install pycryptodome") from exc

DTS_NS = "www.microsoft.com/SqlServer/Dts"
XMLENC_NS = "http://www.w3.org/2001/04/xmlenc#"
DPAPI_PREFIX = bytes.fromhex("01000000d08c9ddf0115d1118c7a00c04fc297eb")
PROTECTION_NAMES = {
    0: "DontSaveSensitive",
    1: "EncryptSensitiveWithUserKey",
    2: "EncryptSensitiveWithPassword",
    3: "EncryptAllWithPassword",
    4: "EncryptAllWithUserKey",
    5: "ServerStorage",
}
PRINTABLE = set(bytes(string.printable, "ascii"))


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].split(":", 1)[-1]


def namespace_uri(tag: str) -> str | None:
    return tag[1:].split("}", 1)[0] if tag.startswith("{") and "}" in tag else None


def attr_by_local_name(element: ET.Element, name: str) -> str | None:
    for key, value in element.attrib.items():
        if local_name(key) == name:
            return value
    return None


def elements_by_local_name(root: ET.Element, name: str) -> list[ET.Element]:
    return [element for element in root.iter() if local_name(element.tag) == name]


def element_text(element: ET.Element) -> str:
    return "".join(element.itertext()).strip()


def decode_b64(text: str) -> bytes:
    normalized = "".join(text.split())
    normalized += "=" * ((-len(normalized)) % 4)
    return base64.b64decode(normalized, validate=False)


def pretty_xml_bytes(data: bytes) -> bytes:
    """Return readable XML while preserving namespaces and CDATA sections."""
    try:
        document = minidom.parseString(data)
        formatted = document.toprettyxml(indent="  ", encoding="utf-8")
        # Remove formatter-only blank lines while preserving meaningful XML text.
        lines = [line for line in formatted.splitlines() if line.strip()]
        return b"\n".join(lines) + b"\n"
    except Exception:
        # Keep the decrypted bytes available even if a non-standard artifact cannot
        # be parsed by the presentation formatter.
        return data


def dpapi_master_key_guid(raw: bytes) -> str | None:
    """Return the DPAPI blob's referenced master-key GUID when available."""
    if not raw.startswith(DPAPI_PREFIX):
        return None
    try:
        from impacket.dpapi import DPAPI_BLOB
        from impacket.uuid import bin_to_string
        return bin_to_string(DPAPI_BLOB(raw)["GuidMasterKey"])
    except Exception:
        return None


def element_path(root: ET.Element, target: ET.Element) -> str:
    result: list[str] = []

    def walk(node: ET.Element, current: list[str]) -> bool:
        name = local_name(node.tag)
        siblings = [x for x in list(node) if local_name(x.tag) == name]
        index = siblings.index(node) if node in siblings else 0
        next_path = current + [f"{name}[{index}]"]
        if node is target:
            result.extend(next_path)
            return True
        return any(walk(child, next_path) for child in list(node))

    walk(root, [])
    return "/" + "/".join(result)


@dataclass
class ProtectedRegion:
    kind: str
    path: str
    encrypted: bool
    payload_bytes: int | None = None
    has_dpapi_signature: bool = False
    has_salt: bool = False
    has_iv: bool = False


@dataclass
class FingerprintResult:
    source_name: str
    source_path: str | None
    sha256: str
    byte_size: int
    parse_status: str
    root_namespace: str | None = None
    root_element: str | None = None
    protection_level: int | None = None
    protection_name: str | None = None
    confidence: str = "unknown"
    scope: str = "unknown"
    backend_required: str = "unknown"
    master_key_guid: str | None = None
    root_encrypted: bool = False
    creator_name: str | None = None
    creator_computer_name: str | None = None
    product_version: str | None = None
    visible_metadata: dict[str, Any] = field(default_factory=dict)
    protected_regions: list[ProtectedRegion] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def fingerprint_bytes(data: bytes, source_name: str = "<bytes>", source_path: str | None = None) -> FingerprintResult:
    result = FingerprintResult(source_name, source_path, sha256(data).hexdigest(), len(data), "unparsed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        result.parse_status = "invalid_xml"
        result.error = str(exc)
        return result

    result.parse_status = "valid_xml"
    result.root_namespace = namespace_uri(root.tag)
    result.root_element = local_name(root.tag)
    result.creator_name = attr_by_local_name(root, "CreatorName")
    result.creator_computer_name = attr_by_local_name(root, "CreatorComputerName")
    result.product_version = attr_by_local_name(root, "LastModifiedProductVersion")
    result.root_encrypted = attr_by_local_name(root, "Encrypted") == "1"
    declared_level = attr_by_local_name(root, "ProtectionLevel")
    if declared_level is not None:
        try:
            result.protection_level = int(declared_level)
        except ValueError:
            result.warnings.append(f"Invalid ProtectionLevel: {declared_level!r}")

    result.visible_metadata = {
        key: value for key, value in {
            "creation_name": attr_by_local_name(root, "CreationName"),
            "object_name": attr_by_local_name(root, "ObjectName"),
            "package_type": attr_by_local_name(root, "PackageType"),
            "version_build": attr_by_local_name(root, "VersionBuild"),
        }.items() if value is not None
    }

    if result.root_namespace == XMLENC_NS and result.root_element == "EncryptedData":
        result.protection_level = 3
        result.protection_name = PROTECTION_NAMES[3]
        result.confidence = "high"
        result.scope = "whole_package"
        result.backend_required = "password"
        for cipher in elements_by_local_name(root, "CipherValue"):
            try:
                raw = decode_b64(element_text(cipher))
                valid = True
            except Exception:
                raw, valid = b"", False
            result.protected_regions.append(ProtectedRegion(
                "xmlenc_cipher_value", element_path(root, cipher), True,
                len(raw) if valid else None, raw.startswith(DPAPI_PREFIX),
                attr_by_local_name(root, "Salt") is not None,
                attr_by_local_name(root, "IV") is not None,
            ))
        return result

    if result.root_namespace != DTS_NS or result.root_element != "Executable":
        result.warnings.append("Unrecognized SSIS root element or namespace.")
        return result

    if result.root_encrypted:
        result.protection_level = result.protection_level or 4
        result.protection_name = PROTECTION_NAMES.get(result.protection_level)
        result.confidence = "high" if result.protection_level == 4 else "medium"
        result.scope = "whole_package"
        result.backend_required = "dpapi"
        try:
            raw = decode_b64(element_text(root))
            valid = True
        except Exception:
            raw, valid = b"", False
        result.protected_regions.append(ProtectedRegion(
            "dpapi_whole_package", "/Executable[0]", True,
            len(raw) if valid else None, raw.startswith(DPAPI_PREFIX),
        ))
        result.master_key_guid = dpapi_master_key_guid(raw)
        return result

    encrypted_data = elements_by_local_name(root, "EncryptedData")
    encrypted_sensitive = [
        element for element in root.iter()
        if attr_by_local_name(element, "Encrypted") == "1"
        and attr_by_local_name(element, "Sensitive") == "1"
    ]
    for element in encrypted_data:
        cipher = next((x for x in element.iter() if local_name(x.tag) == "CipherValue"), None)
        try:
            raw = decode_b64(element_text(cipher)) if cipher is not None else b""
            valid = cipher is not None
        except Exception:
            raw, valid = b"", False
        result.protected_regions.append(ProtectedRegion(
            "xmlenc_sensitive_region", element_path(root, element), True,
            len(raw) if valid else None, raw.startswith(DPAPI_PREFIX),
            attr_by_local_name(element, "Salt") is not None,
            attr_by_local_name(element, "IV") is not None,
        ))
    for element in encrypted_sensitive:
        try:
            raw = decode_b64(element_text(element))
            valid = True
        except Exception:
            raw, valid = b"", False
        result.protected_regions.append(ProtectedRegion(
            "dpapi_sensitive_property", element_path(root, element), True,
            len(raw) if valid else None, raw.startswith(DPAPI_PREFIX),
        ))
        if result.master_key_guid is None:
            result.master_key_guid = dpapi_master_key_guid(raw)

    if result.protection_level == 0:
        result.confidence, result.scope, result.backend_required = "high", "none", "none"
    elif result.protection_level == 2 or encrypted_data:
        result.protection_level, result.protection_name = 2, PROTECTION_NAMES[2]
        result.confidence, result.scope, result.backend_required = "high", "sensitive_properties", "password"
    elif result.protection_level == 1 or encrypted_sensitive:
        result.protection_level, result.protection_name = 1, PROTECTION_NAMES[1]
        result.confidence, result.scope, result.backend_required = "high", "sensitive_properties", "dpapi"
    else:
        result.warnings.append("Readable DTS:Executable has no recognized protection marker.")
    result.protection_name = PROTECTION_NAMES.get(result.protection_level, result.protection_name)
    return result


def fingerprint_file(path: str | Path) -> FingerprintResult:
    path = Path(path)
    return fingerprint_bytes(path.read_bytes(), path.name, str(path))


# ------------------------- password backend -------------------------

def parse_xmlenc(data: bytes) -> tuple[bytes, bytes, bytes]:
    root = ET.fromstring(data)
    if local_name(root.tag) != "EncryptedData":
        encrypted = next((x for x in root.iter() if local_name(x.tag) == "EncryptedData"), None)
        if encrypted is None:
            raise ValueError("No XML Encryption EncryptedData element found")
        root = encrypted
    salt = attr_by_local_name(root, "Salt")
    iv = attr_by_local_name(root, "IV")
    cipher = next((x for x in root.iter() if local_name(x.tag) == "CipherValue"), None)
    if not salt or not iv or cipher is None:
        raise ValueError("Missing Salt, IV, or CipherValue")
    return decode_b64(salt), decode_b64(iv), decode_b64(element_text(cipher))


def decrypt_password_candidate(password: str, salt: bytes, iv: bytes, cipher_value: bytes, iterations: int = 1000, encoding: str = "utf-8") -> bytes | None:
    try:
        password_bytes = password.encode(encoding)
        key = PBKDF2(password_bytes, salt, dkLen=32, count=iterations, hmac_hash_module=SHA1)
        ciphertext = cipher_value[16:] if cipher_value[:16] == iv else cipher_value
        if len(ciphertext) == 0 or len(ciphertext) % 16:
            return None
        plaintext = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    except Exception:
        return None
    sample = plaintext[:64]
    if not sample.startswith(b"<"):
        return None
    if not sample or sum(byte in PRINTABLE for byte in sample) / len(sample) < 0.95:
        return None
    return plaintext


def unpad_iso10126(plaintext: bytes) -> bytes:
    if not plaintext:
        raise ValueError("Empty plaintext")
    pad = plaintext[-1]
    if not 1 <= pad <= 16 or pad > len(plaintext):
        raise ValueError("Invalid padding length")
    return plaintext[:-pad]


# ------------------------- DPAPI backend -------------------------

class DpapiBackend:
    """Offline DPAPI backend for supplied artifacts only.

    This backend does not connect to hosts, collect profiles, or retrieve
    master-key files. The operator must supply the .dtsx file, the matching
    master-key artifact, the user SID, and either the authorized user password
    or an already recovered master key.
    """

    def __init__(self):
        try:
            from impacket.dpapi import (
                DPAPI_BLOB, MasterKey, MasterKeyFile, DomainKey,
                DPAPI_DOMAIN_RSA_MASTER_KEY, PVK_FILE_HDR, PRIVATE_KEY_BLOB,
                privatekeyblob_to_pkcs1, deriveKeysFromUser, deriveKeysFromUserkey,
            )
            from impacket.uuid import bin_to_string
            from Crypto.Cipher import PKCS1_v1_5
        except ImportError as exc:
            raise RuntimeError("Install dependency first: pip install impacket") from exc
        self.DPAPI_BLOB = DPAPI_BLOB
        self.MasterKey = MasterKey
        self.MasterKeyFile = MasterKeyFile
        self.DomainKey = DomainKey
        self.DPAPI_DOMAIN_RSA_MASTER_KEY = DPAPI_DOMAIN_RSA_MASTER_KEY
        self.PVK_FILE_HDR = PVK_FILE_HDR
        self.PRIVATE_KEY_BLOB = PRIVATE_KEY_BLOB
        self.privatekeyblob_to_pkcs1 = privatekeyblob_to_pkcs1
        self.PKCS1_v1_5 = PKCS1_v1_5
        self.deriveKeysFromUser = deriveKeysFromUser
        self.deriveKeysFromUserkey = deriveKeysFromUserkey
        self.bin_to_string = bin_to_string

    def _load_master_key(self, master_key_path: str | Path, sid: str | None = None,
                         password: str | None = None, nt_hash: str | None = None,
                         master_key_hex: str | None = None,
                         backup_key_path: str | Path | None = None) -> tuple[bytes, str]:
        raw = Path(master_key_path).read_bytes()
        container = self.MasterKeyFile(raw)
        offset = len(container)
        master_key_bytes = raw[offset:offset + container["MasterKeyLen"]]
        offset += container["MasterKeyLen"]
        offset += container["BackupKeyLen"]
        offset += container["CredHistLen"]
        domain_key_bytes = raw[offset:offset + container["DomainKeyLen"]]

        if backup_key_path:
            if not domain_key_bytes:
                raise ValueError("Master-key file has no domain backup-key section")
            try:
                domain_key = self.DomainKey(domain_key_bytes)
                pvk_data = Path(backup_key_path).read_bytes()
                pvk_header = self.PVK_FILE_HDR(pvk_data)
                pvk_blob = pvk_data[len(pvk_header):len(pvk_header) + pvk_header["cbPvk"]]
                private_blob = self.PRIVATE_KEY_BLOB(pvk_blob)
                private_key = self.privatekeyblob_to_pkcs1(private_blob)
                cipher = self.PKCS1_v1_5.new(private_key)
                decrypted = cipher.decrypt(domain_key["SecretData"][::-1], None)
                if not decrypted:
                    raise ValueError("Backup key did not decrypt the domain-key section")
                domain_master_key = self.DPAPI_DOMAIN_RSA_MASTER_KEY(decrypted)
                recovered = domain_master_key["buffer"][:domain_master_key["cbMasterKey"]]
                if not recovered:
                    raise ValueError("Domain backup key produced an empty master key")
                return recovered, container["Guid"].decode("utf-16le").rstrip("\\x00")
            except Exception as exc:
                raise ValueError(f"Domain backup-key recovery failed: {exc}") from exc

        if not master_key_bytes:
            raise ValueError("Master-key file contains no primary master-key section")
        master = self.MasterKey(master_key_bytes)
        if master_key_hex:
            recovered = bytes.fromhex(master_key_hex.removeprefix("0x"))
            if len(recovered) != 64:
                raise ValueError(f"Recovered DPAPI MasterKey must be 64 bytes, got {len(recovered)}")
            return recovered, container["Guid"].decode("utf-16le").rstrip("\\x00")

        if nt_hash is not None:
            try:
                nt_hash_bytes = bytes.fromhex(nt_hash.removeprefix("0x"))
            except ValueError as exc:
                raise ValueError("NT hash must be hexadecimal") from exc
            if len(nt_hash_bytes) != 16:
                raise ValueError("NT hash must be exactly 16 bytes / 32 hexadecimal characters")
            if not sid:
                raise ValueError("SID is required with --nt-hash")
            candidates = self.deriveKeysFromUserkey(sid, nt_hash_bytes)
        else:
            if not sid or password is None:
                raise ValueError("SID and user password are required unless --master-key-hex, --nt-hash, or --backup-key is supplied")
            candidates = self.deriveKeysFromUser(sid, password)
        for candidate in candidates:
            decrypted = master.decrypt(candidate)
            if decrypted is not None:
                return decrypted, container["Guid"].decode("utf-16le").rstrip("\\x00")
        raise ValueError("User password and SID did not unlock the supplied master-key file")

    def _decrypt_generic_xml_artifact(self, data: bytes, master_key: bytes, master_guid: str,
                                     source_name: str, output_path: str | Path | None) -> dict[str, Any]:
        root = ET.fromstring(data)
        changed = 0
        blob_guids: list[str] = []
        for element in root.iter():
            value = element_text(element)
            if not value or not value.startswith("AQAAAN"):
                continue
            try:
                blob_bytes = decode_b64(value)
                if not blob_bytes.startswith(DPAPI_PREFIX):
                    continue
                blob = self.DPAPI_BLOB(blob_bytes)
                blob_guid = self.bin_to_string(blob["GuidMasterKey"])
                blob_guids.append(blob_guid)
                if master_guid.lower().strip("{}") != blob_guid.lower().strip("{}"):
                    return {"status": "master_key_guid_mismatch", "encryption": "dpapi", "master_key_guid": master_guid, "blob_master_key_guid": blob_guid}
                plaintext = blob.decrypt(master_key)
                if plaintext is None:
                    return {"status": "blob_decrypt_failed", "encryption": "dpapi", "master_key_guid": blob_guid}
                element.text = plaintext.decode("utf-16le").rstrip("\x00") if b"\x00" in plaintext else plaintext.decode("utf-8")
                element.attrib.pop("Encrypted", None)
                changed += 1
            except (ValueError, UnicodeDecodeError):
                continue
        if changed == 0:
            return {"status": "no_dpapi_values", "encryption": "dpapi", "output_path": None}
        output = ET.tostring(root, encoding="utf-8", xml_declaration=True)
        if output_path:
            Path(output_path).write_bytes(output)
        return {"status": "success", "encryption": "dpapi", "artifact": source_name, "decrypted_values": changed, "master_key_guid": blob_guids[0], "output_path": str(output_path) if output_path else None, "_output_bytes": output}

    def decrypt(self, xml_path: str | Path, master_key_path: str | Path,
                sid: str | None = None, password: str | None = None,
                nt_hash: str | None = None, master_key_hex: str | None = None,
                backup_key_path: str | Path | None = None,
                output_path: str | Path | None = None) -> dict[str, Any]:
        data = Path(xml_path).read_bytes()
        fingerprint = fingerprint_bytes(data, Path(xml_path).name, str(xml_path))
        if Path(xml_path).suffix.lower() in {".ispac", ".zip"}:
            try:
                master_key, master_guid = self._load_master_key(master_key_path, sid, password, nt_hash, master_key_hex, backup_key_path)
                changed = 0
                first_guid = None
                from io import BytesIO
                with zipfile.ZipFile(BytesIO(data), "r") as source_zip, BytesIO() as buffer:
                    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as target_zip:
                        for info in source_zip.infolist():
                            member = source_zip.read(info.filename)
                            if Path(info.filename).suffix.lower() in {".dtsx", ".params", ".conmgr", ".dtproj"}:
                                try:
                                    member_result = self._decrypt_generic_xml_artifact(member, master_key, master_guid, info.filename, None)
                                    if member_result.get("status") == "success":
                                        member = member_result.pop("_output_bytes")
                                        changed += member_result.get("decrypted_values", 0)
                                        first_guid = first_guid or member_result.get("master_key_guid")
                                except Exception:
                                    pass
                            target_zip.writestr(info, member)
                    output = buffer.getvalue()
                if output_path:
                    Path(output_path).write_bytes(output)
                return {"status": "success", "encryption": "dpapi", "artifact": Path(xml_path).name, "decrypted_values": changed, "master_key_guid": first_guid or master_guid, "output_path": str(output_path) if output_path else None}
            except Exception as exc:
                return {"status": "error", "encryption": "dpapi", "error": str(exc)}
        if Path(xml_path).suffix.lower() != ".dtsx":
            try:
                master_key, master_guid = self._load_master_key(master_key_path, sid, password, nt_hash, master_key_hex, backup_key_path)
                return self._decrypt_generic_xml_artifact(data, master_key, master_guid, Path(xml_path).name, output_path)
            except Exception as exc:
                return {"status": "error", "encryption": "dpapi", "error": str(exc)}
        if fingerprint.backend_required != "dpapi":
            return {"status": "wrong_backend", "backend": "dpapi", "detected": fingerprint.protection_name}
        if fingerprint.protection_level not in (1, 4):
            return {"status": "unsupported_level", "backend": "dpapi", "level": fingerprint.protection_level}

        try:
            master_key, master_guid = self._load_master_key(
                master_key_path, sid, password, nt_hash, master_key_hex, backup_key_path
            )
            root = ET.fromstring(data)
            if fingerprint.protection_level == 4:
                elements = [root]
            else:
                elements = [element for element in root.iter()
                            if attr_by_local_name(element, "Encrypted") == "1"
                            and attr_by_local_name(element, "Sensitive") == "1"]
            if not elements:
                raise ValueError("No DPAPI-protected elements found")
            blob_guids: list[str] = []
            for element in elements:
                blob_bytes = decode_b64(element_text(element))
                blob = self.DPAPI_BLOB(blob_bytes)
                blob_guid = self.bin_to_string(blob["GuidMasterKey"])
                blob_guids.append(blob_guid)
                if master_guid.lower().strip("{}") != blob_guid.lower().strip("{}"):
                    return {
                        "status": "master_key_guid_mismatch",
                        "backend": "dpapi",
                        "master_key_guid": master_guid,
                        "blob_master_key_guid": blob_guid,
                    }
                plaintext = blob.decrypt(master_key)
                if plaintext is None:
                    return {"status": "blob_decrypt_failed", "backend": "dpapi", "master_key_guid": blob_guid}
                if fingerprint.protection_level == 4:
                    output = plaintext
                else:
                    try:
                        value = plaintext.decode("utf-16le").rstrip("\x00") if b"\x00" in plaintext else plaintext.decode("utf-8")
                    except UnicodeDecodeError:
                        value = plaintext.decode("utf-8", errors="replace")
                    element.text = value
                    element.attrib.pop("Encrypted", None)
                    element.attrib.pop("Sensitive", None)
            if fingerprint.protection_level != 4:
                output = ET.tostring(root, encoding="utf-8", xml_declaration=True)
            blob_guid = blob_guids[0]

            if output_path:
                Path(output_path).write_bytes(output)
            records = extract_sensitive_records(output, Path(xml_path).name)
            result = {
                "status": "success",
                "encryption": "dpapi",
                "protection_level": fingerprint.protection_level,
                "master_key_guid": blob_guid,
                "output_path": str(output_path) if output_path else None,
            }
            return result
        except Exception as exc:
            return {"status": "error", "encryption": "dpapi", "error": str(exc)}


def print_decryption_result(result: dict[str, Any]) -> None:
    """Print a concise human-readable decryption result."""
    print(f"Status: {result.get('status', 'unknown')}")
    if result.get("encryption"):
        print(f"Encryption: {result['encryption']}")
    if result.get("protection_level") is not None:
        print(f"Protection level: {result['protection_level']}")
    if result.get("password") is not None:
        print(f"Password: {result['password']}")
    if result.get("encoding"):
        print(f"Encoding: {result['encoding']}")
    if result.get("master_key_guid"):
        print(f"Master-key GUID: {result['master_key_guid']}")
    if result.get("output_path"):
        print(f"Output file: {result['output_path']}")
    if result.get("error"):
        print(f"Error: {result['error']}")


def _looks_like_path(value: str) -> bool:
    lowered = value.lower()
    return ("\\\\" in value or "/" in value or ":\\" in value
            or lowered.endswith((".xlsx", ".xls", ".csv", ".txt", ".xml", ".dtsx", ".ispac")))


def extract_sensitive_records(data: bytes, source_name: str) -> list[dict[str, Any]]:
    """Extract meaningful leaf values and connection/file attributes without parent duplicates."""
    root = ET.fromstring(data)
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    relevant_element_names = {
        "password", "variablevalue", "parametervalue", "filename", "filepath",
        "connectionstring", "server", "datasource", "initialcatalog", "userid",
        "username", "user", "value",
    }
    relevant_attribute_names = {
        "connectionstring", "filename", "filepath", "server", "datasource",
        "initialcatalog", "userid", "username", "user", "password", "value",
    }
    excluded_nodes = {
        id(node)
        for design_node in root.iter()
        if local_name(design_node.tag) == "DesignTimeProperties"
        for node in design_node.iter()
    }

    def add_record(element: ET.Element, record_type: str, name: str | None,
                   value: str, sensitive: bool, encrypted: bool) -> None:
        value = value.strip()
        if not value or len(value) >= 8192:
            return
        key = (element_path(root, element), record_type, value)
        if key in seen:
            return
        seen.add(key)
        records.append({
            "source": source_name,
            "type": record_type,
            "name": name,
            "path": element_path(root, element),
            "sensitive": sensitive,
            "encrypted": encrypted,
            "value": value,
            "master_key_guid": None,
        })

    for element in root.iter():
        name = local_name(element.tag)
        lowered_name = name.lower()
        if id(element) in excluded_nodes:
            continue
        # Do not treat a package, connection manager, variable, or property
        # container's recursive text as a secret. Inspect only direct text on
        # leaf elements and explicitly interesting encrypted elements.
        children = list(element)
        sensitive = attr_by_local_name(element, "Sensitive") == "1"
        encrypted = attr_by_local_name(element, "Encrypted") == "1"
        if not children:
            direct_value = (element.text or "").strip()
            if direct_value and (sensitive or encrypted or lowered_name in relevant_element_names or _looks_like_path(direct_value)):
                add_record(
                    element,
                    name,
                    attr_by_local_name(element, "Name"),
                    direct_value,
                    sensitive,
                    encrypted,
                )

        # Connection strings and file paths are commonly stored as attributes,
        # not element text. Capture each relevant attribute on its owning node.
        for attr_key, attr_value in element.attrib.items():
            attr_name = local_name(attr_key)
            if attr_name.lower() not in relevant_attribute_names:
                continue
            value = (attr_value or "").strip()
            if not value:
                continue
            add_record(
                element,
                attr_name,
                attr_by_local_name(element, "ObjectName") or attr_by_local_name(element, "Name"),
                value,
                sensitive or attr_name.lower() in {"password"},
                encrypted,
            )
    return records


def extract_artifact_records(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    supported = {".dtsx", ".params", ".dtproj", ".conmgr", ".database"}
    records: list[dict[str, Any]] = []
    if path.suffix.lower() in {".ispac", ".zip"}:
        with zipfile.ZipFile(path) as archive:
            for name in archive.namelist():
                if Path(name).suffix.lower() in supported:
                    try:
                        records.extend(extract_sensitive_records(archive.read(name), name))
                    except (ET.ParseError, UnicodeDecodeError):
                        continue
        return records
    if path.suffix.lower() not in supported:
        raise ValueError(f"Unsupported artifact extension: {path.suffix or '<none>'}")
    return extract_sensitive_records(path.read_bytes(), path.name)


def save_secret_records(records: list[dict[str, Any]], output_path: str | Path | None) -> str | None:
    if not records:
        return None
    if output_path:
        sidecar = Path(output_path).with_suffix(Path(output_path).suffix + ".secrets.json")
    else:
        sidecar = Path("ssis.secrets.json")
    sidecar.write_text(json.dumps({"secrets": records}, indent=2, ensure_ascii=False), encoding="utf-8")
    return str(sidecar)


def cmd_fingerprint(args: argparse.Namespace) -> int:
    results = [fingerprint_file(path) for path in args.files]
    if args.pretty:
        for result in results:
            print(f"{result.source_name}: level={result.protection_level} "
                  f"{result.protection_name or 'unknown'}; scope={result.scope}; "
                  f"backend={result.backend_required}; confidence={result.confidence}")
            if result.master_key_guid:
                print(f"  master-key-guid={result.master_key_guid}")
    else:
        print(json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True))
    return 0


def decrypt_xmlenc_package(data: bytes, password: str, iterations: int, encodings: list[str]) -> tuple[bytes, str] | None:
    for encoding in encodings:
        working = ET.fromstring(data)
        regions = [element for element in working.iter() if local_name(element.tag) == "EncryptedData"]
        if not regions:
            return None
        try:
            if local_name(working.tag) == "EncryptedData":
                salt, iv, cipher_value = parse_xmlenc(data)
                plaintext = decrypt_password_candidate(password, salt, iv, cipher_value, iterations, encoding)
                if plaintext is None:
                    raise ValueError("candidate failed")
                return pretty_xml_bytes(unpad_iso10126(plaintext)), encoding
            for region in regions:
                salt, iv, cipher_value = parse_xmlenc(ET.tostring(region, encoding="utf-8"))
                plaintext = decrypt_password_candidate(password, salt, iv, cipher_value, iterations, encoding)
                if plaintext is None:
                    raise ValueError("candidate failed")
                fragment = unpad_iso10126(plaintext)
                replacement = ET.fromstring(fragment)
                parent = next((p for p in working.iter() if region in list(p)), None)
                if parent is None:
                    raise ValueError("encrypted region has no parent")
                index = list(parent).index(region)
                parent.remove(region)
                parent.insert(index, replacement)
            return ET.tostring(working, encoding="utf-8", xml_declaration=True), encoding
        except (ValueError, ET.ParseError, UnicodeError):
            continue
    return None


def cmd_password(args: argparse.Namespace) -> int:
    data = Path(args.xml).read_bytes()
    fingerprint = fingerprint_bytes(data, Path(args.xml).name, args.xml)
    if fingerprint.backend_required != "password":
        raise SystemExit(f"Input is not a password-protected XMLENC package/region; detected {fingerprint.protection_name or 'unknown'}.")
    if bool(args.password) == bool(args.wordlist):
        raise SystemExit("Provide exactly one of --password or --wordlist")
    if args.password is not None:
        passwords = [args.password]
    else:
        passwords = [line.rstrip("\r\n") for line in Path(args.wordlist).read_text(errors="ignore").splitlines() if line.strip()]
    encodings = ["utf-8"] + (["utf-16-le"] if args.try_utf16 else [])
    for password in passwords:
        decrypted = decrypt_xmlenc_package(data, password, args.iterations, encodings)
        if decrypted is not None:
            body, encoding = decrypted
            result = {
                "status": "success",
                "encryption": "password",
                "password": password,
                "encoding": encoding,
                "protection_level": fingerprint.protection_level,
                "output_path": None,
            }
            if args.out:
                Path(args.out).write_bytes(body)
                result["output_path"] = str(args.out)
            records = extract_sensitive_records(body, Path(args.xml).name)
            if args.secrets:
                result["secrets_path"] = save_secret_records(records, args.out)
                result["secrets_found"] = len(records)
            print_decryption_result(result)
            if args.secrets and records:
                print(f"Secrets file: {result.get('secrets_path')}")
            return 0
    result = {"status": "no_match", "encryption": "password", "tested": len(passwords) * len(encodings)}
    print_decryption_result(result)
    print(f"Candidates tested: {result['tested']}")
    return 1


def cmd_dpapi(args: argparse.Namespace) -> int:
    if sum(value is not None for value in (args.password, args.nt_hash, args.master_key_hex, args.backup_key)) > 1:
        raise SystemExit("Use only one of --password, --nt-hash, --master-key-hex, or --backup-key")
    if args.password is None and args.nt_hash is None and args.master_key_hex is None and args.backup_key is None:
        import getpass
        args.password = getpass.getpass("Authorized Windows user password: ")
    result = DpapiBackend().decrypt(
        xml_path=args.xml,
        master_key_path=args.master_key,
        sid=args.sid,
        password=args.password,
        nt_hash=args.nt_hash,
        master_key_hex=args.master_key_hex,
        backup_key_path=args.backup_key,
        output_path=args.out,
    )
    if result.get("status") == "success" and args.secrets and args.out:
        try:
            records = extract_artifact_records(args.out) if Path(args.out).suffix.lower() in {".ispac", ".zip"} else extract_sensitive_records(Path(args.out).read_bytes(), Path(args.xml).name)
            result["secrets_path"] = save_secret_records(records, args.out)
            result["secrets_found"] = len(records)
        except Exception as exc:
            result["secrets_error"] = str(exc)
    print_decryption_result(result)
    if args.secrets and result.get("secrets_path"):
        print(f"Secrets file: {result['secrets_path']}")
    return 0 if result.get("status") == "success" else 1


class WideHelpFormatter(argparse.HelpFormatter):
    """Keep CLI option descriptions on the same line when terminal width permits."""

    def __init__(self, prog: str, indent_increment: int = 2, max_help_position: int = 50, width: int | None = None) -> None:
        super().__init__(
            prog,
            indent_increment=indent_increment,
            max_help_position=max_help_position,
            width=width or 120,
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Unified SSIS protection analyzer",
        formatter_class=WideHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("fingerprint", help="Analyze one or more .dtsx files", formatter_class=WideHelpFormatter)
    fp.add_argument("files", nargs="+")
    fp.add_argument("--pretty", action="store_true")
    fp.set_defaults(func=cmd_fingerprint)
    pw = sub.add_parser("password", help="Test candidates against a password-protected XMLENC package", formatter_class=WideHelpFormatter)
    pw.add_argument("-f", "--file", dest="xml", required=True, metavar="FILE", help="SSIS artifact to decrypt")
    pw.add_argument("-w", "--wordlist", dest="wordlist", metavar="WORDLIST", help="File containing password candidates")
    pw.add_argument("-p", "--password", dest="password", metavar="PASSWORD", help="Known package password")
    pw.add_argument("-i", "--iterations", dest="iterations", type=int, default=1000, metavar="ITERATIONS")
    pw.add_argument("--try-utf16", action="store_true")
    pw.add_argument("-o", "--out", dest="out", metavar="OUT", help="Write reconstructed artifact to this path")
    pw.add_argument("-s", "--secrets", action="store_true", help="Save extracted credential/path values to a sidecar file")
    pw.set_defaults(func=cmd_password)
    dp = sub.add_parser("dpapi", help="Decrypt a level-1 or level-4 package from supplied offline artifacts", formatter_class=WideHelpFormatter)
    dp.add_argument("-f", "--file", dest="xml", required=True, metavar="FILE", help="SSIS artifact to decrypt")
    dp.add_argument("--master-key", required=True, metavar="MASTER_KEY", help="DPAPI Master Key File")
    dp.add_argument("--sid", help="Windows user SID used with --password or --hash")
    dp.add_argument("-p", "--password", dest="password", metavar="PASSWORD", help="Windows user password; omit to be prompted")
    dp.add_argument("-H", "--hash", dest="nt_hash", metavar="HASH", help="NTLM hash")
    dp.add_argument("--master-key-hex", metavar="MASTER_KEY_HEX", help="Recovered master key")
    dp.add_argument("-pvk", "--backup-key", dest="backup_key", metavar="BACKUP_KEY", help="Domain backup private key in PVK format")
    dp.add_argument("-o", "--out", dest="out", metavar="OUT", help="Write reconstructed artifact to this path")
    dp.add_argument("-s", "--secrets", action="store_true", help="Save extracted credential/path values to a sidecar file")
    dp.set_defaults(func=cmd_dpapi)
    return args_func(parser, sub)


def args_func(parser: argparse.ArgumentParser, sub: Any) -> int:
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

