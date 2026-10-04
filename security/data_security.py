"""
游戏内数据加密与防篡改系统 - 核心模块（修复版）

安全特性：
- 加密：HMAC-SHA256 派生子密钥 + CTR 模式，随机 IV，相同明文密文不同
- 解密：HMAC 完整性验证、格式/密钥错误处理、属主权限检查
- 校验和：带密钥的 HMAC-SHA256，覆盖全部数据
- 密钥管理：随机生成、支持轮换、密钥库加密存储且文件权限 0o600
- 防篡改：快照比对、定时检测、告警与锁定惩罚
"""
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional
import hashlib
import hmac
import json
import os
import socket
import getpass
import time


class SecurityError(Exception):
    """安全模块基础异常。"""


class IntegrityError(SecurityError, ValueError):
    """数据完整性验证失败。"""


class DecryptionError(SecurityError, ValueError):
    """密文格式错误或无法解密。"""


@dataclass
class Config:
    pass


_MAGIC = b"GDS1"
_IV_LEN = 16
_MAC_LEN = 32
_KEY_LEN = 32


def _canonical(data) -> bytes:
    """把任意数据序列化为覆盖全部字段的规范字节串。"""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    return json.dumps(data, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=repr).encode("utf-8")


def _derive_subkeys(master_key: bytes):
    enc_key = hmac.new(master_key, b"gds/enc", hashlib.sha256).digest()
    mac_key = hmac.new(master_key, b"gds/mac", hashlib.sha256).digest()
    return enc_key, mac_key


def _ctr_stream(enc_key: bytes, iv: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, iv + counter.to_bytes(8, "big"),
                        hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _seal(master_key: bytes, plaintext: bytes) -> bytes:
    """加密并附加 HMAC：iv + ciphertext + mac。"""
    enc_key, mac_key = _derive_subkeys(master_key)
    iv = os.urandom(_IV_LEN)
    ciphertext = _xor(plaintext, _ctr_stream(enc_key, iv, len(plaintext)))
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    return iv + ciphertext + mac


def _unseal(master_key: bytes, blob: bytes) -> bytes:
    """验证 HMAC 后解密，完整性失败抛 IntegrityError。"""
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < _IV_LEN + _MAC_LEN:
        raise DecryptionError("密文格式错误：长度不足")
    blob = bytes(blob)
    iv, ciphertext, mac = blob[:_IV_LEN], blob[_IV_LEN:-_MAC_LEN], blob[-_MAC_LEN:]
    enc_key, mac_key = _derive_subkeys(master_key)
    expected = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, mac):
        raise IntegrityError("数据完整性验证失败：数据已被篡改或密钥错误")
    return _xor(ciphertext, _ctr_stream(enc_key, iv, len(ciphertext)))


class DataSecurity:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []
        self.admins = list(self.config.get("admins", ["admin"]))
        self.check_interval = float(self.config.get("tamper_check_interval", 1.0))
        self.max_violations = int(self.config.get("max_violations", 3))
        self.penalty_callback: Optional[Callable] = self.config.get("penalty_callback")
        self._elapsed = 0.0
        self._keys: Dict[int, bytes] = {}
        self._current_version = 0
        self._keystore_path = self.config.get("keystore_path")
        if self._keystore_path and os.path.exists(self._keystore_path):
            self._load_keystore()
        else:
            self._add_key()
            if self._keystore_path:
                self._save_keystore()
        self._snapshots: Dict[str, Dict] = {}
        self._providers: Dict[str, Callable[[], object]] = {}
        self.alerts: List[Dict] = []
        self.violations = 0
        self.locked = False

    # ------------------------------------------------------------------
    # 密钥管理
    # ------------------------------------------------------------------
    def _add_key(self) -> int:
        self._current_version += 1
        self._keys[self._current_version] = os.urandom(_KEY_LEN)
        return self._current_version

    @property
    def key_version(self) -> int:
        return self._current_version

    def rotate_key(self) -> int:
        """轮换密钥：生成新版本密钥，旧版本保留以解密历史密文。"""
        version = self._add_key()
        if self._keystore_path:
            self._save_keystore()
        self._history.append({"event": "key_rotated", "version": version,
                              "time": time.time()})
        return version

    def key_management(self) -> Dict:
        """返回密钥管理状态（不暴露密钥本体）。"""
        return {
            "current_version": self._current_version,
            "versions": sorted(self._keys),
            "hardcoded": False,
            "storage": self._keystore_path or "memory",
        }

    def _master_key(self) -> bytes:
        env_key = os.environ.get("DATA_SECURITY_MASTER_KEY")
        if env_key:
            return hashlib.sha256(bytes.fromhex(env_key)).digest()
        identity = f"{getpass.getuser()}@{socket.gethostname()}".encode("utf-8")
        return hashlib.pbkdf2_hmac("sha256", identity, b"gds-keystore",
                                   100_000, dklen=_KEY_LEN)

    def _save_keystore(self):
        """密钥库加密落盘，文件权限 0o600，不明文存储。"""
        master = self._master_key()
        payload = {
            "current": self._current_version,
            "keys": {str(v): _seal(master, k).hex() for v, k in self._keys.items()},
        }
        blob = json.dumps(payload).encode("utf-8")
        mac = hmac.new(master, blob, hashlib.sha256).hexdigest()
        content = json.dumps({"mac": mac, "payload": payload}).encode("utf-8")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(self._keystore_path, flags, 0o600)
        try:
            os.write(fd, content)
        finally:
            os.close(fd)
        os.chmod(self._keystore_path, 0o600)

    def _load_keystore(self):
        try:
            with open(self._keystore_path, "rb") as fh:
                content = fh.read()
            doc = json.loads(content.decode("utf-8"))
        except (OSError, ValueError) as exc:
            raise DecryptionError(f"密钥库读取失败: {exc}") from exc
        master = self._master_key()
        blob = json.dumps(doc.get("payload")).encode("utf-8")
        expected = hmac.new(master, blob, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, doc.get("mac", "")):
            raise IntegrityError("密钥库完整性验证失败")
        self._keys = {int(v): _unseal(master, bytes.fromhex(ct))
                      for v, ct in doc["payload"]["keys"].items()}
        self._current_version = int(doc["payload"]["current"])

    # ------------------------------------------------------------------
    # 数据加密 / 解密
    # ------------------------------------------------------------------
    def encrypt_data(self, data, user: Optional[str] = None) -> bytes:
        """加密数据：随机 IV + 版本号 + 属主绑定 + HMAC 完整性保护。"""
        key = self._keys[self._current_version]
        owner = (user or "").encode("utf-8")
        if len(owner) > 255:
            raise ValueError("用户名过长")
        header = (_MAGIC + self._current_version.to_bytes(2, "big")
                  + bytes([len(owner)]) + owner)
        return header + _seal(key, _canonical(data))

    def decrypt_data(self, token: bytes, user: Optional[str] = None):
        """解密数据：先验证完整性，再做权限检查，错误时抛出明确异常。"""
        if self.locked:
            raise PermissionError("系统已因篡改违规被锁定，拒绝解密")
        if not isinstance(token, (bytes, bytearray)):
            raise DecryptionError("密文格式错误：必须为字节串")
        token = bytes(token)
        if len(token) < 4 + 2 + 1 + _IV_LEN + _MAC_LEN or token[:4] != _MAGIC:
            raise DecryptionError("密文格式错误：魔数或长度不合法")
        version = int.from_bytes(token[4:6], "big")
        owner_len = token[6]
        owner = token[7:7 + owner_len].decode("utf-8", errors="replace")
        blob = token[7 + owner_len:]
        key = self._keys.get(version)
        if key is None:
            raise DecryptionError(f"未知的密钥版本: {version}")
        plaintext = _unseal(key, blob)
        if owner and user != owner and user not in self.admins:
            raise PermissionError(f"用户 {user!r} 无权解密属主为 {owner!r} 的数据")
        try:
            return json.loads(plaintext.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return plaintext

    # ------------------------------------------------------------------
    # 校验和
    # ------------------------------------------------------------------
    def checksum(self, data, key: Optional[bytes] = None) -> str:
        """带密钥的 HMAC-SHA256 校验和，覆盖全部数据。"""
        mac_key = key if key is not None else self._keys[self._current_version]
        return hmac.new(mac_key, _canonical(data), hashlib.sha256).hexdigest()

    def verify_checksum(self, data, checksum: str, key: Optional[bytes] = None) -> bool:
        return hmac.compare_digest(self.checksum(data, key=key), checksum)

    # ------------------------------------------------------------------
    # 防篡改检测
    # ------------------------------------------------------------------
    def register_save(self, save_id: str, data, owner: Optional[str] = None):
        """登记存档快照，后续可比对检测篡改。"""
        self._snapshots[save_id] = {
            "checksum": self.checksum(data),
            "owner": owner,
            "time": time.time(),
        }

    def watch_save(self, save_id: str, provider: Callable[[], object]):
        """注册数据提供者，供定时检测自动拉取当前数据。"""
        self._providers[save_id] = provider

    def check_tamper(self, save_id: str, current_data=None) -> bool:
        """比对当前数据与快照；发现篡改时告警并记违规。返回是否完好。"""
        snapshot = self._snapshots.get(save_id)
        if snapshot is None:
            raise KeyError(f"未登记的存档: {save_id}")
        if current_data is None:
            provider = self._providers.get(save_id)
            if provider is None:
                raise ValueError(f"存档 {save_id} 无当前数据来源")
            current_data = provider()
        if self.verify_checksum(current_data, snapshot["checksum"]):
            return True
        self._on_tamper(save_id)
        return False

    def tamper_detection(self) -> List[Dict]:
        """对所有登记存档执行一次检测，返回本次新增的告警。"""
        before = len(self.alerts)
        for save_id in list(self._snapshots):
            if save_id in self._providers:
                self.check_tamper(save_id)
        return self.alerts[before:]

    def _on_tamper(self, save_id: str):
        alert = {"save_id": save_id, "time": time.time(),
                 "violation": self.violations + 1}
        self.alerts.append(alert)
        self._history.append({"event": "tamper_detected", **alert})
        self.violations += 1
        if self.violations >= self.max_violations:
            self.locked = True
        if self.penalty_callback is not None:
            self.penalty_callback(save_id, self.violations)

    # ------------------------------------------------------------------
    # 周期更新
    # ------------------------------------------------------------------
    def update(self, dt: float):
        """按 check_interval 周期执行防篡改检测。"""
        self._elapsed += dt
        if self._elapsed >= self.check_interval:
            self._elapsed = 0.0
            self.tamper_detection()

    def reset(self):
        self._state = {}
        self._history = []
        self._elapsed = 0.0
        self._snapshots = {}
        self._providers = {}
        self.alerts = []
        self.violations = 0
        self.locked = False
