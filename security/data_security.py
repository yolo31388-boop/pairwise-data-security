"""
游戏内数据加密与防篡改系统 - 核心模块

安全设计（仅使用 Python 标准库）：
- 加密：HMAC-SHA256 作为伪随机函数的 CTR 模式流加密，每次加密使用随机 IV，
  相同明文加密结果不同；采用 Encrypt-then-MAC 保证机密性与完整性。
- 完整性：Encrypt-then-MAC，解密前先校验 HMAC，任何篡改都会被拒绝。
- 校验和：带密钥的 HMAC-SHA256，覆盖数据的完整规范化序列化，无法伪造。
- 密钥管理：密钥由安全随机数生成，不硬编码；持久化到权限 0600 的独立
  密钥库文件（而非明文配置文件）；支持版本化轮换，旧版本密钥保留用于解密。
- 防篡改：保护记录带校验和，支持定时巡检，发现篡改即告警并触发惩罚（锁定）。
"""
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
import hashlib
import hmac
import json
import os
import secrets
import time


class SecurityError(Exception):
    """安全模块基础异常"""


class IntegrityError(SecurityError):
    """数据完整性校验失败（数据被篡改或损坏）"""


class DecryptionError(SecurityError):
    """解密失败（数据包格式非法等）"""


class KeyManagementError(SecurityError):
    """密钥管理错误（密钥不存在等）"""


class TamperDetectedError(SecurityError):
    """检测到数据被篡改"""


@dataclass
class Config:
    pass


_DEFAULT_KEY_ID = "default"


class DataSecurity:
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self._state = {}
        self._history = []

        self._key_store_path = self.config.get("key_store_path")
        self._rotation_interval = float(self.config.get("key_rotation_interval", 24 * 3600))
        self._tamper_check_interval = float(self.config.get("tamper_check_interval", 5.0))
        self._on_penalty: Optional[Callable] = self.config.get("on_penalty")

        # key_id -> [key 版本记录,...]，记录含 version/material/created_at
        self._keys: Dict[str, List[Dict]] = {}
        # 访问控制：key_id -> 被授权的请求者集合
        self._acl: Dict[str, set] = {}
        # 防篡改保护记录：record_id -> {"data":..., "checksum":...}
        self._protected: Dict[str, Dict] = {}

        self.tamper_alarms: List[Dict] = []
        self.penalty_count = 0
        self.locked = False
        self._time_since_check = 0.0

        self._load_or_create_keys()

    # ------------------------------------------------------------------
    # 密钥管理
    # ------------------------------------------------------------------
    def _load_or_create_keys(self):
        if self._key_store_path and os.path.exists(self._key_store_path):
            try:
                with open(self._key_store_path, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
                self._keys = {kid: list(recs) for kid, recs in payload.get("keys", {}).items()}
            except (OSError, ValueError) as exc:
                raise KeyManagementError(f"密钥库读取失败: {exc}") from exc
        if _DEFAULT_KEY_ID not in self._keys:
            self._generate_key(_DEFAULT_KEY_ID)

    def _generate_key(self, key_id: str) -> Dict:
        versions = self._keys.setdefault(key_id, [])
        record = {
            "key_id": key_id,
            "version": (versions[-1]["version"] + 1) if versions else 1,
            "material": secrets.token_hex(32),
            "created_at": time.time(),
        }
        versions.append(record)
        self._save_keys()
        return record

    def _save_keys(self):
        if not self._key_store_path:
            return
        directory = os.path.dirname(os.path.abspath(self._key_store_path))
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
        tmp_path = self._key_store_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as fh:
            json.dump({"keys": self._keys}, fh)
        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, self._key_store_path)
        os.chmod(self._key_store_path, 0o600)

    def _get_key(self, key_id: str, version: Optional[int] = None) -> Dict:
        versions = self._keys.get(key_id)
        if not versions:
            raise KeyManagementError(f"密钥不存在: {key_id}")
        if version is None:
            return versions[-1]
        for record in versions:
            if record["version"] == version:
                return record
        raise KeyManagementError(f"密钥版本不存在: {key_id} v{version}")

    @staticmethod
    def _derive(material_hex: str, label: bytes) -> bytes:
        return hmac.new(bytes.fromhex(material_hex), label, hashlib.sha256).digest()

    def rotate_key(self, key_id: str = _DEFAULT_KEY_ID) -> int:
        """轮换密钥：生成新版本，旧版本保留用于解密历史数据"""
        return self._generate_key(key_id)["version"]

    def _maybe_rotate(self, key_id: str):
        latest = self._get_key(key_id)
        if time.time() - latest["created_at"] >= self._rotation_interval:
            self._generate_key(key_id)

    def key_fingerprint(self, key_id: str = _DEFAULT_KEY_ID,
                        version: Optional[int] = None) -> str:
        """密钥指纹（不暴露密钥本身），用于审计与比较"""
        record = self._get_key(key_id, version)
        return hashlib.sha256(bytes.fromhex(record["material"])).hexdigest()

    def grant_permission(self, requester: str, key_id: str = _DEFAULT_KEY_ID):
        self._acl.setdefault(key_id, set()).add(requester)

    def revoke_permission(self, requester: str, key_id: str = _DEFAULT_KEY_ID):
        self._acl.get(key_id, set()).discard(requester)

    def _check_permission(self, key_id: str, requester: Optional[str]):
        allowed = self._acl.get(key_id)
        if allowed is not None and requester not in allowed:
            raise PermissionError(f"请求者 {requester!r} 无权使用密钥 {key_id!r}")

    # ------------------------------------------------------------------
    # 加密 / 解密
    # ------------------------------------------------------------------
    @staticmethod
    def _keystream(key: bytes, iv: bytes, length: int) -> bytes:
        output = b""
        counter = 0
        while len(output) < length:
            block = hmac.new(key, iv + counter.to_bytes(8, "big"),
                             hashlib.sha256).digest()
            output += block
            counter += 1
        return output[:length]

    @staticmethod
    def _to_bytes(data: Any) -> bytes:
        if isinstance(data, bytes):
            return data
        if isinstance(data, str):
            return data.encode("utf-8")
        return json.dumps(data, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    def encrypt_data(self, data: Any, key_id: str = _DEFAULT_KEY_ID) -> Dict:
        """加密数据，返回包含 IV 与完整性标签的数据包"""
        if self.locked:
            raise SecurityError("系统已因篡改事件锁定，拒绝加密")
        self._maybe_rotate(key_id)
        record = self._get_key(key_id)
        plaintext = self._to_bytes(data)
        iv = secrets.token_bytes(16)  # 每次加密使用随机 IV
        enc_key = self._derive(record["material"], b"enc")
        mac_key = self._derive(record["material"], b"mac")
        stream = self._keystream(enc_key, iv, len(plaintext))
        ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
        header = (key_id.encode() + record["version"].to_bytes(4, "big") + iv)
        tag = hmac.new(mac_key, b"DS1" + header + ciphertext,
                       hashlib.sha256).hexdigest()
        return {
            "key_id": key_id,
            "key_version": record["version"],
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "hmac": tag,
        }

    def decrypt_data(self, packet: Dict, key_id: str = _DEFAULT_KEY_ID,
                     requester: Optional[str] = None) -> bytes:
        """解密数据：先做权限检查与完整性验证，失败时抛出明确异常而非崩溃"""
        if self.locked:
            raise SecurityError("系统已因篡改事件锁定，拒绝解密")
        self._check_permission(key_id, requester)
        if not isinstance(packet, dict):
            raise DecryptionError("数据包格式非法：不是字典")
        try:
            packet_key_id = packet["key_id"]
            version = int(packet["key_version"])
            iv = bytes.fromhex(packet["iv"])
            ciphertext = bytes.fromhex(packet["ciphertext"])
            tag = packet["hmac"]
        except (KeyError, TypeError, ValueError) as exc:
            raise DecryptionError(f"数据包格式非法: {exc}") from exc
        if packet_key_id != key_id:
            raise DecryptionError(f"数据包密钥ID不匹配: {packet_key_id!r}")
        try:
            record = self._get_key(key_id, version)
        except KeyManagementError as exc:
            raise DecryptionError(str(exc)) from exc
        mac_key = self._derive(record["material"], b"mac")
        header = (key_id.encode() + version.to_bytes(4, "big") + iv)
        expected = hmac.new(mac_key, b"DS1" + header + ciphertext,
                            hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, tag):
            raise IntegrityError("完整性校验失败：数据被篡改或密钥错误")
        enc_key = self._derive(record["material"], b"enc")
        stream = self._keystream(enc_key, iv, len(ciphertext))
        return bytes(a ^ b for a, b in zip(ciphertext, stream))

    # ------------------------------------------------------------------
    # 校验和
    # ------------------------------------------------------------------
    def checksum(self, data: Any, key_id: str = _DEFAULT_KEY_ID) -> str:
        """带密钥的 HMAC-SHA256 校验和，覆盖数据的完整内容，无法伪造"""
        record = self._get_key(key_id)
        mac_key = self._derive(record["material"], b"checksum")
        return hmac.new(mac_key, self._to_bytes(data), hashlib.sha256).hexdigest()

    def verify_checksum(self, data: Any, checksum: str,
                        key_id: str = _DEFAULT_KEY_ID) -> bool:
        if not isinstance(checksum, str):
            return False
        return hmac.compare_digest(self.checksum(data, key_id), checksum)

    # ------------------------------------------------------------------
    # 防篡改检测
    # ------------------------------------------------------------------
    def protect(self, data: Any, record_id: Optional[str] = None) -> Dict:
        """为数据生成防篡改保护记录（数据 + 全覆盖校验和）"""
        record = {"data": data, "checksum": self.checksum(data)}
        if record_id is not None:
            self._protected[record_id] = record
        return record

    def tamper_detection(self, record: Dict,
                         record_id: Optional[str] = None) -> bool:
        """检测记录是否被篡改；发现篡改即告警并触发惩罚"""
        try:
            data = record["data"]
            checksum = record["checksum"]
        except (TypeError, KeyError):
            self._raise_tamper(record_id, "保护记录结构损坏")
            return True
        if not self.verify_checksum(data, checksum):
            self._raise_tamper(record_id, "数据校验和不匹配")
            return True
        return False

    def check_all(self) -> List[str]:
        """巡检所有已注册的保护记录，返回被篡改的记录ID列表"""
        tampered = []
        for record_id, record in list(self._protected.items()):
            if self.tamper_detection(record, record_id):
                tampered.append(record_id)
        return tampered

    def _raise_tamper(self, record_id: Optional[str], reason: str):
        alarm = {"time": time.time(), "record_id": record_id, "reason": reason}
        self.tamper_alarms.append(alarm)
        self._history.append(("tamper", alarm))
        self._apply_penalty(alarm)

    def _apply_penalty(self, alarm: Dict):
        """篡改惩罚：锁定系统并触发外部惩罚回调"""
        self.penalty_count += 1
        self.locked = True
        if callable(self._on_penalty):
            self._on_penalty(alarm)

    # ------------------------------------------------------------------
    # 生命周期
    # ------------------------------------------------------------------
    def update(self, dt: float):
        """按配置的间隔定时巡检防篡改记录（游戏进行中也能发现篡改）"""
        self._time_since_check += dt
        if self._time_since_check >= self._tamper_check_interval:
            self._time_since_check = 0.0
            self.check_all()

    def reset(self):
        self._state = {}
        self._history = []
        self._protected = {}
        self.tamper_alarms = []
        self.penalty_count = 0
        self.locked = False
        self._time_since_check = 0.0
