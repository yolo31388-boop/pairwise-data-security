"""
游戏内数据加密与防篡改系统 - 验收测试
运行方式：python -m pytest tests/test_data_security.py -q
共 14 个测试用例
"""
import hashlib
import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.data_security import (
    DataSecurity,
    DecryptionError,
    IntegrityError,
    SecurityError,
)


class TestDataSecurity:
    def setup_method(self):
        self.system = DataSecurity()

    # 加密：使用标准构造（HMAC-SHA256 CTR 流加密 + Encrypt-then-MAC），可正确往返
    def test_case_01(self):
        data = b"player_save: gold=100, hp=80"
        packet = self.system.encrypt_data(data)
        assert packet["ciphertext"] != data.hex()
        assert "iv" in packet and "hmac" in packet
        # 不是简单 XOR：明文与密文异或结果不是恒定重复密钥
        keystream = bytes(a ^ b for a, b in zip(
            data, bytes.fromhex(packet["ciphertext"])))
        assert len(set(keystream)) > 1
        assert self.system.decrypt_data(packet) == data

    # 加密：每次使用随机 IV，相同明文加密结果不同
    def test_case_02(self):
        data = b"same plaintext"
        packet1 = self.system.encrypt_data(data)
        packet2 = self.system.encrypt_data(data)
        assert packet1["iv"] != packet2["iv"]
        assert packet1["ciphertext"] != packet2["ciphertext"]
        assert self.system.decrypt_data(packet1) == data
        assert self.system.decrypt_data(packet2) == data

    # 解密：完整性验证，篡改密文/标签会被拒绝而不是返回损坏数据
    def test_case_03(self):
        packet = self.system.encrypt_data(b"gold=100")
        tampered = dict(packet)
        raw = bytearray.fromhex(packet["ciphertext"])
        raw[0] ^= 0xFF
        tampered["ciphertext"] = raw.hex()
        with pytest.raises(IntegrityError):
            self.system.decrypt_data(tampered)
        bad_tag = dict(packet, hmac="0" * 64)
        with pytest.raises(IntegrityError):
            self.system.decrypt_data(bad_tag)

    # 解密：错误处理，非法数据包/错误密钥抛出明确异常而不是崩溃
    def test_case_04(self):
        for bad_packet in (None, "str", 123, {}, {"key_id": "default"},
                           {"key_id": "default", "key_version": 1,
                            "iv": "zz", "ciphertext": "", "hmac": ""}):
            with pytest.raises(SecurityError):
                self.system.decrypt_data(bad_packet)
        other = DataSecurity()  # 不同密钥的系统
        packet = other.encrypt_data(b"secret")
        with pytest.raises(SecurityError):
            self.system.decrypt_data(packet)

    # 解密：权限检查，未授权者不能解密
    def test_case_05(self):
        packet = self.system.encrypt_data(b"account_password")
        self.system.grant_permission("alice")
        with pytest.raises(PermissionError):
            self.system.decrypt_data(packet, requester="bob")
        with pytest.raises(PermissionError):
            self.system.decrypt_data(packet)  # 匿名请求同样被拒绝
        assert self.system.decrypt_data(packet, requester="alice") == \
            b"account_password"

    # 校验和：使用安全散列（SHA-256 级），具备雪崩效应
    def test_case_06(self):
        digest = self.system.checksum(b"gold=100")
        assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
        other = self.system.checksum(b"gold=101")  # 仅差 1 bit
        assert other != digest
        diff = sum(a != b for a, b in zip(digest, other))
        assert diff > 10  # 雪崩效应，简单求和做不到

    # 校验和：带密钥（加密），攻击者无法伪造
    def test_case_07(self):
        data = b"gold=100"
        assert not self.system.verify_checksum(data, hashlib.sha256(data).hexdigest())
        assert not self.system.verify_checksum(data, str(sum(data)))
        # 其他系统（不同密钥）算出的校验和不能用于本系统
        foreign = DataSecurity().checksum(data)
        assert not self.system.verify_checksum(data, foreign)
        assert self.system.verify_checksum(data, self.system.checksum(data))

    # 校验和：覆盖所有数据字段，改任何部分都能检测到
    def test_case_08(self):
        save = {"gold": 100, "hp": 80, "name": "hero", "items": ["sword"]}
        record = self.system.protect(save)
        assert not self.system.tamper_detection(record)
        for mutate in (
            lambda s: s.update(gold=999999),
            lambda s: s.update(hp=1),
            lambda s: s.update(name="hacker"),
            lambda s: s["items"].append("dragon_egg"),
            lambda s: s.update(extra_field="injected"),
        ):
            save2 = json.loads(json.dumps(save))
            mutate(save2)
            assert not self.system.verify_checksum(save2, record["checksum"])

    # 密钥管理：不硬编码，每个实例使用不同的随机密钥
    def test_case_09(self):
        another = DataSecurity()
        assert self.system.key_fingerprint() != another.key_fingerprint()
        assert self.system.checksum(b"data") != another.checksum(b"data")
        # 源码中不存在硬编码密钥材料
        source_path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "security", "data_security.py")
        with open(source_path, "r", encoding="utf-8") as fh:
            source = fh.read()
        assert self.system.key_fingerprint() not in source

    # 密钥管理：支持轮换，旧数据仍可解密，新数据用新密钥
    def test_case_10(self):
        old_packet = self.system.encrypt_data(b"old save")
        old_fp = self.system.key_fingerprint()
        new_version = self.system.rotate_key()
        assert new_version == old_packet["key_version"] + 1
        assert self.system.key_fingerprint() != old_fp
        new_packet = self.system.encrypt_data(b"new save")
        assert new_packet["key_version"] == new_version
        assert self.system.decrypt_data(old_packet) == b"old save"
        assert self.system.decrypt_data(new_packet) == b"new save"

    # 密钥管理：安全存储，密钥库文件权限 0600，不明文放在配置里
    def test_case_11(self, tmp_path):
        store = tmp_path / "keys" / "keys.json"
        system = DataSecurity({"key_store_path": str(store)})
        system.encrypt_data(b"x")  # 触发持久化
        assert store.exists()
        mode = stat.S_IMODE(os.stat(store).st_mode)
        assert mode & 0o077 == 0  # 其他用户不可读
        assert "material" not in json.dumps(system.config)
        # 重启后能从密钥库恢复同一密钥
        restored = DataSecurity({"key_store_path": str(store)})
        assert restored.key_fingerprint() == system.key_fingerprint()

    # 防篡改：实际生效，玩家改存档会告警
    def test_case_12(self):
        save = {"gold": 100}
        record = self.system.protect(save, record_id="save_1")
        assert self.system.tamper_detection(record, "save_1") is False
        assert self.system.tamper_alarms == []
        save["gold"] = 999999  # 玩家用记事本改存档
        assert self.system.tamper_detection(record, "save_1") is True
        assert len(self.system.tamper_alarms) == 1
        assert self.system.tamper_alarms[0]["record_id"] == "save_1"

    # 防篡改：定时检测，游戏运行中改数据也能发现
    def test_case_13(self):
        system = DataSecurity({"tamper_check_interval": 1.0})
        save = {"gold": 100}
        system.protect(save, record_id="save_1")
        system.update(2.0)  # 无篡改：巡检通过
        assert system.tamper_alarms == []
        save["gold"] = 999999  # 游戏中途篡改
        system.update(0.5)  # 未到巡检间隔，暂不检测
        assert system.tamper_alarms == []
        system.update(0.6)  # 到达巡检间隔，发现篡改
        assert len(system.tamper_alarms) == 1

    # 防篡改：检测到篡改触发惩罚（锁定 + 回调）
    def test_case_14(self):
        penalties = []
        system = DataSecurity({"on_penalty": penalties.append})
        save = {"gold": 100}
        record = system.protect(save, record_id="save_1")
        save["gold"] = 999999
        assert system.tamper_detection(record, "save_1") is True
        assert system.penalty_count == 1
        assert system.locked is True
        assert len(penalties) == 1
        with pytest.raises(SecurityError):  # 锁定后拒绝继续服务
            system.encrypt_data(b"x")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
