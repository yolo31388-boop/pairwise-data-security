"""
游戏内数据加密与防篡改系统 - 验收测试
运行方式：python -m pytest tests/test_data_security.py -q
共 14 个测试用例
"""
import pytest
import sys
import os
import stat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from security.data_security import (
    DataSecurity,
    IntegrityError,
    DecryptionError,
    SecurityError,
)


class TestDataSecurity:
    def setup_method(self):
        self.system = DataSecurity()

    def test_case_01(self):
        # 加密使用随机 IV：相同明文两次加密结果不同
        data = {"coins": 100, "level": 5}
        token1 = self.system.encrypt_data(data)
        token2 = self.system.encrypt_data(data)
        assert token1 != token2
        assert self.system.decrypt_data(token1) == data
        assert self.system.decrypt_data(token2) == data

    def test_case_02(self):
        # 加密不是简单 XOR：密文不泄露明文，且不是定长逐字节异或
        data = {"password": "super-secret-123", "coins": 999999}
        token = self.system.encrypt_data(data)
        assert b"super-secret-123" not in token
        assert b"999999" not in token
        # 单字符明文的密文长度也应包含 IV 和 MAC，不可能被直接异或还原
        short = self.system.encrypt_data("a")
        assert len(short) >= 16 + 32

    def test_case_03(self):
        # 解密验证完整性：篡改密文任意字节都会被拒绝
        token = bytearray(self.system.encrypt_data({"coins": 100}))
        token[-10] ^= 0xFF
        with pytest.raises(IntegrityError):
            self.system.decrypt_data(bytes(token))

    def test_case_04(self):
        # 解密有错误处理：垃圾数据、错误密钥都抛出明确异常而不是崩溃
        with pytest.raises(DecryptionError):
            self.system.decrypt_data(b"not-a-valid-token")
        with pytest.raises(DecryptionError):
            self.system.decrypt_data("")
        other = DataSecurity()
        token = other.encrypt_data({"coins": 1})
        with pytest.raises(IntegrityError):
            self.system.decrypt_data(token)

    def test_case_05(self):
        # 解密有权限检查：非属主不能解密，属主和管理员可以
        token = self.system.encrypt_data({"coins": 100}, user="alice")
        with pytest.raises(PermissionError):
            self.system.decrypt_data(token, user="bob")
        assert self.system.decrypt_data(token, user="alice") == {"coins": 100}
        assert self.system.decrypt_data(token, user="admin") == {"coins": 100}

    def test_case_06(self):
        # 校验和使用安全算法：HMAC-SHA256（64 位十六进制），可验证
        data = {"coins": 100}
        digest = self.system.checksum(data)
        assert isinstance(digest, str) and len(digest) == 64
        int(digest, 16)
        assert self.system.verify_checksum(data, digest)
        # 不是简单求和：求和结果不可能达到 256 位
        assert digest != str(sum(repr(data).encode()))

    def test_case_07(self):
        # 校验和覆盖所有数据：修改任意字段（包括嵌套）都会改变校验和
        data = {"coins": 100, "items": {"sword": 1}, "name": "hero"}
        base = self.system.checksum(data)
        assert self.system.checksum({**data, "coins": 101}) != base
        changed = {"coins": 100, "items": {"sword": 2}, "name": "hero"}
        assert self.system.checksum(changed) != base
        assert self.system.checksum({**data, "name": "hero2"}) != base

    def test_case_08(self):
        # 校验和带密钥：不同密钥结果不同，错误密钥验证失败
        data = {"coins": 100}
        key_a = os.urandom(32)
        key_b = os.urandom(32)
        digest_a = self.system.checksum(data, key=key_a)
        assert digest_a != self.system.checksum(data, key=key_b)
        assert self.system.verify_checksum(data, digest_a, key=key_a)
        assert not self.system.verify_checksum(data, digest_a, key=key_b)

    def test_case_09(self):
        # 密钥不硬编码：不同实例密钥不同，互相无法解密
        other = DataSecurity()
        token = self.system.encrypt_data({"coins": 100})
        with pytest.raises(IntegrityError):
            other.decrypt_data(token)
        info = self.system.key_management()
        assert info["hardcoded"] is False

    def test_case_10(self):
        # 密钥轮换：轮换后版本号增加，旧密文仍可解密，新密文用新密钥
        old_version = self.system.key_version
        old_token = self.system.encrypt_data({"coins": 100})
        new_version = self.system.rotate_key()
        assert new_version == old_version + 1
        assert self.system.decrypt_data(old_token) == {"coins": 100}
        new_token = self.system.encrypt_data({"coins": 200})
        assert new_token[4:6] != old_token[4:6]
        assert self.system.decrypt_data(new_token) == {"coins": 200}

    def test_case_11(self, tmp_path=None):
        # 密钥安全存储：密钥库文件权限 0o600，且不明文保存密钥
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "keystore.json")
            system = DataSecurity({"keystore_path": path})
            mode = stat.S_IMODE(os.stat(path).st_mode)
            assert mode == 0o600
            raw_key = system._keys[system.key_version]
            with open(path, "rb") as fh:
                content = fh.read()
            assert raw_key not in content
            assert raw_key.hex().encode() not in content
            # 重新加载后密钥一致，可以解密之前的数据
            token = system.encrypt_data({"coins": 42})
            reloaded = DataSecurity({"keystore_path": path})
            assert reloaded.decrypt_data(token) == {"coins": 42}

    def test_case_12(self):
        # 防篡改检测实际生效：改动存档会告警并返回不通过
        save = {"coins": 100, "level": 5}
        self.system.register_save("slot1", save)
        assert self.system.check_tamper("slot1", save) is True
        tampered = {"coins": 999999, "level": 5}
        assert self.system.check_tamper("slot1", tampered) is False
        assert len(self.system.alerts) == 1
        assert self.system.alerts[0]["save_id"] == "slot1"

    def test_case_13(self):
        # 防篡改定时检测：update 到达间隔后自动检测游戏中被改的数据
        save = {"coins": 100}
        self.system.register_save("slot1", save)
        self.system.watch_save("slot1", lambda: save)
        self.system.update(self.system.check_interval)
        assert self.system.alerts == []
        save["coins"] = 999999  # 游戏运行中被修改
        self.system.update(self.system.check_interval / 2)
        assert self.system.alerts == []  # 未到检测周期
        self.system.update(self.system.check_interval)
        assert len(self.system.alerts) == 1

    def test_case_14(self):
        # 篡改有惩罚：违规计数累加，达到上限后系统锁定拒绝解密
        system = DataSecurity({"max_violations": 2})
        token = system.encrypt_data({"coins": 1})
        system.register_save("slot1", {"coins": 100})
        system.check_tamper("slot1", {"coins": 1})
        assert system.violations == 1 and not system.locked
        system.check_tamper("slot1", {"coins": 2})
        assert system.violations == 2 and system.locked
        with pytest.raises(PermissionError):
            system.decrypt_data(token)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
