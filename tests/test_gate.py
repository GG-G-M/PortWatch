from core.gate import authorize_target, GateError, GATE_REJECTIONS
import os
import json
import tempfile
from config import Config


def test_empty_target_rejected():
    try:
        authorize_target("")
        assert False, "should have raised"
    except GateError as e:
        assert e.code == 7


def test_invalid_ip():
    try:
        authorize_target("not-an-ip")
        assert False
    except GateError as e:
        assert e.code == 5


def test_public_ip_rejected():
    try:
        authorize_target("8.8.8.8")
        assert False
    except GateError as e:
        assert e.code == 4


def test_loopback_is_private_but_must_be_registered_and_authorized():
    # loopback 127.0.0.1 is private; ensure flow reaches registration
    try:
        authorize_target("127.0.0.1")
        assert False
    except GateError as e:
        # could be 2 (not registered) or 1 (not authorized) depending on state
        assert e.code in (1, 2)


def test_registered_and_authorized_passes(tmp_path):
    inst = tmp_path / "instance"
    inst.mkdir()
    devices = {"127.0.0.1": {"ip": "127.0.0.1", "hostname": "localhost", "is_authorized": 1}}
    auths = {"127.0.0.1": {"authorized_by": "admin", "expires_at": "2099-12-31T23:59:59Z"}}
    (inst / "devices.json").write_text(json.dumps(devices), encoding="utf-8")
    (inst / "authorizations.json").write_text(json.dumps(auths), encoding="utf-8")
    # monkeypatch Config.INSTANCE_DIR
    old = Config.INSTANCE_DIR
    try:
        Config.INSTANCE_DIR = str(inst)
        ok, info = authorize_target("127.0.0.1")
        assert ok is True
        assert info["ip"] == "127.0.0.1"
    finally:
        Config.INSTANCE_DIR = old


def test_expired_authorization(tmp_path):
    inst = tmp_path / "instance"
    inst.mkdir()
    devices = {"192.168.1.10": {"ip": "192.168.1.10"}}
    auths = {"192.168.1.10": {"authorized_by": "admin", "expires_at": "2000-01-01T00:00:00Z"}}
    (inst / "devices.json").write_text(json.dumps(devices), encoding="utf-8")
    (inst / "authorizations.json").write_text(json.dumps(auths), encoding="utf-8")
    old = Config.INSTANCE_DIR
    try:
        Config.INSTANCE_DIR = str(inst)
        try:
            authorize_target("192.168.1.10")
            assert False
        except GateError as e:
            assert e.code == 8
    finally:
        Config.INSTANCE_DIR = old


def test_not_registered(tmp_path):
    inst = tmp_path / "instance"
    inst.mkdir()
    (inst / "devices.json").write_text(json.dumps({}), encoding="utf-8")
    (inst / "authorizations.json").write_text(json.dumps({}), encoding="utf-8")
    old = Config.INSTANCE_DIR
    try:
        Config.INSTANCE_DIR = str(inst)
        try:
            authorize_target("192.168.1.50")
            assert False
        except GateError as e:
            assert e.code == 2
    finally:
        Config.INSTANCE_DIR = old


def test_missing_authorization(tmp_path):
    inst = tmp_path / "instance"
    inst.mkdir()
    devices = {"192.168.1.60": {"ip": "192.168.1.60"}}
    (inst / "devices.json").write_text(json.dumps(devices), encoding="utf-8")
    (inst / "authorizations.json").write_text(json.dumps({}), encoding="utf-8")
    old = Config.INSTANCE_DIR
    try:
        Config.INSTANCE_DIR = str(inst)
        try:
            authorize_target("192.168.1.60")
            assert False
        except GateError as e:
            assert e.code == 1
    finally:
        Config.INSTANCE_DIR = old
