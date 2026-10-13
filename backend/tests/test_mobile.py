from types import SimpleNamespace
import plistlib
import zipfile

import app.services.ca as ca_module
import app.services.mobile as mobile_module
from app.services.mobile import (
    ManifestInspection,
    MobileResult,
    export_android_ca,
    enable_iptables_proxy,
    disable_iptables_proxy,
    list_remote_dir,
    read_remote_file,
    remote_file_info,
    search_remote_file,
    set_http_proxy,
    unset_http_proxy,
    analyze_ipa,
    unpack_apk,
)


def test_set_http_proxy_writes_http_and_https_proxy(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append(argv)
        return MobileResult(True, argv[0], " ".join(argv), "")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = set_http_proxy("10.0.2.2:8080")

    assert result.ok is True
    assert calls == [
        ["adb", "shell", "settings", "put", "global", "http_proxy", "10.0.2.2:8080"],
        ["adb", "shell", "settings", "put", "global", "https_proxy", "10.0.2.2:8080"],
    ]


def test_unset_http_proxy_writes_zero_proxy(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append(argv)
        return MobileResult(True, argv[0], " ".join(argv), "")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = unset_http_proxy()

    assert result.ok is True
    assert result.title == "unset proxy"
    assert calls == [
        ["adb", "shell", "settings", "put", "global", "http_proxy", ":0"],
        ["adb", "shell", "settings", "put", "global", "https_proxy", ":0"],
    ]


def test_enable_iptables_proxy_installs_nat_rules(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, argv[0], " ".join(argv), "")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = enable_iptables_proxy("192.168.1.150", 8080)

    assert result.ok is True
    assert calls[0][0] == ["adb", "root"]
    setup_script = calls[2][0][-1]
    assert "iptables -t nat -A OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT" in setup_script
    assert "iptables -t nat -A OUTPUT -p tcp --dport 443 -j ARKADROID_PROXY_OUT" in setup_script
    assert "DNAT --to-destination 192.168.1.150:8080" in setup_script
    assert "iptables -t nat -A ARKADROID_PROXY_POST -p tcp -j MASQUERADE" in setup_script


def test_enable_iptables_proxy_rejects_invalid_ip(monkeypatch):
    monkeypatch.setattr(mobile_module, "run_command", lambda argv, *, timeout=120: (_ for _ in ()).throw(AssertionError))

    result = enable_iptables_proxy("burp.local", 8080)

    assert result.ok is False
    assert "valid IP" in result.output


def test_disable_iptables_proxy_removes_arkadroid_chains(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, argv[0], " ".join(argv), "")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = disable_iptables_proxy()

    assert result.ok is True
    cleanup_script = calls[1][0][-1]
    assert "iptables -t nat -D OUTPUT -p tcp --dport 80 -j ARKADROID_PROXY_OUT" in cleanup_script
    assert "iptables -t nat -X ARKADROID_PROXY_OUT" in cleanup_script
    assert "iptables -t nat -X ARKADROID_PROXY_POST" in cleanup_script


def test_export_android_ca_names_certificate_with_old_subject_hash(tmp_path, monkeypatch):
    monkeypatch.setattr(ca_module, "get_settings", lambda: SimpleNamespace(resolved_data_dir=tmp_path))
    monkeypatch.setattr(mobile_module, "get_settings", lambda: SimpleNamespace(resolved_data_dir=tmp_path))

    def fake_run_command(argv, *, timeout=120):
        assert argv[:3] == ["openssl", "x509", "-inform"]
        return MobileResult(True, "openssl", " ".join(argv), "9a5ba575\n")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = export_android_ca(7)

    assert result.ok is True
    assert result.artifact == str(tmp_path / "certs" / "7" / "android" / "9a5ba575.0")
    assert (tmp_path / "certs" / "7" / "android" / "9a5ba575.0").exists()


def test_format_manifest_inspection_includes_evidence_for_findings():
    inspection = ManifestInspection(
        debuggable=True,
        min_sdk_version=23,
        read_external_storage=True,
        write_external_storage=False,
        debuggable_evidence='<application android:debuggable="true">',
        min_sdk_evidence='<uses-sdk android:minSdkVersion="23" />',
        read_external_storage_evidence='<uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />',
    )

    output = mobile_module._format_manifest_inspection(inspection)

    assert 'android:debuggable="true": FOUND' in output
    assert '  <application android:debuggable="true">' in output
    assert "android:minSdkVersion < 30: FOUND" in output
    assert '  <uses-sdk android:minSdkVersion="23" />' in output
    assert "READ_EXTERNAL_STORAGE permission: FOUND" in output
    assert '  <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />' in output
    assert "WRITE_EXTERNAL_STORAGE permission: not found" in output


def test_manifest_min_sdk_falls_back_to_apktool_yml():
    manifest = "<manifest><application /></manifest>"
    apktool_yml = "sdkInfo:\n  minSdkVersion: '26'\n"

    assert mobile_module._manifest_min_sdk_version(manifest, apktool_yml) == 26
    assert mobile_module._manifest_min_sdk_evidence(manifest, apktool_yml) == "apktool.yml: minSdkVersion: '26'"


def test_list_remote_dir_parses_directories_before_files(monkeypatch):
    def fake_run_command(argv, *, timeout=120):
        assert argv == ["adb", "shell", "cd '/sdcard' && ls -1Ap"]
        assert timeout == 30
        return MobileResult(True, "adb", "adb shell ls", "Download/\nnotes.txt\nAndroid/\n")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    entries, result = list_remote_dir("/sdcard")

    assert result.ok is True
    assert [(entry.name, entry.is_dir) for entry in entries] == [
        ("..", True),
        ("Android", True),
        ("Download", True),
        ("notes.txt", False),
    ]


def test_remote_file_info_uses_stat(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, "adb", "adb shell stat", "Size: 42 bytes\nOwner: shell\n")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = remote_file_info("/sdcard/My File.txt")

    assert result.ok is True
    assert result.title == "remote file info"
    assert calls == [
        (
            [
                "adb",
                "shell",
                "stat -c '%n\\nType: %F\\nSize: %s bytes\\nOwner: %U\\nGroup: %G\\nMode: %A (%a)\\nModified: %y' '/sdcard/My File.txt'",
            ],
            30,
        )
    ]


def test_remote_file_info_falls_back_to_ls(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append(argv)
        if "stat -c" in argv[-1]:
            return MobileResult(False, "adb", "adb shell stat", "stat failed")
        return MobileResult(True, "adb", "adb shell ls", "-rw-r--r-- shell shell 42 file.txt\n")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    result = remote_file_info("/sdcard/file.txt")

    assert result.ok is True
    assert len(calls) == 2
    assert calls[1] == ["adb", "shell", "ls -la '/sdcard/file.txt'"]
    assert "-rw-r--r--" in result.output


def test_read_and_search_remote_file_commands(monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, "adb", "adb shell", "body")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)

    read_remote_file("/sdcard/a b.txt", max_bytes=123)
    search_remote_file("/sdcard/a b.txt", "needle value")

    assert calls == [
        (["adb", "shell", "head -c 123 '/sdcard/a b.txt'"], 30),
        (["adb", "shell", "grep -n -I -- 'needle value' '/sdcard/a b.txt' | head -200"], 30),
    ]


def test_unpack_apk_runs_apktool_and_jadx_when_available(tmp_path, monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, argv[0], " ".join(argv), f"{argv[0]} ok")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)
    monkeypatch.setattr(mobile_module.shutil, "which", lambda command: f"/usr/bin/{command}" if command == "jadx" else None)

    result = unpack_apk(tmp_path / "demo.apk", tmp_path / "out")

    assert result.ok is True
    assert result.artifact == str(tmp_path / "out")
    assert calls == [
        (["apktool", "d", "-f", "-o", str(tmp_path / "out" / "apktool"), str(tmp_path / "demo.apk")], 600),
        (["/usr/bin/jadx", "-d", str(tmp_path / "out" / "jadx"), str(tmp_path / "demo.apk")], 600),
    ]
    assert f"apktool output: {tmp_path / 'out' / 'apktool'}" in result.output
    assert f"jadx output: {tmp_path / 'out' / 'jadx'}" in result.output


def test_unpack_apk_runs_managed_jadx_after_auto_install(tmp_path, monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append((argv, timeout))
        return MobileResult(True, argv[0], " ".join(argv), f"{argv[0]} ok")

    managed = tmp_path / "tools" / "jadx" / "bin" / "jadx"
    setup = MobileResult(True, "install jadx", "download jadx", "Installed JADX at test path")
    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)
    monkeypatch.setattr(mobile_module, "ensure_jadx", lambda: ([str(managed)], setup))

    result = unpack_apk(tmp_path / "demo.apk", tmp_path / "out")

    assert result.ok is True
    assert calls == [
        (["apktool", "d", "-f", "-o", str(tmp_path / "out" / "apktool"), str(tmp_path / "demo.apk")], 600),
        ([str(managed), "-d", str(tmp_path / "out" / "jadx"), str(tmp_path / "demo.apk")], 600),
    ]
    assert "Installed JADX at test path" in result.output
    assert f"jadx output: {tmp_path / 'out' / 'jadx'}" in result.output


def test_unpack_apk_skips_jadx_when_unavailable_after_install_attempt(tmp_path, monkeypatch):
    calls = []

    def fake_run_command(argv, *, timeout=120):
        calls.append(argv)
        return MobileResult(True, argv[0], " ".join(argv), "apktool ok")

    monkeypatch.setattr(mobile_module, "run_command", fake_run_command)
    monkeypatch.setattr(
        mobile_module,
        "ensure_jadx",
        lambda: (None, MobileResult(False, "install jadx", "download jadx", "Unable to install JADX automatically")),
    )

    result = unpack_apk(tmp_path / "demo.apk", tmp_path / "out")

    assert result.ok is True
    assert calls == [["apktool", "d", "-f", "-o", str(tmp_path / "out" / "apktool"), str(tmp_path / "demo.apk")]]
    assert "Unable to install JADX automatically" in result.output
    assert "jadx not available" in result.output


def test_analyze_ipa_reports_plist_inventory_and_string_findings(tmp_path, monkeypatch):
    ipa = tmp_path / "demo.ipa"
    info = {
        "CFBundleIdentifier": "com.example.demo",
        "CFBundleExecutable": "Demo",
        "CFBundleShortVersionString": "1.0",
        "CFBundleVersion": "42",
        "MinimumOSVersion": "15.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["demo"]}],
        "NSCameraUsageDescription": "Camera",
    }
    provision = {
        "Name": "Dev profile",
        "ProvisionedDevices": ["device"],
        "Entitlements": {"get-task-allow": True, "keychain-access-groups": ["ABCDE.com.example.demo"]},
    }
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Demo.app/Info.plist", plistlib.dumps(info))
        archive.writestr(
            "Payload/Demo.app/Demo",
            b"MachO-ish https://api.example.test AKIA1234567890ABCDEF SecTrustEvaluate UIWebView",
        )
        archive.writestr(
            "Payload/Demo.app/embedded.mobileprovision",
            b"prefix" + plistlib.dumps(provision) + b"suffix",
        )
        archive.writestr("Payload/Demo.app/Frameworks/SDK.framework/SDK", b"sdk")
        archive.writestr("Payload/Demo.app/data.sqlite", b"db")

    monkeypatch.setattr(mobile_module, "run_command", lambda argv, *, timeout=120: MobileResult(True, argv[0], " ".join(argv), "Mach-O"))

    result = analyze_ipa(ipa, tmp_path / "out")

    assert result.ok is True
    assert "Bundle ID: com.example.demo" in result.output
    assert "IOS-ATS-001 ATS globally disabled: FOUND" in result.output
    assert "IOS-ENT-001 get-task-allow enabled: FOUND" in result.output
    assert "https://api.example.test" in result.output
    assert "AWS access key: AKIA12...CDEF" in result.output
    assert "Frameworks/SDK.framework" in result.output
    assert (tmp_path / "out" / "ios-static-report.md").exists()


def test_extract_ipa_rejects_path_traversal(tmp_path):
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("../escape.txt", "nope")

    result = mobile_module.extract_ipa(ipa, tmp_path / "out")

    assert result.ok is False
    assert "Unsafe IPA member path" in result.output
