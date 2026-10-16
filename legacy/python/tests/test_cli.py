from passkey_gen.cli import main


def test_cli_default_run(capsys):
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 1
    assert len(lines[0]) == 32


def test_cli_64_characters(capsys):
    ret = main(["-l", "64"])
    assert ret == 0
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 1
    assert len(lines[0]) == 64


def test_cli_custom_length(capsys):
    ret = main(["--length", "48"])
    assert ret == 0
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 1
    assert len(lines[0]) == 48


def test_cli_show_entropy(capsys):
    ret = main(["-l", "32", "--show-entropy"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Entropy:" in captured.err
    assert len(captured.out.strip()) == 32


def test_cli_multiple_count(capsys):
    ret = main(["-l", "32", "-n", "3"])
    assert ret == 0
    captured = capsys.readouterr()
    lines = captured.out.strip().split("\n")
    assert len(lines) == 3
    for line in lines:
        assert len(line) == 32
    assert len(set(lines)) == 3


def test_cli_invalid_charset(capsys):
    ret = main(["-c", "1"])
    assert ret == 1
    captured = capsys.readouterr()
    assert "Error:" in captured.err


def test_cli_audit(capsys):
    ret = main(["--audit"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Linux Process Defense Audit" in captured.out
    assert "Core Dumps Disabled" in captured.out
    assert "Non-Dumpable" in captured.out
    assert "No New Privileges" in captured.out


def test_cli_webauthn(capsys):
    ret = main(["--webauthn"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "FIDO2 / WebAuthn Passkey" in captured.out
    assert "Credential ID" in captured.out
    assert "Public Key (COSE" in captured.out


def test_cli_webauthn_json(capsys):
    import json
    ret = main(["--webauthn", "--webauthn-alg", "Ed25519", "--json", "--export-private"])
    assert ret == 0
    captured = capsys.readouterr()
    parsed = json.loads(captured.out)
    assert parsed["type"] == "public-key"
    assert parsed["algorithm"] == "Ed25519"
    assert parsed["coseAlgorithm"] == -8
    assert "publicKeyCose" in parsed
    assert "privateKeyPem" in parsed


