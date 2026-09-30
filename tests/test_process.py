from passkey_gen.process import (
    check_security_status,
    disable_core_dumps,
    get_dumpable_status,
    harden_process,
    set_no_new_privs,
    set_non_dumpable,
    set_process_name,
)


def test_disable_core_dumps():
    assert disable_core_dumps() is True


def test_set_non_dumpable():
    # Calling set_non_dumpable on Linux should succeed
    res = set_non_dumpable()
    assert res is True
    # Verify dumpable status is 0 (non-dumpable)
    status = get_dumpable_status()
    assert status == 0


def test_set_no_new_privs():
    res = set_no_new_privs()
    assert res is True


def test_set_process_name():
    res = set_process_name("passkey-test")
    assert res is True


def test_harden_process():
    results = harden_process()
    assert results["core_dumps_disabled"] is True
    assert results["non_dumpable"] is True
    assert results["no_new_privs"] is True


def test_check_security_status():
    harden_process()
    status = check_security_status()
    assert status["core_dumps_disabled"] is True
    assert status["ptrace_protected"] is True
    assert status["no_new_privs"] is True
    assert status["mlock_available"] is True
