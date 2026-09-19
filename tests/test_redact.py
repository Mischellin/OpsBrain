from opsbrain.redact import redact


def test_known_secret_shapes_are_removed() -> None:
    wg = "A" * 43 + "="
    text = "\n".join([
        "password: hunter2secret", 'DB_PASSWORD="s3cr3t-value"', "api_key = abcdef123456",
        "url=postgres://app:topsecret@db:5432/x", "token glpat-abcdefghijklmnopqrst", "AKIAABCDEFGHIJKLMNOP",
        f"PrivateKey = {wg}", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\ndef\n-----END OPENSSH PRIVATE KEY-----",
        "  POSTGRES_PASSWORD:          spaced-out-value"])
    clean, count = redact(text)
    for secret in ("hunter2secret", "s3cr3t-value", "abcdef123456", "topsecret", "glpat-abcdefghijklmnopqrst",
                   "AKIAABCDEFGHIJKLMNOP", wg, "abcdefghijklmnopqrstuvwxyz", "abc\ndef", "spaced-out-value"):
        assert secret not in clean
    assert count >= 9


def test_ordinary_output_is_untouched() -> None:
    text = "pve : ok=12 changed=0 unreachable=0 failed=0\nPlan: 1 to add, 0 to change, 0 to destroy\npassword: null"
    assert redact(text) == (text, 0)


def test_ansible_vault_block() -> None:
    clean, count = redact("x: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6162636465666768696a6b6c6d6e6f70\n"
                          "  3132333435363738393031323334353637\nnext: 1\n")
    assert "6162636465" not in clean and "next: 1" in clean and count == 1
