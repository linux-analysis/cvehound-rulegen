"""Model-input extraction helpers that need no kernel: messages and diff payloads."""

from rulegen.extract import changed_lines_only, hunk_lines, strip_message


def test_strip_message_drops_trailers_keeps_fixes():
    msg = (
        'net: fix a bug\n\n'
        'The description.\n\n'
        'Fixes: 1234567890ab ("net: introduce foo")\n'
        'Signed-off-by: A Dev <dev@example.com>\n'
        'Reviewed-by: B Dev <b@example.com>\n'
        'Reported-by: syzbot <syz@example.com>\n'
    )
    stripped, syzbot = strip_message(msg)
    assert syzbot is True and 'Fixes: 1234567890ab' in stripped
    for trailer in ('Signed-off-by', 'Reviewed-by', 'Reported-by'):
        assert trailer not in stripped


def test_changed_lines_keep_the_payload_and_the_file_boundary():
    diff = (
        'diff --git a/net/foo.c b/net/foo.c\n'
        '--- a/net/foo.c\n'
        '+++ b/net/foo.c\n'
        '@@ -1,4 +1,3 @@\n'
        ' context\n'
        '-\tkfree(sk);\n'
        '+\tkfree_rcu(sk);\n'
    )
    assert changed_lines_only(diff) == '+++ b/net/foo.c\n-\tkfree(sk);\n+\tkfree_rcu(sk);\n'


def test_hunk_lines_keep_code_and_drop_log_prose():
    log = (
        'commit abc\nAuthor: Ada Author <ada@mail.example>\nDate: x\n\n'
        '    net: sctp: the message returns early\n\n'
        'diff --git a/net/sctp/bind_addr.c b/net/sctp/bind_addr.c\n'
        'index 1..2 100644\n--- a/net/sctp/bind_addr.c\n+++ b/net/sctp/bind_addr.c\n'
        '@@ -1,3 +1,3 @@\n struct sctp_af *af;\n-\tif (sctp_bind_addr_match(a))\n'
        '+\tif (sctp_bind_addr_conflict(a))\n'
        'commit def\nAuthor: Someone <s@example.org>\n\n    servaddr fixup\n\n'
        'diff --git a/x b/x\n@@ -9 +9 @@\n-old_line(servaddr);\n'
    )
    code = hunk_lines(log)
    assert 'sctp_bind_addr_match' in code and 'old_line(servaddr)' in code
    for word in ('Ada', 'mail', 'returns', 'fixup', 'example'):
        assert word not in code
