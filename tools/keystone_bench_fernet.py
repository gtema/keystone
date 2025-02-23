from pathlib import Path
import pytest
import tempfile

from keystone.token.providers.fernet.core import Provider
import keystone.conf
from keystone.conf import configure

CONF = keystone.conf.CONF

@pytest.fixture(scope="session", autouse=True)
def execute_before_any_test():
    configure(CONF)


def test_fenet_token_python(benchmark):
    key_repo = tempfile.TemporaryDirectory()
    CONF.set_override("key_repository", key_repo.name, "fernet_tokens")
    with open(Path(key_repo.name, "0"), "w") as fp:
        fp.write("3HgVBYzXMJYSr-5hxYI5lvmXK9-UjwQNwQYnKlA3-aA=")
        fp.flush()
    with open(Path(key_repo.name, "1"), "w") as fp:
        fp.write("BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=")
        fp.flush()

    fernet = Provider()
    token = "gAAAAABnt1rtv0ROracU_8Iqyf5wIN5R4bo7Enk1P_KQeLtiC8bC4_qvCj9PzBOq1EHflF20aYYJq2dVDoy9hBxM23ua79YVjCd1BnjN8Mxz5ZG0-kYfEJPytVydWqKPG9p5V5eQ5H0ztsxJJZFG6qQHRDBUrk_SuKox8aVddX38Oa5Nx7wCGnA"

    token = benchmark(lambda: fernet.validate_token(token))

    assert token == (
        '4b7d364ad87d400bbd91798e3c15e9c2',
        ['external'],
        ['FL7FbzBKQsK115_4TyyiIw'],
        None,
        None,
        '97cd761d581b485792a4afc8cc6a998d',
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        '2025-02-20T16:40:13.000000Z',
        '2025-02-20T17:40:13.000000Z',
    )
