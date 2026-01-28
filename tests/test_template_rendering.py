import uuid
from pathlib import Path

from pwnv.models import Challenge
from pwnv.models.challenge import Category
from pwnv.utils.template import render_template


def _challenge_with_services(path: Path) -> Challenge:
    return Challenge(
        name="ServiceChallenge",
        ctf_id=uuid.uuid4(),
        path=path,
        category=Category.pwn,
        points=100,
        extras={
            "services": [
                {
                    "type": "tcp",
                    "host": "example.com",
                    "port": 31337,
                    "raw": "nc example.com 31337",
                }
            ]
        },
    )


def test_render_template_service_placeholders(tmp_path):
    challenge = _challenge_with_services(tmp_path / "svc")
    template = 'con = "{{service.host}} {{service.port}}"\n'

    rendered = render_template(template, challenge)

    assert rendered == 'con = "example.com 31337"\n'


def test_render_template_missing_service_keeps_placeholder(tmp_path):
    challenge = Challenge(
        name="NoService",
        ctf_id=uuid.uuid4(),
        path=tmp_path / "nosvc",
        category=Category.pwn,
    )
    template = "host={{service.host}} port={{service.port}}\n"

    rendered = render_template(template, challenge)

    assert rendered == template
