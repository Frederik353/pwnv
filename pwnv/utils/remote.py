"""Helpers for interacting with remote CTF platforms via ``ctfbridge``."""

import asyncio
from typing import Any, Dict, Tuple

from pwnv.models import CTF, Challenge
from pwnv.models.challenge import Category

_keyword_map = {
    "pwn": Category.pwn,
    "web": Category.web,
    "rev": Category.rev,
    "reverse": Category.rev,
    "crypto": Category.crypto,
    "cryptography": Category.crypto,
    "stego": Category.steg,
    "steganography": Category.steg,
    "misc": Category.misc,
    "miscellaneous": Category.misc,
    "osint": Category.osint,
    "forensics": Category.forensics,
    "hardware": Category.hardware,
    "mobile": Category.mobile,
    "game": Category.game,
    "blockchain": Category.blockchain,
}


def sanitize(name: str) -> str:
    """Return a filesystem friendly version of ``name``."""
    return name.strip().replace(" ", "-").replace("..", ".").replace("/", "_").lower()


def normalise_category(raw: str) -> Category:
    """Best effort mapping from a textual category to :class:`Category`."""
    import re

    clean = re.sub(r"\\(.*?\\)", "", raw).strip().lower()
    key = re.split(r"[^a-z]+", clean, maxsplit=1)[0]
    return _keyword_map.get(key, Category.other)


def _ask_for_credentials(methods) -> Dict[str, str | None]:
    """Prompt the user for credentials using available authentication methods."""
    from ctfbridge.models.auth import AuthMethod
    from InquirerPy import inquirer

    from pwnv.utils.ui import error, prompt_text

    creds: Dict[str, str | None] = {"username": None, "password": None, "token": None}

    if len(methods) == 1:
        chosen_method = methods[0]
    else:
        choices = [
            {"name": method.name.capitalize(), "value": method} for method in methods
        ]
        chosen_method = inquirer.select(
            message="Choose authentication method:",
            choices=choices,
        ).execute()

    if chosen_method == AuthMethod.CREDENTIALS:
        creds["username"] = prompt_text("Username:")
        creds["password"] = inquirer.secret(message="Password:").execute().strip()
    elif chosen_method == AuthMethod.TOKEN:
        creds["token"] = inquirer.secret(message="Token:").execute().strip()
    else:
        error("No supported authentication methods found.")
        return {}
    return creds


_runner: asyncio.Runner | None = None


def _run_async(coro):
    """Run ``coro`` in a persistent asyncio runner."""
    import asyncio
    import atexit

    global _runner
    if _runner is None:
        _runner = asyncio.Runner()
        atexit.register(_runner.close)
    return _runner.run(coro)


async def wait_for_challenges(
    client: Any,
    ctf: CTF,
    interval: int = 60,
) -> list | None:
    """Poll remote platform until challenges become available."""
    from pwnv.utils.ui import info

    while True:
        challenges = await get_remote_challenges(client, ctf)

        if challenges is None:
            # Error fetching - return None
            return None

        if challenges:
            # Challenges available!
            return challenges

        # Empty list - CTF hasn't started yet
        info(f"No challenges yet. Checking again in {interval}s... (Ctrl+C to stop)")
        await asyncio.sleep(interval)


def _save_credentials(ctf: CTF, creds: Dict[str, str | None]) -> None:
    """Save credentials to .env file in CTF folder."""
    env_path = ctf.path / ".env"
    with open(env_path, "w") as f:
        if creds.get("username"):
            f.write(f"CTF_USERNAME={creds.get('username')}\n")
        if creds.get("password"):
            f.write(f"CTF_PASSWORD={creds.get('password')}\n")
        if creds.get("token"):
            f.write(f"CTF_TOKEN={creds.get('token')}\n")


def add_remote_ctf(ctf: CTF, wait: bool = True, interval: int = 10) -> bool:
    """Interactively add ``ctf`` by fetching its challenges remotely."""
    from pwnv.utils.crud import add_ctf
    from pwnv.utils.ui import info, warn

    client, methods = _run_async(get_remote_credential_methods(ctf.url))
    if client is None or methods is None:
        return False
    creds = _ask_for_credentials(methods)
    if not creds:
        return False

    add_ctf(ctf)

    # Save credentials early so user can retry with sync if something fails
    _save_credentials(ctf, creds)

    if not _run_async(create_remote_session(client, creds, ctf)):
        # Don't remove CTF - credentials saved, user can retry with sync
        return False

    challenges = _run_async(get_remote_challenges(client, ctf))
    if challenges is None:
        return False

    if not challenges:
        if wait:
            info("CTF hasn't started. Waiting for challenges...")
            challenges = _run_async(wait_for_challenges(client, ctf, interval))
            if challenges is None:
                return False
        else:
            warn("No challenges available yet. Use 'pwnv ctf sync' later.")
            return True  # CTF created successfully

    _run_async(add_remote_challenges(client, ctf, challenges))
    return True


def _get_creds_from_env(ctf: CTF) -> Dict[str, str | None]:
    """Load credentials from .env file."""
    import os

    from dotenv import load_dotenv

    load_dotenv(ctf.path / ".env")
    return {
        "username": os.getenv("CTF_USERNAME"),
        "password": os.getenv("CTF_PASSWORD"),
        "token": os.getenv("CTF_TOKEN"),
    }


def sync_remote_ctf(ctf: CTF) -> None:
    """Fetch new challenges for ``ctf`` from its remote platform."""
    from pwnv.utils.crud import challenges_for_ctf
    from pwnv.utils.ui import info, warn

    if not ctf.url:
        warn("CTF has no remote URL configured.")
        return

    client, methods = _run_async(get_remote_credential_methods(ctf.url))
    if client is None or methods is None:
        return

    local_challenges = {sanitize(ch.name): ch for ch in challenges_for_ctf(ctf)}

    # Try to authenticate
    session_loaded = False
    if (ctf.path / ".session").exists():
        try:
            _run_async(client.session.load(str(ctf.path / ".session")))
            session_loaded = True
        except Exception as e:
            warn(f"Ignoring broken session cookie ({e}).")

    if not session_loaded:
        # Need to create a new session
        if (ctf.path / ".env").exists():
            creds = _get_creds_from_env(ctf)
        else:
            creds = _ask_for_credentials(methods)
            if not creds:
                return
        if not _run_async(create_remote_session(client, creds, ctf)):
            return

    challenges = _run_async(get_remote_challenges(client, ctf))
    if challenges is None:
        return

    # If we got 0 challenges but have local ones, session might be stale - try re-auth
    if not challenges and local_challenges:
        warn("Got 0 challenges from server but have local challenges. Session may be stale, re-authenticating...")
        if (ctf.path / ".env").exists():
            creds = _get_creds_from_env(ctf)
        else:
            creds = _ask_for_credentials(methods)
            if not creds:
                return
        if not _run_async(create_remote_session(client, creds, ctf)):
            return
        challenges = _run_async(get_remote_challenges(client, ctf))
        if challenges is None:
            return

    info(f"Found {len(challenges)} challenges on server, {len(local_challenges)} local")

    new_challenges = [ch for ch in challenges if sanitize(ch.name) not in local_challenges]

    # Generate READMEs for existing challenges that don't have one
    for remote_ch in challenges:
        name = sanitize(remote_ch.name)
        if name in local_challenges:
            local_ch = local_challenges[name]
            readme_path = local_ch.path / "README.md"
            if not readme_path.exists():
                services = [svc.model_dump(mode="json") for svc in getattr(remote_ch, "services", [])]
                _write_challenge_readme(local_ch, remote_ch, services)
                info(f"Generated README for {local_ch.name}")

    if not new_challenges:
        info("No new challenges found.")
        return

    info(f"Downloading {len(new_challenges)} new challenges...")
    _run_async(add_remote_challenges(client, ctf, new_challenges))


async def get_remote_credential_methods(
    url: str | None,
) -> Tuple[Any, Any] | Tuple[None, None]:
    """Retrieve supported authentication methods from the remote platform."""
    from ctfbridge import create_client

    if not url:
        return None, None

    try:
        client: Any = await create_client(url=url)
    except Exception:
        from pwnv.utils.ui import error

        error("Failed to get client.")
        return None, None
    methods = await client.auth.get_supported_auth_methods()
    return client, methods


async def create_remote_session(
    client: Any, creds: Dict[str, str | None], ctf: CTF
) -> bool:
    """Create and store an authenticated session."""
    try:
        await client.auth.login(**{k: v for k, v in creds.items() if v is not None})
        await client.session.save(str(ctf.path / ".session"))
        return True
    except Exception:
        from pwnv.utils.ui import error

        error("Failed to authenticate with the provided credentials.")
        return False


async def get_remote_challenges(client: Any, ctf: CTF):
    """Fetch the list of challenges for ``ctf`` from the remote platform."""
    try:
        await client.session.load(str(ctf.path / ".session"))
        challenges = await client.challenges.get_all()
        return challenges
    except Exception:
        from pwnv.utils.ui import error

        error("Failed to fetch challenges.")
        return None


def _write_challenge_readme(challenge: Challenge, remote_ch, services) -> None:
    """Write a README.md with challenge description to the challenge folder."""
    readme_path = challenge.path / "README.md"
    challenge.path.mkdir(parents=True, exist_ok=True)

    lines = [f"# {remote_ch.name}", ""]

    meta = []
    if challenge.category:
        meta.append(f"**Category:** {challenge.category.name}")
    if challenge.points:
        meta.append(f"**Points:** {challenge.points}")
    if remote_ch.author:
        meta.append(f"**Author:** {remote_ch.author}")
    if meta:
        lines.append(" | ".join(meta))
        lines.append("")

    if remote_ch.description:
        lines.append("## Description")
        lines.append("")
        lines.append(remote_ch.description)
        lines.append("")

    if services:
        lines.append("## Connection")
        lines.append("")
        for svc in services:
            if svc.get("url"):
                lines.append(f"- {svc['url']}")
            elif svc.get("host") and svc.get("port"):
                lines.append(f"- `nc {svc['host']} {svc['port']}`")
        lines.append("")

    with open(readme_path, "w") as f:
        f.write("\n".join(lines))


async def _download_attachments_with_retry(
    client, ch, path, max_retries: int = 3, base_delay: float = 2.0
):
    """Download attachments with exponential backoff retry."""
    from pwnv.utils.ui import warn

    last_error = None
    for attempt in range(max_retries):
        try:
            return await client.attachments.download_all(ch, save_dir=path)
        except Exception as e:
            last_error = e
            if attempt < max_retries - 1:
                delay = base_delay * (2 ** attempt)
                warn(f"Download failed for {ch.name}, retrying in {delay:.0f}s... ({attempt + 1}/{max_retries})")
                await asyncio.sleep(delay)

    warn(f"Failed to download attachments for {ch.name} after {max_retries} attempts: {last_error}")
    return ch  # Return original challenge without downloaded attachments


async def add_remote_challenges(client, ctf: CTF, challenges) -> None:
    """Persist fetched challenges locally and download attachments."""
    from pwnv.models import Challenge
    from pwnv.models.challenge import Solved
    from pwnv.utils.crud import add_challenge
    from pwnv.utils.ui import success

    for ch in challenges:
        category = normalise_category(ch.category)
        name = sanitize(ch.name)
        path = ctf.path / category.name / name

        ch = await _download_attachments_with_retry(client, ch, path)

        attachments = [
            att.model_dump(mode="json") for att in getattr(ch, "attachments", [])
        ]
        services = [svc.model_dump(mode="json") for svc in getattr(ch, "services", [])]

        challenge = Challenge(
            name=name,
            ctf_id=ctf.id,
            path=path,
            category=category,
            points=ch.value,
            solved=Solved.solved if ch.solved else Solved.unsolved,
            extras={
                "slug": ch.id,
                "description": ch.description,
                "attachments": attachments,
                "services": services,
                "author": ch.author,
            },
            tags=ch.tags,
        )
        add_challenge(challenge)

        _write_challenge_readme(challenge, ch, services)

        success(f"{challenge.name} ({challenge.points} pts) added")


async def remote_solve(ctf: CTF, challenge: Challenge, flag: str) -> bool:
    """Submit ``flag`` to the remote platform and return ``True`` if correct."""
    import os

    from ctfbridge import create_client
    from dotenv import load_dotenv

    if not ctf.url:
        return False

    client: Any = await create_client(ctf.url)
    if (ctf.path / ".session").exists():
        try:
            await client.session.load(str(ctf.path / ".session"))
        except Exception as e:
            from pwnv.utils.ui import warn

            warn(f"Ignoring broken session cookie ({e}).")

    elif (ctf.path / ".env").exists():
        load_dotenv(ctf.path / ".env")
        creds = {
            "username": os.getenv("CTF_USERNAME"),
            "password": os.getenv("CTF_PASSWORD"),
            "token": os.getenv("CTF_TOKEN"),
        }
        await client.auth.login(**{k: v for k, v in creds.items() if v is not None})
    else:
        creds = _ask_for_credentials(await client.auth.get_supported_auth_methods())
        if not await create_remote_session(client, creds, ctf):
            return False

    try:
        slug = (
            challenge.extras.get("slug") if isinstance(challenge.extras, dict) else None
        )
        if slug is None:
            return False
        res = await client.challenges.submit(slug, flag)
        if res.correct:
            from pwnv.utils.ui import success

            success(f"Flag [cyan]{flag}[/] accepted!")

            return True
        else:
            from pwnv.utils.ui import error

            error(f"Flag [cyan]{flag}[/] incorrect")
            return False
    except Exception:
        from pwnv.utils.ui import error

        error(f"Failed to submit flag '{flag}'.")
        return False
