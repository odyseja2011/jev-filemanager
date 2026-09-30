from __future__ import annotations

import os
import stat
import subprocess
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from migrator import db
from migrator.runs import create_run, open_run
from tests.fake_jev import FakeJev, standard_rules
from tests.helpers import write_config, write_files


@dataclass
class Env:
    tmp: Path
    dsn: str
    conn: object
    config: Path
    src: Path
    lib: Path
    ws: Path
    wrapper: Path

    def new_run(self, config: Path | None = None):
        return create_run(self.conn, config or self.config)

    def run_batch(self, script: Path, **extra_env):
        env = dict(os.environ, MIGRATOR_DATABASE_URL=self.dsn, MIGRATOR_BIN=str(self.wrapper), **extra_env)
        return subprocess.run(["bash", str(script)], capture_output=True, text=True, env=env)


def populate(src: Path) -> None:
    write_files(src, {
        "MULTIMEDIA/FILMY/Dune/Dune.mkv": b"dune-data",
        "MULTIMEDIA/FILMY/Alien/Alien.mkv": b"alien-data",
        "MULTIMEDIA/SERIALE/Show/S01E01.mkv": b"s01e01",
        "MULTIMEDIA/Unsorted/Blade Runner (2017).mkv": b"blade",
        "MULTIMEDIA/Unsorted/weird.bin": b"weird",
        "MULTIMEDIA/Unsorted/maybe.mkv": b"maybe",
        "loose book.epub": b"epub-data",
        "Lowconf/song.mp3": b"song",
        "Lowconf/sub/song2.mp3": b"song2",
    })
    (src / "dangling").symlink_to(src / "nowhere")
    (src / "MULTIMEDIA" / "linkdir").symlink_to(src / "MULTIMEDIA" / "FILMY")
    (src / "hard_a.bin").write_bytes(b"hardlinked")
    os.link(src / "hard_a.bin", src / "hard_b.bin")


@pytest.fixture()
def bare_env(tmp_path, pg_dsn, conn):
    src, lib, ws = tmp_path / "MEDIA", tmp_path / "LIBRARY", tmp_path / "workspace"
    src.mkdir()
    for t in ("MOVIES", "SERIES", "MUSIC", "BOOKS"):
        (lib / t).mkdir(parents=True)
    cfg = write_config(tmp_path)
    wrapper = tmp_path / "mig"
    wrapper.write_text(f"#!/bin/sh\nexec {sys.executable} -m migrator \"$@\"\n")
    wrapper.chmod(0o755)
    return Env(tmp_path, pg_dsn, conn, cfg, src, lib, ws, wrapper)


@pytest.fixture()
def env(bare_env):
    populate(bare_env.src)
    return bare_env


def all_movies(state, question):
    return ("MOVIES", 0.99)


def ready_run(env, files, rules=None, config=None, **cfg_over):
    """Create files under MEDIA, then run create/inventory/classify/plan.  Returns (ctx, fake)."""
    from migrator import classifier, inventory, planner
    write_files(env.src, files)
    cfg = config or (write_config(env.tmp, **cfg_over) if cfg_over else env.config)
    fake = FakeJev(rules or all_movies)
    ctx = env.new_run(cfg)
    inventory.run_inventory(ctx)
    classifier.run_classification(ctx, fake)
    planner.create_plan(ctx)
    return ctx, fake


@pytest.fixture()
def fake():
    return FakeJev(standard_rules)
