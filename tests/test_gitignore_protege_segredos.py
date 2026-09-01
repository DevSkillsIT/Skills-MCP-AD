"""The .gitignore must keep AD credentials out of the index -- verified, not read.

The rules were audited by creating the files and asking git, not by reading the
patterns. That audit found five real holes in the monorepo: a config parked at
the directory root, one inside a configs/ subfolder, and the variants
ad-servers.backup.json / ad-servers-2026.json / any new ad-*.json under
_shared/configs. It also found that the glob `ad-servers*.json` does not match
`meu-ad-servers.json`, which needs `*ad-servers*`.

Each of those would have committed the service-account password of every
configured directory at once. This test exists so a later "simplification" of
the rules cannot quietly reopen them.
"""

import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
MONOREPO = Path("/opt/mcp-servers")

# Paths a hurried operator actually creates.
DEVE_IGNORAR = [
    "ad-config/ad-config.json",
    "ad-config/ad-servers.json",
    "ad-config/ad-servers.backup.json",
    "ad-config/ad-servers-2026.json",
    "ad-config/producao.json",
    "configs/prod.json",
    "src/meu-ad-servers.json",
    "backup-ad-config.json",
    ".env",
]

# Templates carry no secret and must stay versioned.
DEVE_VERSIONAR = [
    "ad-config/ad-config.example.json",
    "ad-config/ad-servers.example.json",
]


def _ignorado(repo: Path, caminho: str) -> bool:
    r = subprocess.run(["git", "check-ignore", "-q", caminho],
                       cwd=repo, capture_output=True)
    return r.returncode == 0


@pytest.mark.parametrize("caminho", DEVE_IGNORAR)
def test_config_com_credencial_nunca_entra(caminho):
    assert _ignorado(REPO, caminho), (
        f"{caminho} SERIA COMMITADO. Um arquivo desses leva a senha de todos os "
        "diretorios configurados."
    )


@pytest.mark.parametrize("caminho", DEVE_VERSIONAR)
def test_templates_continuam_versionados(caminho):
    assert not _ignorado(REPO, caminho), (
        f"{caminho} passou a ser ignorado; os templates precisam ficar no repo."
    )


@pytest.mark.skipif(not (MONOREPO / ".gitignore").exists(),
                    reason="monorepo nao presente (repositorio isolado)")
@pytest.mark.parametrize("caminho", [
    "active-directory/multi/ad-servers.json",
    "active-directory/multi/.env",
    "active-directory/ad-servers.json",
    "active-directory/multi/configs/prod.json",
    "active-directory/multi/ad-servers.backup.json",
    "active-directory/multi/ad-servers-2026.json",
    "_shared/configs/ad-qualquer.json",
    "active-directory/cliente-novo/ad-config/ad-config.json",
])
def test_monorepo_tambem_protege(caminho):
    assert _ignorado(MONOREPO, caminho), f"{caminho} SERIA COMMITADO no monorepo."
