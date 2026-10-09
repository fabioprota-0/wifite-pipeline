"""Base comum dos testes: pasta temporaria de nome deterministico.

Por que nao `tempfile.mkdtemp()`: alem de nomes aleatorios serem ruins de
inspecionar quando um teste falha, antivirus com protecao anti-ransomware
(Avast, por exemplo) bloqueiam o padrao "cria pasta de nome aleatorio e escreve
dentro imediatamente". Nomes deterministicos resolvem os dois problemas.

A variavel de ambiente `WP_TEST_DIR` permite ao CI escolher onde os testes
escrevem (util quando /tmp e tmpfs pequeno ou somente leitura).
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path


def temp_base() -> Path:
    base = os.environ.get("WP_TEST_DIR")
    path = Path(base) if base else Path(tempfile.gettempdir())
    path.mkdir(parents=True, exist_ok=True)
    return path


class TempCase(unittest.TestCase):
    """Cria `self.tmp`, uma pasta propria e limpa, com nome previsivel."""

    def setUp(self) -> None:
        nome = f"wptest-{os.getpid()}-{self.__class__.__name__}-{self._testMethodName}"
        self.tmp = temp_base() / nome
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write(self, name: str, content: str) -> Path:
        path = self.tmp / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path
