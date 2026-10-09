"""Testes de configuracao: resolucao de wordlists e deteccao de comprimidas.

O caso que motivou estes testes: na Kali o rockyou vem como `rockyou.txt.gz`
de fabrica. Nem o hashcat nem o aircrack-ng descompactam, entao aceitar um .gz
como wordlist valida faria o pipeline "quebrar" sem produzir candidato nenhum,
em silencio.
"""

from __future__ import annotations

import unittest

try:
    from ._base import TempCase
except ImportError:      # execucao direta: python tests/test_config.py
    from _base import TempCase  # type: ignore[no-redef]

from wifite_pipeline.config import (
    TOOLS,
    Settings,
    find_tool,
    is_compressed,
    resolve_wordlist,
    tool_available,
)


class TestDeteccaoDeComprimida(unittest.TestCase):
    def test_reconhece_extensoes_comprimidas(self):
        for nome in ("rockyou.txt.gz", "lista.bz2", "x.xz", "y.zip", "z.7z", "w.tgz", "v.tar"):
            with self.subTest(nome=nome):
                self.assertTrue(is_compressed(nome))

    def test_nao_marca_arquivo_normal(self):
        for nome in ("rockyou.txt", "best110.txt", "regra.rule", "README.md", "lista"):
            with self.subTest(nome=nome):
                self.assertFalse(is_compressed(nome))

    def test_ignora_maiusculas(self):
        self.assertTrue(is_compressed("ROCKYOU.TXT.GZ"))


class TestSettings(TempCase):
    def _settings(self, *nomes: str) -> Settings:
        s = Settings()
        s.wordlists = [str(self.tmp / n) for n in nomes]
        return s

    def test_existing_wordlists_ignora_comprimidas(self):
        self.write("pronta.txt", "a\nb\n")
        self.write("comprimida.txt.gz", "binario")
        s = self._settings("pronta.txt", "comprimida.txt.gz")

        validas = s.existing_wordlists()
        self.assertEqual(len(validas), 1)
        self.assertTrue(validas[0].endswith("pronta.txt"))

    def test_compressed_wordlists_lista_so_as_comprimidas(self):
        self.write("pronta.txt", "a\n")
        self.write("comprimida.txt.gz", "binario")
        s = self._settings("pronta.txt", "comprimida.txt.gz")

        comprimidas = s.compressed_wordlists()
        self.assertEqual(len(comprimidas), 1)
        self.assertTrue(comprimidas[0].endswith(".gz"))

    def test_existing_wordlists_ignora_arquivo_ausente(self):
        self.write("existe.txt", "a\n")
        s = self._settings("existe.txt", "nao_existe.txt")
        self.assertEqual(len(s.existing_wordlists()), 1)

    def test_ordem_de_prioridade_e_preservada(self):
        self.write("primeira.txt", "a\n")
        self.write("segunda.txt", "b\n")
        s = self._settings("segunda.txt", "primeira.txt")
        self.assertTrue(s.existing_wordlists()[0].endswith("segunda.txt"))


class TestResolveWordlist(TempCase):
    def test_explicita_valida_e_devolvida(self):
        caminho = self.write("minha.txt", "a\n")
        self.assertEqual(resolve_wordlist(str(caminho), Settings()), str(caminho))

    def test_explicita_comprimida_devolve_none(self):
        caminho = self.write("rockyou.txt.gz", "x")
        self.assertIsNone(resolve_wordlist(str(caminho), Settings()))

    def test_explicita_ausente_devolve_none(self):
        self.assertIsNone(resolve_wordlist(str(self.tmp / "nada.txt"), Settings()))

    def test_sem_explicita_usa_a_primeira_valida(self):
        self.write("primeira.txt", "a\n")
        self.write("segunda.txt", "b\n")
        s = Settings()
        s.wordlists = [str(self.tmp / "primeira.txt"), str(self.tmp / "segunda.txt")]
        self.assertTrue(resolve_wordlist(None, s).endswith("primeira.txt"))

    def test_sem_explicita_pula_comprimida_e_usa_a_proxima(self):
        """Regressao: uma rockyou.txt.gz nao pode esconder a wordlist seguinte."""
        self.write("comprimida.txt.gz", "x")
        self.write("valida.txt", "a\n")
        s = Settings()
        s.wordlists = [str(self.tmp / "comprimida.txt.gz"), str(self.tmp / "valida.txt")]
        self.assertTrue(resolve_wordlist(None, s).endswith("valida.txt"))

    def test_sem_explicita_e_sem_nenhuma_valida_devolve_none(self):
        self.write("so_comprimida.txt.gz", "x")
        s = Settings()
        s.wordlists = [str(self.tmp / "so_comprimida.txt.gz")]
        self.assertIsNone(resolve_wordlist(None, s))


class TestCatalogoDeFerramentas(unittest.TestCase):
    def test_toda_ferramenta_esta_bem_declarada(self):
        for nome, meta in TOOLS.items():
            with self.subTest(ferramenta=nome):
                self.assertIn("required", meta)
                self.assertIn("apt", meta)
                self.assertIn("why", meta)
                self.assertIsInstance(meta["required"], bool)

    def test_existe_pelo_menos_uma_obrigatoria(self):
        self.assertTrue(any(m["required"] for m in TOOLS.values()))

    def test_ferramenta_inexistente_nao_e_encontrada(self):
        nome = "ferramenta-que-nao-existe-xyz"
        self.assertIsNone(find_tool(nome))
        self.assertFalse(tool_available(nome))


class TestDefaults(unittest.TestCase):
    def test_caminhos_de_estado_derivam_do_state_dir(self):
        s = Settings()
        self.assertEqual(s.db_path.parent, s.state_path)
        self.assertTrue(str(s.db_path).endswith("pipeline.db"))
        self.assertEqual(s.results_dir.parent, s.state_path)

    def test_uso_autorizado_vem_desligado(self):
        """A trava precisa comecar fechada: o padrao seguro e exigir confirmacao."""
        self.assertFalse(Settings().authorized_use_acknowledged)

    def test_conexao_automatica_vem_desligada(self):
        self.assertFalse(Settings().auto_connect)

    def test_ida_e_volta_por_dict(self):
        s = Settings()
        s.capture_interface = "wlan0"
        s.connect_interface = "wlan1"
        outro = Settings.from_dict(s.to_dict())
        self.assertEqual(outro.capture_interface, "wlan0")
        self.assertEqual(outro.connect_interface, "wlan1")

    def test_from_dict_ignora_chave_desconhecida(self):
        """Config antiga com campo removido nao pode derrubar o programa."""
        s = Settings.from_dict({"capture_interface": "wlan0", "campo_que_nao_existe": 42})
        self.assertEqual(s.capture_interface, "wlan0")


if __name__ == "__main__":       # pragma: no cover
    unittest.main(verbosity=2)
