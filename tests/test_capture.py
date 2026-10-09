"""Testes do modulo de captura: nomes de arquivo, validacao e conversao.

Nao dependemos de arquivos .cap reais nem de hardware: testamos a logica pura
(analise do nome, decisao de validade) e, para a conversao, apenas o caminho
de arquivo que ja e 22000.
"""

from __future__ import annotations

import os
import shutil
import unittest
from pathlib import Path

try:
    from ._base import TempCase as _BaseTempCase
except ImportError:      # execucao direta: python tests/test_capture.py
    from _base import TempCase as _BaseTempCase  # type: ignore[no-redef]

from wifite_pipeline.capture import (
    CaptureInfo,
    clean_essid,
    from_filename,
    is_capture_file,
    to_22000,
)


class TempCase(_BaseTempCase):
    """Acrescenta um helper para criar arquivos de captura falsos."""

    def touch(self, name: str, content: bytes = b"x") -> Path:
        path = self.tmp / name
        path.write_bytes(content)
        return path


class TestNomeDeArquivo(unittest.TestCase):
    def test_padrao_do_wifite_com_airodump(self):
        bssid, essid = from_filename(Path("handshake_MinhaRede_AA:BB:CC:DD:EE:FF-01.cap"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(essid, "MinhaRede")

    def test_essid_com_underscore(self):
        bssid, essid = from_filename(Path("handshake_Casa_do_Rafa_AA-BB-CC-DD-EE-FF-02.cap"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:FF")
        self.assertEqual(essid, "Casa_do_Rafa")

    def test_essid_com_espacos_no_nome(self):
        """Nomes de rede reais tem espacos; wifite troca por underscore."""
        bssid, essid = from_filename(Path("handshake_TP-LINK_2.4GHz_AA:BB:CC:DD:EE:01.cap"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:01")
        self.assertEqual(essid, "TP-LINK_2.4GHz")

    def test_ordem_invertida_bssid_primeiro(self):
        bssid, essid = from_filename(Path("AA:BB:CC:DD:EE:02_RedeInvertida.pcapng"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:02")
        self.assertEqual(essid, "RedeInvertida")

    def test_hash_puro_do_hcxpcapngtool(self):
        bssid, essid = from_filename(Path("AA:BB:CC:DD:EE:03.22000"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:03")
        self.assertIsNone(essid)

    def test_nome_desconhecido_devolve_none(self):
        bssid, essid = from_filename(Path("airodump-01.cap"))
        self.assertIsNone(bssid)
        self.assertIsNone(essid)

    # -- Regressao ------------------------------------------------------
    def test_handshake_com_extensao_de_hash_nao_engole_o_prefixo(self):
        """Bug real: o padrao 'handshake_' nao listava .22000, entao o arquivo
        caia no padrao generico e o ESSID virava 'handshake_CasaDoRafa'. Isso
        quebrava o cache de senhas conhecidas, que casa por SSID."""
        bssid, essid = from_filename(Path("handshake_CasaDoRafa_AA-BB-CC-DD-EE-01-01.22000"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:01")
        self.assertEqual(essid, "CasaDoRafa")

    def test_todas_as_extensoes_aceitas_pelo_padrao_handshake(self):
        for ext in ("cap", "pcap", "pcapng", "22000", "16800", "pmkid"):
            with self.subTest(ext=ext):
                bssid, essid = from_filename(Path(f"handshake_Rede_AA-BB-CC-DD-EE-05-01.{ext}"))
                self.assertEqual(essid, "Rede")
                self.assertEqual(bssid, "AA:BB:CC:DD:EE:05")

    def test_essid_com_underscore_e_extensao_de_hash(self):
        bssid, essid = from_filename(Path("handshake_Casa_do_Rafa_AA-BB-CC-DD-EE-06-01.22000"))
        self.assertEqual(bssid, "AA:BB:CC:DD:EE:06")
        self.assertEqual(essid, "Casa_do_Rafa")


class TestLimpezaDeEssid(unittest.TestCase):
    def test_remove_prefixo_de_ferramenta(self):
        self.assertEqual(clean_essid("handshake_Rede"), "Rede")
        self.assertEqual(clean_essid("airodump-Rede"), "Rede")
        self.assertEqual(clean_essid("pmkid_Rede"), "Rede")

    def test_token_solto_vira_none(self):
        """Sem nome de rede no arquivo, nao inventamos um SSID."""
        self.assertIsNone(clean_essid("handshake"))
        self.assertIsNone(clean_essid("airodump"))
        self.assertIsNone(clean_essid("PMKID"))

    def test_preserva_nome_normal(self):
        self.assertEqual(clean_essid("MinhaRede"), "MinhaRede")
        self.assertEqual(clean_essid("TP-LINK_2.4GHz"), "TP-LINK_2.4GHz")
        self.assertEqual(clean_essid("Rede com espaco"), "Rede com espaco")

    def test_none_e_vazio(self):
        self.assertIsNone(clean_essid(None))
        self.assertIsNone(clean_essid(""))
        self.assertIsNone(clean_essid("   "))


class TestValidade(unittest.TestCase):
    def test_valido_com_bssid_e_handshake(self):
        info = CaptureInfo(path=Path("x.cap"), bssid="AA:BB:CC:DD:EE:FF", has_handshake=True)
        self.assertTrue(info.valid)
        self.assertEqual(info.kind, "handshake")

    def test_valido_com_pmkid(self):
        info = CaptureInfo(path=Path("x.pcapng"), bssid="AA:BB:CC:DD:EE:FF", has_pmkid=True)
        self.assertTrue(info.valid)
        self.assertEqual(info.kind, "pmkid")

    def test_invalido_sem_bssid(self):
        info = CaptureInfo(path=Path("x.cap"), has_handshake=True)
        self.assertFalse(info.valid)

    def test_invalido_sem_handshake_nem_pmkid(self):
        info = CaptureInfo(path=Path("x.cap"), bssid="AA:BB:CC:DD:EE:FF")
        self.assertFalse(info.valid)

    def test_arquivo_22000_e_valido_so_pela_extensao(self):
        info = CaptureInfo(path=Path("AA:BB:CC:DD:EE:FF.22000"), bssid="AA:BB:CC:DD:EE:FF")
        self.assertTrue(info.valid)
        self.assertEqual(info.kind, "hash")


class TestConversao(TempCase):
    @unittest.skipIf(os.name == "nt", "':' e caractere ilegal em nome de arquivo no Windows")
    def test_arquivo_ja_22000_e_devolvido_como_esta(self):
        src = self.touch("AA:BB:CC:DD:EE:FF.22000", b"WPA*01*deadbeef\n")
        self.assertEqual(to_22000(src, self.tmp / "out"), src)

    def test_arquivo_22000_sem_dois_pontos_tambem_passa_direto(self):
        src = self.touch("AA-BB-CC-DD-EE-FF.22000", b"WPA*01*deadbeef\n")
        self.assertEqual(to_22000(src, self.tmp / "out"), src)

    def test_cap_sem_hcxpcapngtool_devolve_none(self):
        """Sem a ferramenta instalada, a conversao falha de forma controlada."""
        if shutil.which("hcxpcapngtool"):
            self.skipTest("hcxpcapngtool instalado neste ambiente")
        src = self.touch("x.cap", b"\x00" * 32)
        self.assertIsNone(to_22000(src, self.tmp / "out"))


class TestSelecaoDeArquivo(TempCase):
    def test_extensoes_aceitas(self):
        for name in ("a.cap", "b.pcap", "c.pcapng", "d.22000", "e.16800", "f.pmkid"):
            self.assertTrue(is_capture_file(self.touch(name)), name)

    def test_extensoes_recusadas(self):
        for name in ("a.txt", "b.csv", "c.kismet.csv", "d.log"):
            self.assertFalse(is_capture_file(self.touch(name)), name)

    def test_diretorio_nao_e_arquivo_de_captura(self):
        self.assertFalse(is_capture_file(self.tmp))


if __name__ == "__main__":       # pragma: no cover
    unittest.main(verbosity=2)
