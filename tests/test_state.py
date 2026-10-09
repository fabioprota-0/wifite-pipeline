"""Testes do banco de estado: fila, resultados, importacao e concorrencia.

Usa `unittest` da biblioteca padrao de proposito: o projeto nao tem nenhuma
dependencia externa, entao os testes tambem nao devem ter. Rodam com:

    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path

try:
    from ._base import TempCase
except ImportError:      # execucao direta: python tests/test_state.py
    from _base import TempCase  # type: ignore[no-redef]

from wifite_pipeline.state import (
    STATUS_CRACKING,
    STATUS_EXHAUSTED,
    STATUS_FOUND,
    STATUS_PENDING,
    State,
    normalize_bssid,
)


class StateTestCase(TempCase):
    def setUp(self) -> None:
        super().setUp()
        self.state = State(self.tmp / "pipeline.db")

    def tearDown(self) -> None:
        self.state.close()
        super().tearDown()


class TestBssid(StateTestCase):
    def test_formatos_variados(self):
        self.assertEqual(normalize_bssid("aabbccddeeff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_bssid("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF")
        self.assertEqual(normalize_bssid("AA:BB:CC:DD:EE:FF"), "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(normalize_bssid("aa:bb:cc:dd:ee"))
        self.assertIsNone(normalize_bssid(""))
        self.assertIsNone(normalize_bssid(None))


class TestFila(StateTestCase):
    def test_enqueue_e_deduplicacao(self):
        first = self.state.enqueue("aabbccddeeff", "MinhaRede", capture_path="/tmp/a.cap")
        self.assertIsNotNone(first)
        # Mesmo BSSID + mesma captura: nao duplica.
        self.assertIsNone(self.state.enqueue("aabbccddeeff", "MinhaRede", capture_path="/tmp/a.cap"))
        # Mesmo BSSID, captura diferente: alvo novo (recaptura).
        other = self.state.enqueue("aabbccddeeff", "MinhaRede", capture_path="/tmp/b.cap")
        self.assertIsNotNone(other)
        self.assertNotEqual(other, first)

    def test_claim_next_nao_entrega_o_mesmo_alvo_duas_vezes(self):
        self.state.enqueue("aa:bb:cc:dd:ee:01", "Rede1")
        self.state.enqueue("aa:bb:cc:dd:ee:02", "Rede2")

        first = self.state.claim_next()
        second = self.state.claim_next()
        third = self.state.claim_next()

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertNotEqual(first.id, second.id)
        self.assertIsNone(third)
        self.assertEqual(first.status, STATUS_CRACKING)

    def test_reset_stuck_devolve_alvos_presos(self):
        self.state.enqueue("aa:bb:cc:dd:ee:06", "Rede6")
        self.state.claim_next()
        self.assertEqual(self.state.counts()[STATUS_CRACKING], 1)

        self.assertEqual(self.state.reset_stuck(), 1)
        self.assertEqual(self.state.counts()[STATUS_PENDING], 1)
        self.assertEqual(self.state.counts()[STATUS_CRACKING], 0)

    def test_requeue_exhausted(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:07", "Rede7")
        self.state.set_status(tid, STATUS_EXHAUSTED)
        self.assertEqual(self.state.requeue_exhausted(), 1)
        self.assertEqual(self.state.get(tid).status, STATUS_PENDING)

    def test_counts(self):
        t1 = self.state.enqueue("aa:bb:cc:dd:ee:08", "R1")
        t2 = self.state.enqueue("aa:bb:cc:dd:ee:09", "R2")
        self.state.mark_found(t1, "x", "hashcat")
        self.state.set_status(t2, STATUS_EXHAUSTED)
        counts = self.state.counts()
        self.assertEqual(counts[STATUS_FOUND], 1)
        self.assertEqual(counts[STATUS_EXHAUSTED], 1)
        self.assertEqual(counts["total"], 2)


class TestResultados(StateTestCase):
    def test_mark_found_grava_senha_metodo_e_attempt(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:03", "Rede3")
        self.state.claim_next()
        self.state.mark_found(tid, "senha123", "hashcat")

        target = self.state.get(tid)
        self.assertEqual(target.status, STATUS_FOUND)
        self.assertEqual(target.password, "senha123")
        self.assertEqual(target.method, "hashcat")
        self.assertEqual(target.attempts, 1)
        self.assertEqual(len(self.state.results()), 1)

    def test_senha_nunca_vaza_para_o_log_de_eventos(self):
        """Higiene de seguranca: o evento registra o fato, nunca a senha."""
        tid = self.state.enqueue("aa:bb:cc:dd:ee:04", "Rede4")
        self.state.mark_found(tid, "SuperSecreta!", "aircrack")

        blob = " ".join(e["message"] for e in self.state.recent_events(50))
        self.assertNotIn("SuperSecreta!", blob)
        self.assertIn("senha encontrada", blob)

    def test_known_password_evita_requebra(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:05", "Rede5", capture_path="/tmp/c5.cap")
        self.state.mark_found(tid, "reutilizada", "hashcat")

        self.assertEqual(self.state.known_password("Rede5", "aa:bb:cc:dd:ee:05"), "reutilizada")
        self.assertEqual(self.state.known_password("Rede5", "11:22:33:44:55:66"), "reutilizada")
        self.assertIsNone(self.state.known_password("Outra", "11:22:33:44:55:77"))


class TestExportacao(StateTestCase):
    def test_txt_tem_ssid_e_senha_lado_a_lado(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:0a", "CasaDoRafa")
        self.state.mark_found(tid, "minhasenha", "hashcat")

        out = self.state.export_results(self.tmp / "cracked.txt", "txt")
        self.assertEqual(out.read_text(encoding="utf-8").strip(), "CasaDoRafa:minhasenha")

    def test_json_e_csv(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:0b", "Escritorio")
        self.state.mark_found(tid, "senhaForte", "hashcat")

        js = json.loads(self.state.export_results(self.tmp / "r.json", "json").read_text(encoding="utf-8"))
        self.assertEqual(js[0]["ssid"], "Escritorio")
        self.assertEqual(js[0]["password"], "senhaForte")
        self.assertEqual(js[0]["bssid"], "AA:BB:CC:DD:EE:0B")

        csv_text = self.state.export_results(self.tmp / "r.csv", "csv").read_text(encoding="utf-8")
        self.assertIn("ssid,bssid,password", csv_text)
        self.assertIn("Escritorio", csv_text)

    def test_formato_wifite(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:0c", "Loja")
        self.state.mark_found(tid, "senhaLoja", "aircrack")
        text = self.state.export_results(self.tmp / "wf.txt", "wifite").read_text(encoding="utf-8")
        self.assertIn("BSSID", text)
        self.assertIn("PSK", text)
        self.assertIn("senhaLoja", text)


class TestImportacao(StateTestCase):
    def _write(self, name: str, content: str) -> Path:
        p = self.tmp / name
        p.write_text(content, encoding="utf-8")
        return p

    def test_txt_ssid_senha(self):
        f = self._write("a.txt", "RedeA:senhaA\nRedeB:senhaB\n")
        report = self.state.import_results(f)
        self.assertEqual(report.added, 2)
        self.assertEqual(self.state.known_password("RedeA", None), "senhaA")

    def test_txt_bssid_senha_com_dois_pontos(self):
        """BSSID tambem contem ':' -- o parser precisa desambiguar."""
        f = self._write("b.txt", "aa:bb:cc:dd:ee:0d:senhaDoBssid\n")
        self.state.import_results(f)
        self.assertEqual(self.state.known_password(None, "aa:bb:cc:dd:ee:0d"), "senhaDoBssid")

    def test_json(self):
        f = self._write("r.json", json.dumps([
            {"ssid": "JsonNet", "bssid": "aa:bb:cc:dd:ee:0e", "password": "senhaJson"},
        ]))
        report = self.state.import_results(f)
        self.assertEqual(report.added, 1)
        self.assertEqual(self.state.known_password("JsonNet", "aa:bb:cc:dd:ee:0e"), "senhaJson")

    def test_csv(self):
        f = self._write("r.csv", "ssid,bssid,password,method\nCsvNet,aa:bb:cc:dd:ee:0f,senhaCsv,import\n")
        report = self.state.import_results(f)
        self.assertEqual(report.added, 1)
        self.assertEqual(self.state.known_password("CsvNet", None), "senhaCsv")

    def test_tabela_do_wifite(self):
        f = self._write("cracked.txt",
                        "BSSID              ESSID                    PSK\n"
                        "AA:BB:CC:DD:EE:10  RedeDoWifite             senhaWifite\n")
        report = self.state.import_results(f)
        self.assertEqual(report.added, 1)
        self.assertEqual(self.state.known_password("RedeDoWifite", "aa:bb:cc:dd:ee:10"), "senhaWifite")

    def test_importar_resolve_alvo_que_ja_esta_na_fila(self):
        tid = self.state.enqueue("aa:bb:cc:dd:ee:11", "Pendente")
        self.assertEqual(self.state.get(tid).status, STATUS_PENDING)

        f = self._write("s.txt", "Pendente:achadaPorImport\n")
        report = self.state.import_results(f)

        self.assertEqual(report.updated, 1)
        self.assertEqual(report.added, 0)
        self.assertEqual(self.state.get(tid).status, STATUS_FOUND)
        self.assertEqual(self.state.get(tid).password, "achadaPorImport")

    def test_arquivo_inexistente_nao_explode(self):
        report = self.state.import_results(self.tmp / "nao_existe.txt")
        self.assertEqual(report.total, 0)
        self.assertTrue(report.errors)

    def test_ignora_vazias_e_comentarios(self):
        f = self._write("s.txt", "# comentario\n\nRedeC:senhaC\n   \n")
        report = self.state.import_results(f)
        self.assertEqual(report.added, 1)

    def test_ida_e_volta_export_import(self):
        """Ciclo completo: exportar e reimportar em banco limpo."""
        tid = self.state.enqueue("aa:bb:cc:dd:ee:12", "Ciclo")
        self.state.mark_found(tid, "senhaCiclo", "hashcat")
        exported = self.state.export_results(self.tmp / "ciclo.json", "json")

        other = State(self.tmp / "outro.db")
        try:
            report = other.import_results(exported)
            self.assertEqual(report.added, 1)
            self.assertEqual(other.known_password("Ciclo", None), "senhaCiclo")
        finally:
            other.close()


if __name__ == "__main__":       # pragma: no cover
    unittest.main(verbosity=2)
