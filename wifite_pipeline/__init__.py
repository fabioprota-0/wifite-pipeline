"""wifite-pipeline: orquestrador paralelo em volta do wifite.

Transforma o fluxo sequencial do wifite (capturar -> quebrar -> proximo) num
pipeline com estagios independentes:

    [wifite --skip-crack]  ->  [watcher]  ->  [cracker]  ->  [results]
          captura              detecta        quebra        registra
                                                                 |
                                                                 v
                                                       [connector / nmcli]

O estado vive num banco SQLite compartilhado, seguro para varios processos
simultaneos, permitindo que cada painel do tmux seja um processo separado.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
