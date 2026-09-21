#!/usr/bin/env python3
"""
presidio_scan.py — content classifier for the Go daemon worker.

Usage (per-file, one process per scan):
    python3 presidio_scan.py /path/to/file
        -> prints one JSON object to stdout, always exits 0.

Optional long-lived server mode (avoids paying model-load cost per file):
    python3 presidio_scan.py --server
        -> reads one file path per line on stdin, prints one JSON line per path.
           Exits 0 on EOF. The NLP model is loaded once and reused.

Output shape (success):
    {"path": "...",
     "entities": [{"type": "US_SSN", "count": 12, "max_score": 0.85}, ...],
     "scanned_bytes": 5242880,
     "truncated": true,
     "ner_available": true}

Output shape (failure — the caller logs it and moves on):
    {"error": "..."}

Design notes:
  * Always exits 0 so the worker never treats a bad/binary/unreadable file as a
    daemon crash. Errors are reported in-band as {"error": ...}.
  * Reading is capped (PRESIDIO_SCAN_MAX_BYTES, default 5 MiB) so a huge file
    cannot blow up memory or scan time. `truncated` reports whether the cap hit.
  * The spaCy model is loaded ONCE per process (module state). Building the
    AnalyzerEngine loads ~500-800 MB and takes a few seconds; that cost is paid
    per process, so for high volume prefer --server mode over one process/file.
  * Graceful degradation: if no spaCy model is installed we fall back to a blank
    spaCy pipeline (tokenizer only). Regex/checksum entities (CREDIT_CARD,
    US_SSN, IBAN, EMAIL_ADDRESS, PHONE_NUMBER, ...) still work; NER entities
    (PERSON, LOCATION, NRP, medical) simply won't be detected. `ner_available`
    tells the caller which mode ran. We never trigger Presidio's own network
    auto-download of a model — everything is loaded locally and deterministically.
"""

import json
import os
import sys

# ---- configuration ---------------------------------------------------------

# How many bytes of a file we are willing to read/scan. Huge files are truncated.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
try:
    MAX_BYTES = int(os.environ.get("PRESIDIO_SCAN_MAX_BYTES", DEFAULT_MAX_BYTES))
    if MAX_BYTES <= 0:
        MAX_BYTES = DEFAULT_MAX_BYTES
except (TypeError, ValueError):
    MAX_BYTES = DEFAULT_MAX_BYTES

# spaCy models to try, best accuracy first. First one that is already installed
# wins. If none are installed we drop to a blank (regex-only) pipeline.
SPACY_MODEL_CANDIDATES = ("en_core_web_lg", "en_core_web_md", "en_core_web_sm")

LANGUAGE = "en"

# ---- lazy, process-wide analyzer -------------------------------------------

_ANALYZER = None          # presidio AnalyzerEngine, built once
_NER_AVAILABLE = False     # True if a real NER model loaded, False if blank fallback


def _build_analyzer():
    """
    Build a single AnalyzerEngine. Loads a real spaCy model if one is installed,
    otherwise a blank spaCy pipeline so regex/checksum recognizers still run.

    Returns (analyzer, ner_available). Raises only if presidio itself is missing.
    """
    import spacy
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import SpacyNlpEngine

    class LoadedSpacyNlpEngine(SpacyNlpEngine):
        """Wrap an already-loaded spaCy pipeline so Presidio never re-loads or
        network-downloads a model. Setting self.nlp makes is_loaded() true."""
        def __init__(self, loaded_nlp):
            super().__init__()
            self.nlp = {LANGUAGE: loaded_nlp}

    loaded_nlp = None
    ner_available = False
    for model_name in SPACY_MODEL_CANDIDATES:
        try:
            loaded_nlp = spacy.load(model_name)
            ner_available = True
            break
        except Exception:
            # Not installed / failed to load — try the next candidate. We do NOT
            # call spacy.cli.download here: no surprise network calls in a daemon.
            continue

    if loaded_nlp is None:
        # Regex/checksum-only mode. spacy.blank always works (ships with spaCy)
        # and gives a tokenizer, which the pattern recognizers' context logic
        # and Presidio's pipeline need. It has no NER, so PERSON/LOCATION/NRP/
        # medical entities are simply absent.
        loaded_nlp = spacy.blank(LANGUAGE)
        ner_available = False

    nlp_engine = LoadedSpacyNlpEngine(loaded_nlp)
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[LANGUAGE])
    return analyzer, ner_available


def _get_analyzer():
    global _ANALYZER, _NER_AVAILABLE
    if _ANALYZER is None:
        _ANALYZER, _NER_AVAILABLE = _build_analyzer()
    return _ANALYZER, _NER_AVAILABLE


# ---- file reading ----------------------------------------------------------

def _read_text(path):
    """
    Read up to MAX_BYTES from path and decode to text.

    Returns (text, scanned_bytes, truncated). Decodes UTF-8, falling back to
    latin-1 (which maps all 256 byte values and never raises) so binary or
    mis-encoded files degrade to scannable text instead of crashing.
    """
    with open(path, "rb") as fh:
        raw = fh.read(MAX_BYTES + 1)  # +1 sentinel byte to detect truncation
    truncated = len(raw) > MAX_BYTES
    if truncated:
        raw = raw[:MAX_BYTES]
    scanned_bytes = len(raw)

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
    return text, scanned_bytes, truncated


# ---- scanning --------------------------------------------------------------

def _aggregate(results):
    """Collapse a List[RecognizerResult] into per-entity-type count + max_score."""
    agg = {}  # entity_type -> [count, max_score]
    for r in results:
        etype = r.entity_type
        score = float(r.score)
        if etype in agg:
            agg[etype][0] += 1
            if score > agg[etype][1]:
                agg[etype][1] = score
        else:
            agg[etype] = [1, score]

    entities = [
        {"type": etype, "count": cnt, "max_score": round(max_score, 4)}
        for etype, (cnt, max_score) in agg.items()
    ]
    # Stable, useful ordering: highest count first, then type name.
    entities.sort(key=lambda e: (-e["count"], e["type"]))
    return entities


def scan_path(path):
    """Scan one file. Returns a result dict (never raises for expected errors)."""
    analyzer, ner_available = _get_analyzer()
    text, scanned_bytes, truncated = _read_text(path)

    # entities=None -> analyze for every recognizer/entity the engine supports.
    results = analyzer.analyze(text=text, entities=None, language=LANGUAGE)

    return {
        "path": path,
        "entities": _aggregate(results),
        "scanned_bytes": scanned_bytes,
        "truncated": truncated,
        "ner_available": ner_available,
    }


# ---- entrypoints -----------------------------------------------------------

def _emit(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def _run_single(path):
    try:
        _emit(scan_path(path))
    except Exception as exc:  # noqa: BLE001 — deliberately catch-all
        _emit({"error": "{}: {}".format(type(exc).__name__, exc), "path": path})
    # Always succeed so the worker logs and moves on.
    return 0


def _run_server():
    # Load the model once up front so the first line isn't slow and a load
    # failure is reported immediately rather than per-line.
    try:
        _get_analyzer()
    except Exception as exc:  # noqa: BLE001
        _emit({"error": "analyzer_init: {}: {}".format(type(exc).__name__, exc)})
        return 0
    for line in sys.stdin:
        path = line.strip()
        if not path:
            continue
        try:
            _emit(scan_path(path))
        except Exception as exc:  # noqa: BLE001
            _emit({"error": "{}: {}".format(type(exc).__name__, exc), "path": path})
    return 0


def main(argv):
    if len(argv) == 2 and argv[1] == "--server":
        return _run_server()
    if len(argv) != 2 or argv[1].startswith("-"):
        _emit({"error": "usage: presidio_scan.py <file> | --server"})
        return 0
    return _run_single(argv[1])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
