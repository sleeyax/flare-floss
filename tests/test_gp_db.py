import pathlib

import floss.qs.db.gp


CD = pathlib.Path(__file__).parent


def test_load_db():
    path = CD.parent / "db" / "gp" / "gp.jsonl.gz"
    db = floss.qs.db.gp.StringGlobalPrevalenceDatabase.from_file(path)

    assert len(db) > 0  # 21 entries at time of writing


def test_query_db():
    path = CD.parent / "db" / "gp" / "gp.jsonl.gz"
    db = floss.qs.db.gp.StringGlobalPrevalenceDatabase.from_file(path)
    res = db.metadata_by_string[("!This program cannot be run in DOS mode.", "ascii")]

    assert len(res) == 1
    s = res[0]

    assert s is not None
    assert s.string == '!This program cannot be run in DOS mode.'
    assert s.encoding == 'ascii'
    assert s.global_count == 424466
    assert s.malware_count == None
    assert s.goodware_count == None
    assert s.location == None
