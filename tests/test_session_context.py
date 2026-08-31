import session_context


def _db(tmp_path):
    return str(tmp_path / "session_context.db")


def test_record_observed_url_with_id_shaped_segment(tmp_path):
    db = _db(tmp_path)
    assert session_context.record_observed_url("https://target.com/orders/4521", db_path=db) is True


def test_record_observed_url_without_id_shaped_segment(tmp_path):
    db = _db(tmp_path)
    assert session_context.record_observed_url("https://target.com/api/login", db_path=db) is False


def test_record_observed_url_duplicate_returns_false(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/4521", db_path=db)
    assert session_context.record_observed_url("https://target.com/orders/4521", db_path=db) is False


def test_record_observed_url_same_template_different_id_returns_true(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/1", db_path=db)
    assert session_context.record_observed_url("https://target.com/orders/2", db_path=db) is True


def test_record_observed_urls_counts_only_new_ones(tmp_path):
    db = _db(tmp_path)
    urls = [
        "https://target.com/orders/1",
        "https://target.com/orders/1",  # duplicate
        "https://target.com/orders/2",
        "https://target.com/api/login",  # no id -- doesn't count
    ]
    assert session_context.record_observed_urls(urls, db_path=db) == 2


def test_get_ids_for_template_returns_observed_values(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/1", db_path=db)
    session_context.record_observed_url("https://target.com/orders/2", db_path=db)
    ids = session_context.get_ids_for_template("https://target.com/orders/{id}", db_path=db)
    assert set(ids) == {"1", "2"}


def test_get_ids_for_template_respects_limit(tmp_path):
    db = _db(tmp_path)
    for i in range(10):
        session_context.record_observed_url(f"https://target.com/orders/{i}", db_path=db)
    ids = session_context.get_ids_for_template("https://target.com/orders/{id}", db_path=db, limit=3)
    assert len(ids) == 3


def test_get_ids_for_template_empty_when_nothing_observed(tmp_path):
    db = _db(tmp_path)
    assert session_context.get_ids_for_template("https://target.com/orders/{id}", db_path=db) == []


def test_get_ids_for_template_does_not_cross_templates(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/1", db_path=db)
    session_context.record_observed_url("https://target.com/users/9", db_path=db)
    ids = session_context.get_ids_for_template("https://target.com/orders/{id}", db_path=db)
    assert ids == ["1"]


def test_suggest_object_ids_accepts_placeholder_shape(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/api/orders/4521", db_path=db)
    ids = session_context.suggest_object_ids("https://target.com/api/orders/{id}", db_path=db)
    assert ids == ["4521"]


def test_suggest_object_ids_accepts_concrete_url_shape(tmp_path):
    # A caller passing an already-concrete url (with a real id already in
    # it, not the {id}-placeholder shape) must still resolve to the same
    # template and get a useful answer.
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/api/orders/4521", db_path=db)
    ids = session_context.suggest_object_ids("https://target.com/api/orders/9999", db_path=db)
    assert ids == ["4521"]


def test_suggest_object_ids_empty_when_never_observed(tmp_path):
    db = _db(tmp_path)
    assert session_context.suggest_object_ids("https://target.com/api/orders/{id}", db_path=db) == []


def test_clear_removes_all_observations(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/1", db_path=db)
    session_context.clear(db_path=db)
    assert session_context.get_ids_for_template("https://target.com/orders/{id}", db_path=db) == []


def test_record_observed_url_persists_source_url(tmp_path):
    db = _db(tmp_path)
    session_context.record_observed_url("https://target.com/orders/4521?ref=abc", db_path=db)
    conn = session_context._get_conn(db)
    row = conn.execute("SELECT source_url FROM observed_ids").fetchone()
    conn.close()
    assert row["source_url"] == "https://target.com/orders/4521?ref=abc"
