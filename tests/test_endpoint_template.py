import endpoint_template as et


def test_endpoint_template_replaces_numeric_id():
    assert et.endpoint_template("https://target.com/orders/4521") == "https://target.com/orders/{id}"


def test_endpoint_template_replaces_uuid():
    url = "https://target.com/users/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert et.endpoint_template(url) == "https://target.com/users/{id}"


def test_endpoint_template_replaces_hashid_like_segment():
    url = "https://target.com/share/aB3xY9zQ1m"
    assert et.endpoint_template(url) == "https://target.com/share/{id}"


def test_endpoint_template_leaves_ordinary_words_untouched():
    url = "https://target.com/api/login"
    assert et.endpoint_template(url) == url


def test_endpoint_template_leaves_short_alpha_only_segment_untouched():
    # "login" and similar words are exactly what _HASHID_RE's digit+letter
    # requirement must reject -- an all-letters segment is never id-like.
    assert et._is_id_like("dashboard") is False


def test_endpoint_template_drops_query_string():
    url = "https://target.com/orders/4521?page=2&sort=desc"
    assert et.endpoint_template(url) == "https://target.com/orders/{id}"


def test_endpoint_template_handles_multiple_id_segments():
    url = "https://target.com/v2/users/42/orders/1001"
    assert et.endpoint_template(url) == "https://target.com/v2/users/{id}/orders/{id}"


def test_endpoint_template_two_different_ids_same_template():
    t1 = et.endpoint_template("https://target.com/orders/1")
    t2 = et.endpoint_template("https://target.com/orders/999999")
    assert t1 == t2


def test_group_by_template_buckets_correctly():
    urls = [
        "https://target.com/orders/1",
        "https://target.com/orders/2",
        "https://target.com/users/9",
    ]
    groups = et.group_by_template(urls)
    assert len(groups) == 2
    assert groups["https://target.com/orders/{id}"] == [
        "https://target.com/orders/1", "https://target.com/orders/2",
    ]
    assert groups["https://target.com/users/{id}"] == ["https://target.com/users/9"]


def test_sample_representatives_caps_per_template():
    urls = [f"https://target.com/orders/{i}" for i in range(10)]
    sampled = et.sample_representatives(urls, max_per_template=3)
    assert sampled == urls[:3]


def test_sample_representatives_does_not_cap_across_different_templates():
    urls = (
        [f"https://target.com/orders/{i}" for i in range(3)]
        + [f"https://target.com/users/{i}" for i in range(3)]
    )
    sampled = et.sample_representatives(urls, max_per_template=3)
    assert sampled == urls  # exactly 3 of each, nothing dropped


def test_sample_representatives_preserves_original_order_of_kept_urls():
    urls = [
        "https://target.com/orders/1",
        "https://target.com/users/9",
        "https://target.com/orders/2",
    ]
    sampled = et.sample_representatives(urls, max_per_template=5)
    assert sampled == urls


def test_sample_representatives_default_cap_is_five():
    urls = [f"https://target.com/orders/{i}" for i in range(10)]
    sampled = et.sample_representatives(urls)
    assert len(sampled) == 5


def test_extract_last_id_picks_the_final_id_segment():
    url = "https://target.com/v2/users/42/orders/1001"
    assert et.extract_last_id(url) == "1001"


def test_extract_last_id_single_id_segment():
    assert et.extract_last_id("https://target.com/orders/4521") == "4521"


def test_extract_last_id_returns_none_when_no_id_like_segment():
    assert et.extract_last_id("https://target.com/api/login") is None


def test_extract_last_id_works_with_uuid():
    url = "https://target.com/users/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert et.extract_last_id(url) == "f47ac10b-58cc-4372-a567-0e02b2c3d479"
