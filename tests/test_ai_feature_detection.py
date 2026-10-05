import ai_feature_detection


def test_detects_chat_endpoint_path():
    hits = ai_feature_detection.detect_ai_features('"/api/v1/chat/completions"', source="endpoints")
    assert len(hits) == 1
    assert hits[0]["category"] == "endpoint_path"
    assert hits[0]["source"] == "endpoints"


def test_detects_assistant_named_endpoint():
    hits = ai_feature_detection.detect_ai_features('fetch("/api/assistant/ask")')
    assert any(h["category"] == "endpoint_path" for h in hits)


def test_detects_document_analysis_feature_mention():
    hits = ai_feature_detection.detect_ai_features("Upload your resume for AI-powered document analysis")
    assert any(h["category"] == "ai_feature_mention" for h in hits)


def test_detects_known_llm_vendor_reference():
    hits = ai_feature_detection.detect_ai_features("const client = new OpenAI({apiKey: ...})")
    assert any(h["category"] == "llm_vendor_reference" for h in hits)


def test_detects_upload_to_llm_flow_phrasing():
    hits = ai_feature_detection.detect_ai_features("Upload a file and our AI will summarize it for you")
    assert any(h["category"] == "upload_to_llm_flow" for h in hits)


def test_no_signal_in_ordinary_text_returns_empty():
    hits = ai_feature_detection.detect_ai_features("Login with your email and password to view your orders.")
    assert hits == []


def test_dedupes_identical_matches_from_the_same_text():
    hits = ai_feature_detection.detect_ai_features('"/api/chat" "/api/chat" "/api/chat"')
    endpoint_hits = [h for h in hits if h["category"] == "endpoint_path"]
    assert len(endpoint_hits) == 1


def test_does_not_false_positive_on_unrelated_word_containing_ai_substring():
    """"ai" as a bare substring inside an unrelated word (e.g. "contains",
    "maintain", "domain") must not trigger -- only whole-word / clearly
    AI-feature-shaped patterns."""
    hits = ai_feature_detection.detect_ai_features(
        "This domain contains maintenance information about your container.",
    )
    assert hits == []


def test_summarize_signals_groups_by_category():
    hits = ai_feature_detection.detect_ai_features(
        '"/api/chat/completions" uses OpenAI for AI-powered analysis',
    )
    summary = ai_feature_detection.summarize_signals(hits)
    assert summary["has_ai_feature"] is True
    assert set(summary["categories"]) >= {"endpoint_path", "llm_vendor_reference"}


def test_summarize_signals_empty_when_no_hits():
    summary = ai_feature_detection.summarize_signals([])
    assert summary["has_ai_feature"] is False
    assert summary["categories"] == []
