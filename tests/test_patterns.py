from ghosttype.patterns import scan_text


def test_detects_aws_access_key():
    text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "aws_access_key" in types
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert found.secret_value == "AKIAIOSFODNN7EXAMPLE"
    assert found.confidence == "high"


def test_detects_openai_token():
    text = "client = OpenAI(api_key='sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12')"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "openai_token" in types


def test_detects_github_pat_classic():
    text = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012"
    matches = scan_text(text)
    assert any(m.secret_type == "github_pat_classic" for m in matches)


def test_detects_anthropic_key():
    text = "key = 'sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'"
    matches = scan_text(text)
    assert any(m.secret_type == "anthropic_key" for m in matches)


def test_detects_jwt():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = scan_text(token)
    assert any(m.secret_type == "jwt" for m in matches)


def test_detects_connection_string():
    text = "db = connect('postgresql://user:password@localhost:5432/mydb')"
    matches = scan_text(text)
    assert any(m.secret_type == "connection_string" for m in matches)


def test_detects_pem_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    matches = scan_text(text)
    assert any(m.secret_type == "private_key_pem" for m in matches)


def test_heuristic_detects_api_key_assignment():
    text = "api_key = 'hunter2supersecretvalue'"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_api_key" and m.confidence == "medium" for m in matches)


def test_heuristic_detects_password_assignment():
    text = "password: mysecretpassword123"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_password" and m.confidence == "medium" for m in matches)


def test_context_window_centered_on_match():
    prefix = "x" * 50
    suffix = "y" * 50
    text = f"{prefix}AKIAIOSFODNN7EXAMPLE{suffix}"
    matches = scan_text(text, context_window=40)
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert "AKIAIOSFODNN7EXAMPLE" in found.context
    assert len(found.context) <= 40 + len("AKIAIOSFODNN7EXAMPLE")


def test_no_false_positive_on_clean_text():
    text = "Hello world, this is a normal conversation about coding."
    matches = scan_text(text)
    assert matches == []
