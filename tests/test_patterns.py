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


def test_detects_github_app_token():
    text = "token = ghs_16C7e42F292c6912E7710c838347Ae178B4a"
    matches = scan_text(text)
    assert any(m.secret_type == "github_app_token" for m in matches)


def test_detects_github_user_token():
    text = "GH_USER_TOKEN=ghu_16C7e42F292c6912E7710c838347Ae178B4a"
    matches = scan_text(text)
    assert any(m.secret_type == "github_user_token" for m in matches)


def test_detects_vault_token():
    text = "VAULT_TOKEN=hvs.CvmS4c0DPTvHv5eJgXWMJg9rABC123xyz"
    matches = scan_text(text)
    assert any(m.secret_type == "vault_token" for m in matches)


def test_detects_vault_batch_token():
    text = "hvb.1234567890abcdefghijklmn"
    matches = scan_text(text)
    assert any(m.secret_type == "vault_token" for m in matches)


def test_detects_linear_key():
    text = "LINEAR_API_KEY=lin_api_abcdefghijklmnopqrstuvwxyz1234567890ab12"
    matches = scan_text(text)
    assert any(m.secret_type == "linear_api_key" for m in matches)


def test_detects_databricks_token():
    text = "DATABRICKS_TOKEN=dapi1234567890abcdef1234567890abcdef"
    matches = scan_text(text)
    assert any(m.secret_type == "databricks_token" for m in matches)


def test_detects_npm_token():
    text = "NPM_TOKEN=npm_1234567890abcdefghijklmnopqrstuvwxyz"
    matches = scan_text(text)
    assert any(m.secret_type == "npm_token" for m in matches)


def test_detects_telegram_bot():
    text = "BOT_TOKEN=123456789:AABBccDDeeffGGhhIIjjKKllMMnnOOppQQrr"
    matches = scan_text(text)
    assert any(m.secret_type == "telegram_bot_token" for m in matches)


def test_heuristic_detects_azure_secret():
    text = "AZURE_CLIENT_SECRET='abcdefghijklmnopqrstuvwxyz123456='"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_azure_secret" for m in matches)
