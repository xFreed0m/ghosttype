from ghosttype.patterns import scan_text


def test_detects_aws_access_key():
    text = "export AWS_ACCESS_KEY_ID=AKIATESTFAKEKEY12345"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "aws_access_key" in types
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert found.secret_value == "AKIATESTFAKEKEY12345"
    assert found.confidence == "high"


def test_detects_openai_token():
    text = "client = OpenAI(api_key='sk-abcdefghijklmnopqrstuvwxyz1234567890abcdefghijk12')"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "openai_token" in types


def test_detects_github_pat_classic():
    text = "GITHUB_TOKEN=ghp_RpQs7vXzBnCkDmWjEtFuGhYi12345678901234"
    matches = scan_text(text)
    assert any(m.secret_type == "github_pat_classic" for m in matches)


def test_detects_anthropic_key():
    text = "key = 'sk-ant-api03-RpQs7vXzBnCkDmWjEtFuGhYiOpLmKnJqHrGs-TUVwxyz'"
    matches = scan_text(text)
    assert any(m.secret_type == "anthropic_key" for m in matches)


def test_detects_jwt():
    token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    matches = scan_text(token)
    assert any(m.secret_type == "jwt" for m in matches)


def test_detects_connection_string():
    text = "db = connect('postgresql://admin:Tr0ub4dor@prod-db.corp.example.com:5432/appdb')"
    matches = scan_text(text)
    assert any(m.secret_type == "connection_string" for m in matches)


def test_detects_pem_private_key():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    matches = scan_text(text)
    assert any(m.secret_type == "private_key_pem" for m in matches)


def test_heuristic_detects_api_key_assignment():
    text = "api_key = 'xK9mR3pL8nQ2vZ5sY1wJ4eU7tH'"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_api_key" and m.confidence == "medium" for m in matches)


def test_heuristic_detects_password_assignment():
    text = "password: Tr0ub4dor&3xamplePa55!"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_password" and m.confidence == "medium" for m in matches)


def test_context_window_centered_on_match():
    aws_key = "AKIATESTFAKEKEY12345"
    prefix = "x" * 50
    suffix = "y" * 50
    text = f"{prefix}{aws_key}{suffix}"
    matches = scan_text(text, context_window=40)
    found = next(m for m in matches if m.secret_type == "aws_access_key")
    assert aws_key in found.context
    assert len(found.context) <= 40 + len(aws_key)


def test_no_false_positive_on_clean_text():
    text = "Hello world, this is a normal conversation about coding."
    matches = scan_text(text)
    assert matches == []


def test_known_example_aws_key_excluded():
    """AKIAIOSFODNN7EXAMPLE is the AWS docs canonical key and must be suppressed."""
    text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    assert not any(m.secret_type == "aws_access_key" for m in matches)


def test_detects_github_app_token():
    text = "token = ghs_RpQs7vXzBnCkDmWjEtFuGhYiOpLmKnJqHr12"
    matches = scan_text(text)
    assert any(m.secret_type == "github_app_token" for m in matches)


def test_detects_github_user_token():
    text = "GH_USER_TOKEN=ghu_16C7e42F292c6912E7710c838347Ae178B4a"
    matches = scan_text(text)
    assert any(m.secret_type == "github_user_token" for m in matches)


def test_detects_vault_token():
    text = "VAULT_TOKEN=hvs.RpQs7vXzBnCkDmWjEtFuGhYiOpLmKnJqHrGs12"
    matches = scan_text(text)
    assert any(m.secret_type == "vault_token" for m in matches)


def test_detects_vault_batch_token():
    text = "hvb.1234567890abcdefghijklmn"
    matches = scan_text(text)
    assert any(m.secret_type == "vault_token" for m in matches)


def test_detects_linear_key():
    text = "LINEAR_API_KEY=lin_api_RpQs7_vXzBnCk_DmWjEt_FuGhYiOpLm_KnJqHrGs12"
    matches = scan_text(text)
    assert any(m.secret_type == "linear_api_key" for m in matches)


def test_detects_databricks_token():
    text = "DATABRICKS_TOKEN=dapiRpQs7vXzBnCkDmWjEtFuGhYiOpLm1234"
    matches = scan_text(text)
    assert any(m.secret_type == "databricks_token" for m in matches)


def test_detects_npm_token():
    text = "NPM_TOKEN=npm_RpQs7vXzBnCkDmWjEtFuGhYiOpLmKnJqHrGs12"
    matches = scan_text(text)
    assert any(m.secret_type == "npm_token" for m in matches)


def test_detects_telegram_bot():
    text = "BOT_TOKEN=987654321:ZZYYxxWWvvUUttSSrrQQppOOnnMMllKKjj12"
    matches = scan_text(text)
    assert any(m.secret_type == "telegram_bot_token" for m in matches)


def test_heuristic_detects_azure_secret():
    text = "AZURE_CLIENT_SECRET='abcdefghijklmnopqrstuvwxyz123456='"
    matches = scan_text(text)
    assert any(m.secret_type == "heuristic_azure_secret" for m in matches)


def test_detects_huggingface_token():
    text = "HF_TOKEN=hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"
    matches = scan_text(text)
    assert any(m.secret_type == "huggingface_token" for m in matches)


def test_detects_digitalocean_token():
    text = "DO_TOKEN=dop_v1_" + "a" * 64
    matches = scan_text(text)
    assert any(m.secret_type == "digitalocean_token" for m in matches)


def test_detects_github_oauth_token():
    text = "GH_OAUTH=gho_16C7e42F292c6912E7710c838347Ae178B4a"
    matches = scan_text(text)
    assert any(m.secret_type == "github_oauth_token" for m in matches)


def test_detects_github_refresh_token():
    text = "GH_REFRESH=ghr_" + "A" * 76
    matches = scan_text(text)
    assert any(m.secret_type == "github_refresh_token" for m in matches)


def test_detects_gcp_api_key():
    text = "MAPS_KEY=AIzaSyXp9mK3rT8nQ2vL5wJ4eB7uF1cG6hD0sYZ"  # 6+33=39 chars
    matches = scan_text(text)
    assert any(m.secret_type == "gcp_api_key" for m in matches)


def test_detects_aws_sts_token():
    text = "AWS_ACCESS_KEY_ID=ASIAIOSFODNN7TESTKEY"
    matches = scan_text(text)
    assert any(m.secret_type == "aws_sts_token" for m in matches)


def test_aws_sts_example_value_excluded():
    """ASIAIOSFODNN7EXAMPLE is the AWS docs STS example and must be suppressed."""
    text = "AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE"
    matches = scan_text(text)
    assert not any(m.secret_type == "aws_sts_token" for m in matches)


def test_detects_dockerhub_token():
    text = "DOCKER_TOKEN=dckr_pat_AbCdEfGhIjKlMnOpQrStUvWx"
    matches = scan_text(text)
    assert any(m.secret_type == "dockerhub_token" for m in matches)


def test_detects_pulumi_token():
    text = "PULUMI_ACCESS_TOKEN=pul-" + "a" * 40
    matches = scan_text(text)
    assert any(m.secret_type == "pulumi_token" for m in matches)


def test_detects_doppler_token():
    text = "DOPPLER_TOKEN=dp.st." + "a" * 43
    matches = scan_text(text)
    assert any(m.secret_type == "doppler_token" for m in matches)


def test_test_connection_string_excluded():
    """Standard localhost test connection strings should not be reported."""
    text = "postgresql://user:password@localhost:5432/mydb"
    matches = scan_text(text)
    assert not any(m.secret_type == "connection_string" for m in matches)


def test_real_connection_string_still_detected():
    """Production-looking connection strings should still be detected."""
    text = "postgresql://admin:Tr0ub4dor@prod-db.company.example:5432/appdb"
    matches = scan_text(text)
    assert any(m.secret_type == "connection_string" for m in matches)


def test_anthropic_key_not_classified_as_openai_token():
    """sk-ant- prefixed keys must only match anthropic_key, not openai_token."""
    text = "API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890abc"
    matches = scan_text(text)
    types = [m.secret_type for m in matches]
    assert "anthropic_key" in types
    assert "openai_token" not in types


def test_openai_token_still_detected_after_lookahead():
    """Negative lookahead for ant- must not break regular sk- OpenAI token detection."""
    text = "OPENAI_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJ12"
    matches = scan_text(text)
    assert any(m.secret_type == "openai_token" for m in matches)


def test_pem_not_matched_inside_quote():
    """PEM header inside a string literal should not be reported."""
    text = 'text = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAK..."'
    matches = scan_text(text)
    assert not any(m.secret_type == "private_key_pem" for m in matches)


def test_pem_matched_standalone():
    """PEM header appearing on its own line should be detected."""
    text = "Here is the key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAK..."
    matches = scan_text(text)
    assert any(m.secret_type == "private_key_pem" for m in matches)


def test_heuristic_detects_supabase_key():
    """Supabase service role key should be detected. JWTs are valid Supabase keys."""
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.M2pn5X0extZeP8DjqYDZJw"
    text = f"SUPABASE_SERVICE_ROLE_KEY={jwt}"
    matches = scan_text(text)
    # Supabase keys are JWTs, so either detection is valid
    assert any(m.secret_type in ("heuristic_supabase_key", "jwt") for m in matches)
