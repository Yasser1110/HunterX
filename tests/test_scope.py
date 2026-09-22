from hunterx.config import Target
from hunterx.scope import Scope, ScopeError, normalize_host


def build(*, includes=("*.example.com",), excludes=(), paths=(), ips=()):
    return Scope.build(allowed=includes, excluded=excludes,
                       excluded_paths=paths, excluded_ips=ips,
                       allow_apex=True, allow_subdomains=True)


def test_wildcard_allows_apex_and_deep_subdomains():
    s = build()
    assert s.is_allowed_host("example.com")
    assert s.is_allowed_host("www.example.com")
    assert s.is_allowed_host("api.example.com")
    assert s.is_allowed_host("a.b.example.com")
    assert s.is_allowed_host("deep.a.b.c.example.com")


def test_wildcard_rejects_tricky_suffixes():
    s = build()
    assert not s.is_allowed_host("example.com.evil.com")
    assert not s.is_allowed_host("evil-example.com")
    assert not s.is_allowed_host("notexample.com")
    assert not s.is_allowed_host("example.com.evil")
    assert not s.is_allowed_host("xexample.com")
    assert not s.is_allowed_host("wwwexample.com")


def test_exclusions_always_win():
    s = build(excludes=("admin.example.com", "staging.example.com"))
    assert not s.is_allowed_host("admin.example.com")
    assert not s.is_allowed_host("staging.example.com")
    assert s.is_allowed_host("dev.example.com")


def test_exact_domain_scope():
    s = build(includes=("example.com",))
    assert s.is_allowed_host("example.com")
    assert not s.is_allowed_host("www.example.com")
    assert not s.is_allowed_host("api.example.com")


def test_allow_apex_off():
    s = Scope.build(allowed=("*.example.com",), allow_apex=False)
    assert not s.is_allowed_host("example.com")
    assert s.is_allowed_host("www.example.com")


def test_url_validation_and_path_exclusions():
    s = build(paths=("/logout", "/delete"))
    assert s.is_allowed_url("https://api.example.com/users")
    assert s.is_allowed_url("http://example.com/")
    assert not s.is_allowed_url("https://api.example.com/logout")
    assert not s.is_allowed_url("https://api.example.com/delete/account")
    assert not s.is_allowed_url("ftp://example.com/")
    assert not s.is_allowed_url("https://example.com.evil.com/x")
    assert not s.is_allowed_url("https://evil-example.com/x")
    assert not s.is_allowed_url("")


def test_ip_range_exclusion():
    s = build(ips=("192.0.2.0/24",))
    assert s.is_allowed_ip("203.0.113.10")
    assert not s.is_allowed_ip("192.0.2.77")
    assert not s.is_allowed_ip("not-an-ip")


def test_from_config_derives_target():
    cfg = {"include": [], "exclude": ["admin.example.com"],
           "excluded_paths": [], "excluded_ips": [], "allow_apex": True}
    target = Target(domain="example.com", wildcard="*.example.com")
    s = Scope.from_config(cfg, target)
    assert s.is_allowed_host("example.com")
    assert s.is_allowed_host("a.b.example.com")
    assert not s.is_allowed_host("admin.example.com")
    assert not s.is_allowed_host("example.com.evil.com")


def test_empty_scope_denies_everything():
    s = build(includes=())
    assert not s.is_allowed_host("anything.com")
    assert not s.is_allowed_url("https://anything.com/")


def test_invalid_ip_range_raises():
    try:
        build(ips=("not-a-cidr",))
        assert False, "expected ScopeError"
    except ScopeError:
        pass


def test_normalize_host():
    assert normalize_host("  API.Example.COM. ") == "api.example.com"
    assert normalize_host("bad host") == ""
    assert normalize_host("") == ""