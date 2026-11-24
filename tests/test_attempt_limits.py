"""The hunt's `attempt_limit` check (frame/sil/attempt_limits.py): whether one caller can repeat a
guess of a stored secret at will. Limiters are `[[rate_limit]]` pack data; each case pairs a
covered credential check with the nearest uncovered one."""

import json

from frame.sil.scanner import FrameScanner


def _ctx(tmp_path, files):
    for name, text in files.items():
        (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / name).write_text(text)
    sc = FrameScanner()
    sc.collect_programs = True
    results = sc.scan_directory(str(tmp_path), None, project_root=str(tmp_path))
    findings = [v for r in results for v in r.vulnerabilities]
    from frame.sil.hunt_tools import HuntContext
    from frame.sil.llm_hunt import build_index
    index = build_index(sc._hunt_programs, findings, str(tmp_path))
    return HuntContext(index, sc._hunt_programs, str(tmp_path), "", findings)


def _verdict(ctx, name, file=None):
    return json.loads(ctx.check(name, 0, "attempt_limit", file=file))


EXPRESS = """\
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const app = express();
const loginLimiter = rateLimit({ windowMs: 60000, max: 5 });

async function login(req, res) {
  const ok = await bcrypt.compare(req.body.password, req.user.hash);
  res.send(ok);
}

async function resetCode(req, res) {
  const ok = await bcrypt.compare(req.body.code, req.user.code);
  res.send(ok);
}

async function profile(req, res) {
  res.send(req.user.name);
}

app.post('/login', loginLimiter, login);
app.post('/reset', rateLimit({ max: 3 }), resetCode);
app.post('/verify', resetCodeAgain);
app.get('/me', profile);

async function resetCodeAgain(req, res) {
  const ok = await bcrypt.compare(req.body.code, req.user.code);
  res.send(ok);
}
"""


def test_limiter_middleware_in_the_route_covers_it_and_its_absence_is_refuted(tmp_path):
    ctx = _ctx(tmp_path, {"app.js": EXPRESS})
    login = _verdict(ctx, "login")
    assert login["verdict"] == "proved", login
    assert "loginLimiter" in login["reason"]
    assert _verdict(ctx, "resetCode")["verdict"] == "proved"     # inline `rateLimit(...)`
    bare = _verdict(ctx, "resetCodeAgain")
    assert bare["verdict"] == "refuted", bare
    assert [w["event"] for w in bare["witness"]][0] == "compares a guess with a stored secret"
    # no credential check: nothing to limit, so nothing decided
    assert _verdict(ctx, "profile")["verdict"] == "unknown"


def test_a_limiter_for_the_whole_application_leaves_an_unlisted_route_unknown(tmp_path):
    ctx = _ctx(tmp_path, {"app.js": EXPRESS + "\napp.use(rateLimit({ max: 100 }));\n"})
    r = _verdict(ctx, "resetCodeAgain")
    assert r["verdict"] == "unknown", r
    assert "application" in r["reason"]
    assert _verdict(ctx, "login")["verdict"] == "proved"


ROUTES = """\
const express = require('express');
const rateLimit = require('express-rate-limit');
const auth = require('./auth');
const router = express.Router();
const limiter = rateLimit({ max: 5 });
router.post('/login', limiter, auth.login);
router.post('/otp', auth.otp);
module.exports = router;
"""

AUTH = """\
const bcrypt = require('bcrypt');
async function login(req, res) {
  res.send(await bcrypt.compare(req.body.password, req.user.hash));
}
async function otp(req, res) {
  res.send(await bcrypt.compare(req.body.code, req.user.otp));
}
module.exports = { login, otp };
"""


def test_route_middleware_in_another_file_covers_the_handler_it_registers(tmp_path):
    ctx = _ctx(tmp_path, {"routes.js": ROUTES, "auth.js": AUTH})
    assert _verdict(ctx, "login", "auth.js")["verdict"] == "proved"
    assert _verdict(ctx, "otp", "auth.js")["verdict"] == "refuted"


FLEXIBLE = """\
const { RateLimiterMemory } = require('rate-limiter-flexible');
const bcrypt = require('bcrypt');
const limiter = new RateLimiterMemory({ points: 5, duration: 60 });

async function checkPassword(req, res) {
  await limiter.consume(req.ip);
  res.send(await bcrypt.compare(req.body.password, req.user.hash));
}

async function checkPin(req, res) {
  res.send(await bcrypt.compare(req.body.pin, req.user.pin));
}
module.exports = { checkPassword, checkPin };
"""


def test_a_call_that_spends_an_attempt_covers_the_function(tmp_path):
    ctx = _ctx(tmp_path, {"auth.js": FLEXIBLE})
    r = _verdict(ctx, "checkPassword")
    assert r["verdict"] == "proved", r
    assert "consume" in r["reason"]
    assert _verdict(ctx, "checkPin")["verdict"] == "refuted"


NEST = """\
import { Controller, Post, UseGuards, Body } from '@nestjs/common';
import { ThrottlerGuard, SkipThrottle } from '@nestjs/throttler';
import * as bcrypt from 'bcrypt';

@Controller('auth')
@UseGuards(ThrottlerGuard)
export class AuthController {
  @Post('login')
  async login(@Body() body: any) { return bcrypt.compare(body.password, body.hash); }

  @SkipThrottle()
  @Post('pin')
  async pin(@Body() body: any) { return bcrypt.compare(body.pin, body.hash); }
}

@Controller('open')
export class OpenController {
  @Post('code')
  async code(@Body() body: any) { return bcrypt.compare(body.code, body.hash); }
}
"""

NEST_MODULE = """\
import { Module } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';

@Module({
  imports: [ThrottlerModule.forRoot([{ ttl: 60000, limit: 10 }])],
  providers: [{ provide: APP_GUARD, useClass: ThrottlerGuard }],
})
export class AppModule {}
"""


def test_a_guard_on_the_class_covers_its_handlers_unless_one_is_exempt(tmp_path):
    ctx = _ctx(tmp_path, {"auth.controller.ts": NEST})
    assert _verdict(ctx, "AuthController.login")["verdict"] == "proved"
    assert _verdict(ctx, "AuthController.pin")["verdict"] == "refuted"
    assert _verdict(ctx, "OpenController.code")["verdict"] == "refuted"


def test_a_global_guard_in_a_module_leaves_an_unguarded_controller_unknown(tmp_path):
    ctx = _ctx(tmp_path, {"auth.controller.ts": NEST, "app.module.ts": NEST_MODULE})
    assert _verdict(ctx, "OpenController.code")["verdict"] == "unknown"
    # an exempt handler is not covered by the global guard either
    assert _verdict(ctx, "AuthController.pin")["verdict"] == "refuted"


DJANGO_VIEWS = """\
from django.contrib.auth import authenticate
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit


@ratelimit(key="ip", rate="5/m")
def login_view(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    return HttpResponse("ok" if user else "no")


def api_login(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    return HttpResponse("ok" if user else "no")
"""

DJANGO_SETTINGS = """\
MIDDLEWARE = ["django.middleware.common.CommonMiddleware", "axes.middleware.AxesMiddleware"]
"""


def test_a_python_decorator_covers_the_view_and_settings_can_cover_every_view(tmp_path):
    ctx = _ctx(tmp_path, {"app/views.py": DJANGO_VIEWS})
    assert _verdict(ctx, "login_view")["verdict"] == "proved"
    assert _verdict(ctx, "api_login")["verdict"] == "refuted"
    ctx = _ctx(tmp_path, {"app/settings.py": DJANGO_SETTINGS})
    r = _verdict(ctx, "api_login")
    assert r["verdict"] == "unknown", r
    assert "AxesMiddleware" in r["reason"]


FLASK = """\
from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

app = Flask(__name__)
limiter = Limiter(get_remote_address, app=app)


@app.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login():
    return str(check_password_hash(request.form["hash"], request.form["password"]))


@app.route("/pin", methods=["POST"])
def pin():
    return str(check_password_hash(request.form["hash"], request.form["pin"]))


@app.route("/code", methods=["POST"])
@limiter.exempt
def code():
    return str(check_password_hash(request.form["hash"], request.form["code"]))
"""


def test_flask_limiter_decorates_routes_and_its_defaults_may_cover_the_rest(tmp_path):
    ctx = _ctx(tmp_path, {"app.py": FLASK})
    r = _verdict(ctx, "login")
    assert r["verdict"] == "proved", r
    assert _verdict(ctx, "pin")["verdict"] == "unknown"     # a Limiter's default limits
    assert _verdict(ctx, "code")["verdict"] == "refuted"    # exempt from them


SERVICE = """\
const express = require('express');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const app = express();

async function verifyPassword(user, guess) {
  return bcrypt.compare(guess, user.hash);
}

async function login(req, res) {
  res.send(await verifyPassword(req.user, req.body.password));
}

app.post('/login', rateLimit({ max: 5 }), login);
"""


def test_a_helper_every_caller_of_which_is_limited_is_covered(tmp_path):
    ctx = _ctx(tmp_path, {"app.js": SERVICE})
    r = _verdict(ctx, "verifyPassword")
    assert r["verdict"] == "proved", r
    open_route = SERVICE + "\nasync function relogin(req, res) {\n  res.send(await verifyPassword(req.user, req.body.p));\n}\napp.post('/relogin', relogin);\n"
    ctx = _ctx(tmp_path, {"app.js": open_route})
    assert _verdict(ctx, "verifyPassword")["verdict"] == "unknown"


CSHARP = """\
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;

[ApiController]
[EnableRateLimiting("fixed")]
public class AuthController : ControllerBase {
  [HttpPost("login")]
  public bool Login(byte[] guess, byte[] secret) => CryptographicOperations.FixedTimeEquals(guess, secret);

  [DisableRateLimiting]
  [HttpPost("pin")]
  public bool Pin(byte[] guess, byte[] secret) => CryptographicOperations.FixedTimeEquals(guess, secret);
}
"""


def test_aspnet_rate_limiting_attributes(tmp_path):
    ctx = _ctx(tmp_path, {"AuthController.cs": CSHARP})
    assert _verdict(ctx, "AuthController.Login")["verdict"] == "proved"
    assert _verdict(ctx, "AuthController.Pin")["verdict"] == "refuted"


def test_attempt_limit_corroborates_bruteforce():
    from frame.sil.hunt_classes import CLASSES
    assert "attempt_limit" in CLASSES["bruteforce"].corroborating


def test_rate_limit_entries_are_validated():
    import pytest
    from frame.sil.packs.schema import PackError, parse_pack
    head = {"pack": {"name": "x", "language": "python"}}
    with pytest.raises(PackError, match="kind must be"):
        parse_pack({**head, "rate_limit": [{"call": ["a.b"], "kind": "maybe"}]})
    with pytest.raises(PackError, match="needs `call` or `name`"):
        parse_pack({**head, "rate_limit": [{"kind": "decorator"}]})
    pack = parse_pack({**head, "rate_limit": [{"name": ["UseLimiter"], "kind": "global"}]})
    assert pack.rate_limits == [{"call": [], "name": ["UseLimiter"], "kind": "global"}]


COUNTER = """\
from django.contrib.auth.hashers import check_password
from django.db import models
from django.http import HttpResponse


class Account(models.Model):
    pin = models.CharField(max_length=128)
    failures = models.IntegerField(default=0)


def pin_login(request):
    acct = Account.objects.get(name=request.POST["u"])
    if not check_password(request.POST["pin"], acct.pin):
        acct.failures += 1
        acct.save()
        return HttpResponse("no")
    return HttpResponse("ok")


def pin_check(request):
    acct = Account.objects.get(name=request.POST["u"])
    return HttpResponse("ok" if check_password(request.POST["pin"], acct.pin) else "no")
"""


def test_a_write_of_stored_data_may_be_an_attempt_counter(tmp_path):
    ctx = _ctx(tmp_path, {"app/views.py": COUNTER})
    r = _verdict(ctx, "pin_login")
    assert r["verdict"] == "unknown", r                     # counted, but nothing here refuses on it
    assert "counts in failures" in r["reason"]
    assert _verdict(ctx, "pin_check")["verdict"] == "refuted"


THROTTLE = """\
using System;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography;
public interface ILoginAttemptThrottle { Task<bool> VerifyAsync(Func<bool> verify, CancellationToken ct); }
public class LoginAttemptThrottle : ILoginAttemptThrottle {
  private int failures;
  public async Task<bool> VerifyAsync(Func<bool> verify, CancellationToken ct) { var ok = verify(); if (!ok) failures++; return ok; }
}
public class LoginProvider {
  private readonly ILoginAttemptThrottle loginThrottle;
  public LoginProvider(ILoginAttemptThrottle t) { loginThrottle = t; }
  public async Task<bool> Login(byte[] g, byte[] s, CancellationToken ct) {
    return await loginThrottle.VerifyAsync(() => CryptographicOperations.FixedTimeEquals(g, s), ct);
  }
  public bool Plain(byte[] g, byte[] s) => CryptographicOperations.FixedTimeEquals(g, s);
}
"""


def test_a_check_handed_to_a_project_function_may_be_throttled_there(tmp_path):
    # Duplicati's fix: the password check runs inside a closure the project's own throttle calls
    ctx = _ctx(tmp_path, {"Login.cs": THROTTLE})
    r = _verdict(ctx, "LoginProvider.Login")
    assert r["verdict"] == "unknown", r
    assert "VerifyAsync" in r["reason"]
    assert _verdict(ctx, "LoginProvider.Plain")["verdict"] == "refuted"


CACHE_LIMIT = """\
from django.contrib.auth import authenticate
from django.core.cache import cache
from django.http import HttpResponse


def too_many(request):
    key = "rl:" + request.META["REMOTE_ADDR"]
    n = cache.get(key, 0)
    cache.set(key, n + 1, 300)
    return n >= 5


def login(request):
    if too_many(request):
        return HttpResponse("slow down", status=429)
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    return HttpResponse("ok" if user else "no")


def token_login(request):
    user = authenticate(request, username=request.POST["u"], password=request.POST["p"])
    return HttpResponse("ok" if user else "no")
"""


def test_a_counter_kept_in_a_cache_leaves_it_to_the_agent(tmp_path):
    ctx = _ctx(tmp_path, {"app/views.py": CACHE_LIMIT})
    r = _verdict(ctx, "login")
    assert r["verdict"] == "unknown", r
    assert "across requests" in r["reason"]
    assert _verdict(ctx, "token_login")["verdict"] == "refuted"


INHERITED = """\
from django.contrib.auth.views import LoginView


class SiteLogin(LoginView):
    template_name = "login.html"

    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)
"""


def test_a_check_known_only_from_a_library_base_is_not_refuted(tmp_path):
    # the library's view calls back into the project's form, which may count attempts
    ctx = _ctx(tmp_path, {"app/views.py": INHERITED})
    r = _verdict(ctx, "SiteLogin.dispatch")
    assert r["verdict"] == "unknown", r
    assert "library class" in r["reason"]


IDENTITY = """\
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

public class AppUser : IdentityUser { }

public class AccountController : Controller {
  private readonly SignInManager<AppUser> _signInManager;
  private readonly UserManager<AppUser> _users;
  public AccountController(SignInManager<AppUser> signInManager, UserManager<AppUser> users) {
    _signInManager = signInManager;
    _users = users;
  }

  [HttpPost]
  public async Task<IActionResult> Login(string email, string password, bool remember) {
    var result = await _signInManager.PasswordSignInAsync(email, password, remember, lockoutOnFailure: true);
    return Ok(result.Succeeded);
  }

  [HttpPost]
  public async Task<IActionResult> LoginNoLock(string email, string password, bool remember) {
    var result = await _signInManager.PasswordSignInAsync(email, password, remember, false);
    return Ok(result.Succeeded);
  }

  [HttpPost]
  public async Task<IActionResult> LoginFlag(string email, string password, bool remember, bool lockIt) {
    var result = await _signInManager.PasswordSignInAsync(email, password, remember, lockoutOnFailure: lockIt);
    return Ok(result.Succeeded);
  }

  [HttpPost]
  public async Task<IActionResult> Check(AppUser user, string password) {
    var result = await _signInManager.CheckPasswordSignInAsync(user, password, true);
    return Ok(result.Succeeded);
  }

  [HttpPost]
  public async Task<IActionResult> Verify(AppUser user, string password) {
    var ok = await _users.CheckPasswordAsync(user, password);
    if (!ok) { await _users.AccessFailedAsync(user); }
    return Ok(ok);
  }

  [HttpPost]
  public async Task<IActionResult> VerifyOnly(AppUser user, string password) {
    return Ok(await _users.CheckPasswordAsync(user, password));
  }
}
"""


def test_aspnet_identity_lockout_on_failure(tmp_path):
    ctx = _ctx(tmp_path, {"AccountController.cs": IDENTITY})
    login = _verdict(ctx, "AccountController.Login")
    assert login["verdict"] == "proved", login
    assert "lockoutOnFailure = true" in login["reason"]
    assert _verdict(ctx, "AccountController.Check")["verdict"] == "proved"       # positional `true`
    assert _verdict(ctx, "AccountController.LoginNoLock")["verdict"] == "refuted"
    flag = _verdict(ctx, "AccountController.LoginFlag")
    assert flag["verdict"] == "unknown", flag
    assert "lockoutOnFailure" in flag["reason"]
    # UserManager: the application counts the failure itself
    assert _verdict(ctx, "AccountController.Verify")["verdict"] == "proved"
    assert _verdict(ctx, "AccountController.VerifyOnly")["verdict"] == "refuted"


def test_when_arg_is_validated():
    import pytest
    from frame.sil.packs.schema import PackError, parse_pack
    head = {"pack": {"name": "x", "language": "csharp"}}
    with pytest.raises(PackError, match="on a call entry"):
        parse_pack({**head, "rate_limit": [{"name": ["M"], "kind": "global",
                                            "when_arg": {"position": 0, "value": True}}]})
    with pytest.raises(PackError, match="needs `position` or `name`"):
        parse_pack({**head, "rate_limit": [{"name": ["M"], "kind": "call", "when_arg": {"value": True}}]})
    with pytest.raises(PackError, match="unknown|not allowed|Unknown"):
        parse_pack({**head, "rate_limit": [{"name": ["M"], "kind": "call",
                                            "when_arg": {"position": 0, "value": True, "default": 1}}]})
    pack = parse_pack({**head, "rate_limit": [{"name": ["M"], "kind": "call",
                                               "when_arg": {"name": "lock", "value": True}}]})
    assert pack.rate_limits[0]["when_arg"] == {"position": None, "name": "lock", "value": True}


BUCKET = """\
package com.acme;

import io.github.bucket4j.Bucket;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LoginController {
    private final Bucket bucket;
    private final PasswordEncoder encoder;

    public LoginController(Bucket bucket, PasswordEncoder encoder) {
        this.bucket = bucket;
        this.encoder = encoder;
    }

    @PostMapping("/login")
    public boolean login(String password, String hash) {
        if (bucket.tryConsume(1)) {
            return encoder.matches(password, hash);
        }
        return false;
    }

    @PostMapping("/pin")
    public String pin(String password, String hash) {
        if (encoder.matches(password, hash)) {
            return "ok";
        }
        return "no";
    }
}
"""


def test_a_limiter_and_a_credential_check_written_in_a_condition(tmp_path):
    ctx = _ctx(tmp_path, {"LoginController.java": BUCKET})
    login = _verdict(ctx, "LoginController.login")
    assert login["verdict"] == "proved", login              # a field typed Bucket, in the `if`
    assert "tryConsume" in login["reason"]
    pin = _verdict(ctx, "LoginController.pin")
    assert pin["verdict"] == "refuted", pin                 # the check is the condition itself
    assert pin["witness"][0]["line"] == 28


LOCKOUT = """\
from django.contrib.auth.hashers import check_password
from django.db import models
from django.db.models import F
from django.http import HttpResponse


class Account(models.Model):
    pin = models.CharField(max_length=128)
    failures = models.IntegerField(default=0)


def locked_login(request):
    acct = Account.objects.get(name=request.POST["u"])
    if acct.failures >= 5:
        return HttpResponse("locked")
    if not check_password(request.POST["pin"], acct.pin):
        acct.failures += 1
        acct.save()
        return HttpResponse("no")
    return HttpResponse("ok")


def logged_login(request):
    acct = Account.objects.get(name=request.POST["u"])
    if acct.failures >= 5:
        print("many failures")
    if not check_password(request.POST["pin"], acct.pin):
        Account.objects.filter(pk=acct.pk).update(failures=F("failures") + 1)
        return HttpResponse("no")
    return HttpResponse("ok")


def pin_login(request):
    acct = Account.objects.get(name=request.POST["u"])
    if not check_password(request.POST["pin"], acct.pin):
        acct.failures += 1
        acct.save()
        return HttpResponse("no")
    return HttpResponse("ok")
"""


def test_a_lockout_kept_in_stored_data(tmp_path):
    ctx = _ctx(tmp_path, {"app/views.py": LOCKOUT})
    r = _verdict(ctx, "locked_login")
    assert r["verdict"] == "proved", r                      # refuses on the count before the check
    assert "failures" in r["reason"] and "line 14" in r["reason"]
    # a branch on the count whose arms both go on to the check refuses nothing
    assert _verdict(ctx, "logged_login")["verdict"] == "unknown"
    assert _verdict(ctx, "pin_login")["verdict"] == "unknown"


HELPER_LOCKOUT = """\
from django.contrib.auth.hashers import check_password
from django.db import models
from django.http import HttpResponse


class Account(models.Model):
    pin = models.CharField(max_length=128)
    failures = models.IntegerField(default=0)


def is_locked(acct):
    return acct.failures >= 5


def record_failure(acct):
    acct.failures += 1
    acct.save()


def helper_login(request):
    acct = Account.objects.get(name=request.POST["u"])
    if is_locked(acct):
        return HttpResponse("locked")
    if not check_password(request.POST["pin"], acct.pin):
        record_failure(acct)
        return HttpResponse("no")
    return HttpResponse("ok")
"""


def test_a_lockout_through_helpers(tmp_path):
    # the count is tested by a helper's returned comparison and kept by another helper
    ctx = _ctx(tmp_path, {"app/views.py": HELPER_LOCKOUT})
    r = _verdict(ctx, "helper_login")
    assert r["verdict"] == "proved", r
    assert "record_failure" in r["reason"]


ACCOUNT = """\
package com.acme;

import jakarta.persistence.Entity;

@Entity
public class Account {
    private int failedAttempts;
    private String hash;
    public int getFailedAttempts() { return failedAttempts; }
    public void setFailedAttempts(int n) { failedAttempts = n; }
    public String getHash() { return hash; }
}

"""

LOGIN_SERVICE = """\
package com.acme;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.security.crypto.password.PasswordEncoder;

interface AccountRepository extends JpaRepository<Account, Long> {
    Account findByName(String name);
}

public class LoginService {
    private final AccountRepository accounts;
    private final PasswordEncoder encoder;

    public LoginService(AccountRepository accounts, PasswordEncoder encoder) {
        this.accounts = accounts;
        this.encoder = encoder;
    }

    public boolean login(String name, String password) {
        Account a = accounts.findByName(name);
        if (a.getFailedAttempts() >= 5) {
            throw new IllegalStateException("locked");
        }
        if (!encoder.matches(password, a.getHash())) {
            a.setFailedAttempts(a.getFailedAttempts() + 1);
            accounts.save(a);
            return false;
        }
        return true;
    }

    public boolean audit(String name, String password) {
        Account a = accounts.findByName(name);
        if (!encoder.matches(password, a.getHash())) {
            a.setFailedAttempts(a.getFailedAttempts() + 1);
            accounts.save(a);
            return false;
        }
        return true;
    }
}
"""


def test_a_lockout_through_accessors_and_a_repository_beside_the_service(tmp_path):
    # `accounts.save(a)` on a Spring Data repository declared in the service's own file is the
    # library's save, as when the repository has a file of its own
    ctx = _ctx(tmp_path, {"com/acme/Account.java": ACCOUNT, "com/acme/LoginService.java": LOGIN_SERVICE})
    r = _verdict(ctx, "LoginService.login")
    assert r["verdict"] == "proved", r
    assert "failedAttempts" in r["reason"]
    audit = _verdict(ctx, "LoginService.audit")
    assert audit["verdict"] == "unknown", audit
    assert "counts in failedAttempts" in audit["reason"]
