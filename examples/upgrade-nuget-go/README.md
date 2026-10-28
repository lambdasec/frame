# Upgrading .NET and Go dependencies

Two small projects whose vulnerable package is **transitive**, so the fix depends on how each package manager picks versions.

- `dotnet/`: a .NET 8 app referencing `Azure.Identity` 1.10.3, which pulls in a vulnerable `Microsoft.Identity.Client` (MSAL) 4.56.0. `packages.lock.json` is what `dotnet restore` wrote.
- `go/`: a Go 1.21 module using gin 1.7.0, with old `golang.org/x/crypto` and `golang.org/x/sys`. `go.mod` is what `go mod tidy` wrote.

`offline-advisories/` holds these packages' advisories (OSV data, CC-BY 4.0) and `offline-registry/` the registry documents the planner reads (nuget.org's registration index, the Go module proxy's `go.mod` files), so everything below runs offline.

```bash
cd examples/upgrade-nuget-go
frame kb pull --advisories --source offline-advisories
export FRAME_REGISTRY_CACHE=$PWD/offline-registry
```

## .NET: NuGet picks the lowest version a range admits

```console
$ frame deps dotnet --vulns --plan
4 known vulnerabilities:
  MEDIUM   Azure.Identity@1.10.3 (direct) GHSA-m5vv-6r4h-3vj9: ...; fixed in 1.11.4  [packages.lock.json]
  MEDIUM   Microsoft.Identity.Client@4.56.0 (transitive) GHSA-m5vv-6r4h-3vj9: ...; fixed in 4.60.4  [packages.lock.json]
  ...
Upgrade plan (2 packages):
  Azure.Identity 1.10.3 -> 1.11.4: raise the project's requirement  [packages.lock.json; fixes 2]
  Microsoft.Identity.Client 4.56.0 -> 4.60.4: override: a direct PackageReference at that version  [packages.lock.json; fixes 2]
```

Azure.Identity 1.10.3 asks for MSAL `[4.56.0, )`. npm or pip would take the newest version that range admits; NuGet takes the **lowest**, 4.56.0. So re-locking never moves a NuGet package, and planned one package at a time, the transitive fix becomes a direct `PackageReference` (an override).

With `--registry`, Frame reads every Azure.Identity release's ranges and solves the upgrades together, modelling NuGet's rule: a transitive package *is* the lowest version all its parents admit.

```console
$ frame deps dotnet --vulns --plan --registry
Upgrade plan (3 packages):
  Azure.Identity 1.10.3 -> 1.11.4: raise the project's requirement  [packages.lock.json; fixes 2]
      re-locking also moves Azure.Core 1.35.0 ([1.38.0, ))
  Microsoft.Identity.Client 4.56.0 -> 4.61.3: re-lock to it (admitted by the solved upgrades)  [packages.lock.json; fixes 2]
      re-locking also moves Microsoft.IdentityModel.Abstractions 6.22.0 ([6.35.0, ))
  Microsoft.Identity.Client.Extensions.Msal 4.56.0 -> 4.61.3: re-lock to it (admitted by the solved upgrades)  [packages.lock.json; lets Microsoft.Identity.Client upgrade]

Edits (dry run; --apply writes them):
...
-    <PackageReference Include="Azure.Identity" Version="1.10.3" />
+    <PackageReference Include="Azure.Identity" Version="1.11.4" />
```

Azure.Identity 1.11.4 asks for MSAL `[4.61.3, )`, whose lowest version, 4.61.3, is fixed. One edit, no override. With the .NET SDK installed, `--apply --relock` writes it and runs `dotnet restore --force-evaluate`; the restored lockfile has MSAL 4.61.3 and `frame deps --vulns` finds nothing (checked with the real SDK in `tests/test_sca_solve.py`).

## Go: what the module's Go version can build

Go needs no solver: `go.mod` lists every module the build uses, and Go takes the highest version any `go.mod` requires, so raising a line in your `go.mod` always takes effect. What can stop it is the toolchain: a module version may need a newer Go than yours.

```console
$ frame deps go --vulns --plan --registry
Upgrade plan (3 packages):
  github.com/gin-gonic/gin 1.7.0 -> 1.9.1: raise the project's requirement  [go.mod; fixes 3]
  golang.org/x/crypto 0.0.0-20200622213623-75b288015ac9 -> 0.56.0: raise the project's requirement  [go.mod; fixes 26; 1 with no fix stay open: GO-2026-5932]
      needs Go 1.26.0 (go.mod says go 1.21); the newest fix that Go builds is 0.31.0 (go 1.20), fixing 6 of 26
  golang.org/x/sys 0.0.0-20200116001909-b77594299b42 -> 0.44.0: raise the project's requirement  [go.mod; fixes 2]
      needs Go 1.25.0 (go.mod says go 1.21); the newest fix that Go builds is 0.0.0-20220412211240-33da011f77ad (go 1.17), fixing 1 of 2
```

- `x/crypto` v0.56.0 fixes 26 advisories but its `go.mod` says `go 1.26.0`; `go mod tidy` with Go 1.22 or 1.25 refuses it. The newest fix Go 1.21 builds is v0.31.0, which fixes 6 of them. You choose: move the module to a newer Go, or take the partial fix.
- GO-2026-5932 (`x/crypto/openpgp` is unmaintained) has no fixed version. It stays listed as open, and does not stop the upgrades that fix the other 26.
- Without `--registry`, the plan is the same minus the toolchain notes (they come from the module proxy).
