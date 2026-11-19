# Upload guide

This directory is intended to be its own repository.

## Preflight

```powershell
git init
git status --short
git add .
git status --short
```

Confirm there are no:

- `challenges/`
- `logs/`
- `.venv/`
- `tool-runtime/`
- `third_party/`
- APK/RAR/ZIP challenge files
- broker token files
- real IP addresses or credentials

## Commit

```powershell
git commit -m "Initial public release"
git branch -M main
```

## GitHub

Create an empty repository on GitHub, then:

```powershell
git remote add github https://github.com/<OWNER>/<REPOSITORY>.git
git push -u github main
```

## Gitee

Create an empty repository on Gitee, then:

```powershell
git remote add gitee https://gitee.com/<OWNER>/<REPOSITORY>.git
git push -u gitee main
```

If a remote was added incorrectly:

```powershell
git remote set-url github <correct-url>
git remote set-url gitee <correct-url>
```
