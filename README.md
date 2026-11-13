# polinrider-scan

A small, free scanner that checks your repositories, and optionally your computer, for the **PolinRider** fake-font implant (part of the Contagious Interview operation), the **`#ghc2`** stealer, and the **GhostAction** GitHub Actions workflow, including its self-hosted runner backdoor.

It is one Python 3 file that uses only the standard library and runs on Windows, macOS and Linux. It **only reads files**: it never runs, imports, evaluates or downloads anything it finds. It never starts `node` or `npm` either, because the backdoor patches npm itself, so on an infected computer every npm command restarts it.

Published by Jay Maier, Rising Sun Solutions LLC (phishing and malware threat intelligence). It is new: please report what it finds, and anything it gets wrong, as described under [Report results](#report-results).

## Download it and check it

Download `polinrider_scan.py` from the [latest release](https://github.com/jaym2026/polinrider-scanner/releases/latest). The release notes give the file's SHA-256 hash; check that yours matches before you run it.

macOS and Linux:

```bash
curl -LO https://github.com/jaym2026/polinrider-scanner/releases/latest/download/polinrider_scan.py
shasum -a 256 polinrider_scan.py
```

Windows (PowerShell):

```powershell
Invoke-WebRequest -Uri https://github.com/jaym2026/polinrider-scanner/releases/latest/download/polinrider_scan.py -OutFile polinrider_scan.py
(Get-FileHash .\polinrider_scan.py).Hash
```

You need Python 3.9 or newer (`python3 --version`, or `python --version` on Windows). Nothing else to install.

## Run it

Keep the scanner **outside** the project you are scanning, and run it with `-I` (Python's isolated mode), so nothing in the scanned folder can change how Python starts.

Scan a repository (or several):

```bash
python3 -I polinrider_scan.py path/to/repo
```

On Windows, use `python -I polinrider_scan.py path\to\repo` (or `py -3 -I ...` if you have the Python launcher).

Check the computer itself for the backdoor's persistence:

```bash
python3 -I polinrider_scan.py --machine
```

Options:

| Option | What it does |
|---|---|
| `--json` | JSON output instead of text |
| `--fail-on high` | exit 1 only on high findings (the default is any finding) |
| `--include-node-modules` | also walk `node_modules` folders (skipped by default, like `.git`) |
| `--exclude GLOB` | skip paths matching a glob, relative to the scanned folder, with `/` separators; repeatable |
| `--max-file-mb N` | read at most N MB of each file (default 16). A larger file is read as its first and last N/2 MB, because the implant is appended at the end, and the output says how many files that applied to |

Exit codes: `0` nothing found, `1` at least one finding, `2` the scan itself failed (it never exits 1 because of its own error).

Each finding is either **high** (matches the campaign's shape) or **review** (worth a look by a person, and often legitimate, such as an ordinary task that runs on folder open).

## What it checks in a repository

| Rule | What it looks for | Severity |
|---|---|---|
| `folder-open-task` | `.vscode/tasks.json` (at any depth) and `*.code-workspace` tasks with `"runOn": "folderOpen"`, including tasks reached through `dependsOn` and the `windows` / `linux` / `osx` variants. It follows wrapper scripts such as `.vscode/eslint-check.sh` or `.cmd`, and reports every file the task runs and what that file really is. | High when the task runs a font-like file, a script kept in `.vscode`, a file holding hidden code, or downloads and runs code. Review for any other auto-run task. |
| `fake-font` | Files ending `.woff`, `.woff2`, `.ttf`, `.otf`, `.eot`, and the look-alikes seen in the wild (`.orc`, `.lkf`, `.llf`, `.lfk`, plus `.glb` and `.fml` when the text is JavaScript) whose bytes are text or JavaScript instead of a real font. Real fonts, images and Git LFS pointers are recognized and left alone. | High. A font holding only whitespace, or a web page saved under a font name, is review. |
| `fake-image` | JavaScript saved under an image name (`.svg`, `.jpg`, `.jpeg`, `.png`, `.gif`, `.ico`, `.webp`, `.bmp`), which the campaign also uses. A real SVG starts with markup and is left alone. | High |
| `hidden-code` | A line of 2,000 or more characters with a run of 100 or more spaces or tabs followed by code, in config files at any depth (eslint, postcss, tailwind, vite, next, babel, webpack, hardhat, truffle, jest and any `*.config.js` / `.mjs` / `.cjs` / `.ts`), `.eslintrc.js`, and files named `init` or `api.js`. In other JavaScript and TypeScript files the code after the run must also look like the implant. | High. Review for a whitespace run without implant-like code in an ordinary file. |
| `marker` | The campaign's fixed strings in code, script, JSON and YAML files: `global.i=`, `global['!']`, `global['_V']`, the injector comments `/*C2.....A*/`, `/*M260630A*/`, `/*RS260605*/`, `/*NPM_WS_SHIM*/`, the app-injection names `__inzRQ` / `__inzCR`, a `require` of a `.inz.cjs` file, `.npm-ws-runner.js`, two obfuscator variants, and the `#ghc2` stealer's tag, beacon and collector address. Documentation (`.md`, `.txt`) is not searched, because threat reports quote these strings. | High |
| `npm-script-launcher` | `package.json` scripts (root and subfolders) that run `node <file>`, above all as `node <file> &&` (or `;`, `&`) before the real command, at any position in the chain. | High when the file holds hidden code or markers, or is a font-like file holding text. Review when a chained file is a plain `init` or `api.js`, or a font-like file is missing. |
| `gitignore-entries` | `.gitignore` entries the operator's push scripts leave behind: `config.bat`, `temp_auto_push.bat`, `temp_interactive_push.bat`, `branch_structure.json`. | High for either push script or two or more entries; review for one. |
| `ghostaction-workflow` | A workflow under `.github/workflows/` that sends data to 193.32.204.199: the GhostAction stealer, pushed with a stolen GitHub login. Depending on the version it sends repository secrets, keys found in the code or its git history, or cloud credentials obtained through GitHub's OpenID Connect sign-in. It runs on GitHub, not on your computer. | High |
| `ghostaction-runner-backdoor` | The GhostAction version aimed at a self-hosted runner: it copies SSH keys and cloud, AI and GitHub credentials off the runner's disk and installs a crontab line tagged `#ghc2`. | High |
| `unreadable` | A folder the scan could not open, so nothing in it was checked. | Review |

Folders named `.git`, `node_modules`, `.hg` and `.svn` are skipped. Only regular files are read: symbolic links, named pipes and devices are not. A path that a task or script names outside the scanned folder (`../`, an absolute path, another drive) is not followed. The scanner skips its own source file and byte-identical copies of it.

## What `--machine` checks

Every location below is one the captured malware writes to. The summary says what it actually read: which apps and how many npm copies it checked, that Node.js is not installed when it finds no npm, and any app folder it found with none of the program files it reads (usually what an uninstall leaves behind). A count of zero there means "nothing to check", not "checked and clean".

- `~/.node_modules/` holding `.npm-ws-runner.js`, `.npm-ws.json`, `.npm-ws.pid`, `.npm-ws.log` or `.npm-install.lock` (the backdoor and its settings). The folder on its own is only listed for review, because Node.js still reads it as a legacy module folder. On Linux and macOS it also says whether the process named in `.npm-ws.pid` is running now. That check sends no signal, and it is never made on Windows, where Python's `os.kill` would end the process.
- npm's own `lib/cli.js` with the backdoor launcher appended (`/*M260630A*/` after a run of spaces), in every copy it can find without running npm: beside the `node` on your `PATH`, under any configured npm prefix (`npm_config_prefix`, `~/.npmrc`), `%APPDATA%\npm`, the usual system locations, and every version managed by nvm, nvm-windows, fnm, Volta, asdf, mise and n.
- `%APPDATA%\npm\node_modules\npm\bin\npm-cli.js` (and other `bin/npm-cli.js` copies) marked `/*NPM_WS_SHIM*/`.
- VS Code, Cursor, Antigravity, Discord and GitHub Desktop program files (`out/main.js`, `node_modules/@vscode/deviceid/dist/index.js`, `discord_desktop_core/index.js`, `app/main.js`) that start with an injected `require`, and any `*.inz.cjs`, `*.inz.orig` or `*.inz.tmp` file beside them. On Windows this includes VS Code's versioned `<hash>\resources\app` folder.
- Windows: `%LOCALAPPDATA%\Programs\Python\Python3127`, a Python the malware installs (a genuine Python 3.12 installs to `Python312`).
- The backdoor's first-run marker: a file named after your user name in base64, holding a timestamp, at `/tmp/.<name>` (macOS and Linux alike) or `%LOCALAPPDATA%\Temp\<name>`.
- Linux and macOS: a `crontab -l` line tagged `#ghc2`.

## Use it in continuous integration

[`github-workflow-example.yml`](github-workflow-example.yml) is a sample GitHub Actions workflow. Copy it to `.github/workflows/` and the scanner to `.github/polinrider/polinrider_scan.py`. It runs before anything installs or builds the project, with read-only permissions, and fails the job on any finding. It checks the scanner's hash first, because anyone who can push to the repository can also edit a scanner kept inside it. An organization can do better by keeping the scanner in a separate, protected repository and checking it out at a pinned commit.

## What this catches and what it cannot

It catches the implant shapes listed above, as they stand in the files on disk at the moment you run it, and the persistence the captured stages install on a computer.

It cannot:

- **See pushes made with stolen credentials.** The stealer takes `~/.git-credentials`, the GitHub CLI token and VS Code's stored sign-ins. With those, the operator can push the code back from anywhere, after you remove it, under your name and with forged dates. A clean scan today says nothing about tomorrow. Revoking credentials is what stops this, not the scan.
- **Tell you whether something was stolen.** The Python stealer leaves no files behind, and the backdoor uploads every environment variable as soon as it starts. A clean `--machine` result does not mean your secrets are safe. If you opened, built or ran an infected project, treat them as stolen.
- See other branches, history, forks or pull requests you have not checked out. Check out each branch, or scan a fresh clone of each.
- Recognize variants that change the shape: new markers, other file names, or a payload that is not padded with whitespace. The obfuscation changes often.
- Find copies of npm or the desktop apps in places it does not know about, such as a portable install or an unusual npm prefix set only in a project's `.npmrc`.
- Guarantee anything about a "review" finding. Those need a person to read the file.
- Read more than `--max-file-mb` of a very large file: code hidden in the middle of a file bigger than that is missed.

- **See a GhostAction workflow that has already been deleted.** It only reads the files checked out now. If one ran before you removed it, its secrets are already gone; look at the repository's Actions tab to see when it ran.

Repositories that study this campaign (detection rules, tests, research notes in code) will match the marker rule. Use `--exclude` for those folders.

## If it finds something

Follow these steps in order, because new credentials entered on an infected computer can be stolen too.

1. Do not open the project in VS Code or an editor built on it (Cursor, Windsurf, Antigravity), and do not install, build or run it, until the code is removed.
2. If you opened, built or ran it after the code arrived, treat that computer as compromised and take it off the network. Commit dates can be forged, so if you cannot tell when the code arrived, assume the computer is affected. On Linux or macOS, check `crontab -l` for a line ending in `#ghc2` and remove it before you change any credentials.
3. From a different, clean device, cut off GitHub access first: revoke all personal access tokens, OAuth app and GitHub App grants, and SSH and deploy keys; sign out of all sessions; check your account's security log; and turn on branch protection that blocks force pushes.
4. Still from the clean device, change everything else that computer could reach: every key and token in your environment variables or `.env` files; passwords saved in your browsers, then sign out of all sessions, because it copies cookies too; the master password of your password manager; npm, cloud and AI tool logins; and move any crypto to a new wallet with a new recovery phrase.
5. Then clean the computer, or better, reinstall the operating system. To clean it: delete the hidden `.node_modules` folder in your home folder (not a project's `node_modules`); reinstall Node.js, including every nvm version, because the malware adds code to npm's own `lib/cli.js`; and reinstall VS Code, Cursor, Antigravity, Discord and GitHub Desktop, because it patches their program files. On Windows, also delete `%APPDATA%\npm` and `%LOCALAPPDATA%\Programs\Python\Python3127`.
6. Then remove everything the scan listed from the repositories, and check every config file and every `package.json` in each project, including subfolders. Commit authors and messages can be forged as well as dates. Run the scan again afterwards, and again later, in case the code comes back.

### If it finds a GhostAction workflow

These steps replace the ones above when the only findings are `ghostaction-workflow` or `ghostaction-runner-backdoor`. The workflow runs on GitHub's machines, so your own computer is not affected, unless the repository has a self-hosted runner.

1. For `ghostaction-runner-backdoor` only: if the repository has a self-hosted runner, run `crontab -l` on that machine, remove the line ending in `#ghc2`, and take the machine off the network before you change any credentials. Then rebuild it, or replace everything stored on it: SSH keys, cloud credentials, `.env` files, and AI and GitHub tokens. Deleting the workflow does not clean that machine. If the repository has no self-hosted runner, that job never ran.
2. From a computer you trust, cut off GitHub access first: change your GitHub password; revoke personal access tokens, OAuth app and GitHub App grants you cannot vouch for, and SSH and deploy keys; sign out of other sessions; and check your account's security log for the pushes and for new tokens or keys. Whoever pushed the workflow had a working login.
3. Replace every secret stored in the repository and, for an organization, at the organization level, and every key that has ever appeared in the code, its history or its wiki. Deleting a key from history does not help once it has been sent. If the repository uses AWS through OpenID Connect, check CloudTrail for `AssumeRoleWithWebIdentity` sessions from it.
4. Then delete the workflow, look at the Actions tab to see when it ran, and check for other workflows you did not add and for private gists named "build cache" on your account, which one version uses when it cannot reach its server.
5. Turn on branch protection that blocks force pushes, and consider requiring review before workflow changes are merged.

## Report results

Whether it found something or not, a short report helps: open an [issue](https://github.com/jaym2026/polinrider-scanner/issues) with your operating system, the command you ran and the summary lines. If a result names private repositories or paths you would rather not post, email jay@risingsunsolutions.com instead.

For a finding you think is wrong (a false positive), say which rule fired and on what kind of file. Please do not attach or paste malicious code itself; the rule name, path and line are enough.

## Tests

The tests build small synthetic fixtures in a temporary folder. Each fixture has the shape of an implant (a long whitespace run, then `global.i='x';`), never a working payload.

```bash
python3 -I -m unittest discover -s tests -v
```

## License

MIT, see [LICENSE](LICENSE). Free to use, change and share, including inside your own pipelines and tools. It comes with no warranty: a clean result is not a guarantee, as described under [What this catches and what it cannot](#what-this-catches-and-what-it-cannot).
