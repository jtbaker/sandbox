import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { SessionManager } from "/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/index.js";

const [mode, previous] = process.argv.slice(2);
const cwd = process.cwd();
const text = (manager) => JSON.stringify(manager.buildSessionContext().messages);
const append = (manager, phase) => {
    manager.appendMessage({ role: "user", content: `fixture-pi-${phase}`, timestamp: Date.now() });
    manager.appendMessage({
        role: "assistant", content: [{ type: "text", text: `fixture-pi-answer-${phase}` }],
        api: "openai-completions", provider: "fixture", model: "fixture",
        usage: { input: 1, output: 1, cacheRead: 0, cacheWrite: 0, totalTokens: 2,
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } },
        stopReason: "stop", timestamp: Date.now(),
    });
};
let manager;
if (mode === "fixture") {
    manager = SessionManager.create(cwd);
    assert(!fs.existsSync(manager.getSessionFile()), "Pi should persist lazily");
    append(manager, mode);
    const source = manager.getSessionFile();
    manager = SessionManager.forkFrom(source, cwd);
    assert.equal(manager.getHeader().parentSession, source);
    assert(path.isAbsolute(source) && fs.existsSync(source));
    // Ensure continueRecent has one winner even on coarse-mtime filesystems.
    fs.utimesSync(source, new Date(0), new Date(0));
} else {
    const listed = await SessionManager.list(cwd);
    assert(listed.some((entry) => entry.path === previous), "native Pi listing lost session");
    manager = SessionManager.continueRecent(cwd);
    assert.equal(manager.getSessionFile(), previous, "native Pi continue chose wrong session");
    assert(text(manager).includes("fixture-pi-answer-fixture"), "Pi replay lost first turn");
    assert(fs.existsSync(manager.getHeader().parentSession), "absolute parentSession is not host-valid");
    append(manager, mode);
}
const bucket = `--${cwd.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
assert.equal(path.dirname(manager.getSessionFile()), path.join(process.env.HOME, ".pi/agent/sessions", bucket));
assert.equal(manager.getHeader().cwd, cwd);
const opened = SessionManager.open(manager.getSessionFile());
assert(text(opened).includes("fixture-pi-answer-fixture"), "Pi public reader lost turn");
assert((await SessionManager.listAll()).some((entry) => entry.path === manager.getSessionFile()));
console.log(JSON.stringify({ path: manager.getSessionFile(), parent: manager.getHeader().parentSession }));
