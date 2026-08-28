# Memory backup

Mirror of VS Code Copilot Chat memory for this workspace.

**Layout:**

```
notes/memory/
├── README.md           ← this file
├── repo/               ← live backup of repo-scoped memory (synced)
│   └── <your-files>.md
└── examples/           ← templates / starting points (NOT synced — docs only)
    ├── repo/
    │   ├── example-tenant-context.md
    │   └── example-investigation-patterns.md
    └── user/
        └── example-tenant-context-check.md
```

- **Source of truth for `repo/`:** `%APPDATA%\Code\User\workspaceStorage\<hash>\GitHub.copilot-chat\memory-tool\memories\repo\`
- **Backed up here so:** it survives VS Code reset / reinstall / workspace rename. Because the backup lives inside the workspace folder, any cloud sync you've attached to that folder (OneDrive, Dropbox, iCloud, Google Drive, etc.) will mirror it automatically.
- **Gitignored** via `notes/` in `.gitignore` — contains internal context (tenant IDs, personnel names, IPs).
- **`examples/` is docs only.** The sync script only mirrors `repo/`. Examples are templates you copy and adapt — they never enter live memory unless you explicitly create them via the `memory` tool in chat.
- **Future tiers:** if you ever want to also back up user or session memory, add `notes/memory/user/` or `notes/memory/session/` and extend the script.

## Sync

```powershell
# After updating memory in chat (push AppData -> workspace backup) - DEFAULT, safe
.\scripts\sync-repo-memory.ps1

# Restore from backup on a fresh machine (writes into Copilot's memory)
.\scripts\sync-repo-memory.ps1 -Direction FromBackup -Force

# Preview only (any direction)
.\scripts\sync-repo-memory.ps1 -WhatIf
.\scripts\sync-repo-memory.ps1 -Direction FromBackup -WhatIf

# Also keep the GitHub Copilot CLI / app memory store in sync (machine-global)
.\scripts\sync-repo-memory.ps1 -IncludeCopilotCli
```

Default direction is `ToBackup` (one-way export). `FromBackup` and `Both` require `-Force` because they write into Copilot's trusted memory store.

### Keeping VS Code and the GitHub Copilot CLI in sync

VS Code Copilot and the GitHub Copilot CLI/app keep **separate** memory stores. Pass `-IncludeCopilotCli` to also sync the CLI store (`%USERPROFILE%\.copilot\memories\`) through the same `notes/memory/` backup hub, so both stay consistent:

- `cli-repo` ← → `notes/memory/repo` (recursive — repo memory)
- `cli-user` ← → `notes/memory/user` (top-level `*.md` only — the context-check triggers; the CLI's `repo/` and `session/` subfolders are not dragged into the user tier)

`-IncludeCopilotCli` also relaxes the VS Code requirement: if no VS Code `workspaceStorage` hash matches the workspace (e.g. running from a Copilot worktree that was never opened in VS Code), the script proceeds with the CLI tiers only instead of failing. Because the CLI store is machine-global, `-Direction FromBackup`/`Both` with `-IncludeCopilotCli` will influence **every** Copilot CLI session on the machine — hence the same `-Force` gate applies.

---

## ⚠️ Security: memory is trusted input

Repo memory files are loaded into Copilot Chat as **authoritative instructions** with full access to MCP tools (Sentinel, Graph, Azure). Treat `notes/memory/repo/` the same as code:

| Risk | Mitigation |
|---|---|
| Pulling memory from a fork / PR / shared drive | Review every diff before running `-Direction FromBackup` |
| Tampered backup on disk overwriting AppData | `FromBackup` requires `-Force` and is never the default |
| Sensitive content (tenant IDs, IPs, FP patterns) leaking via git | `notes/memory/repo/` is gitignored; only `notes/memory/README.md` and `notes/memory/examples/` are tracked |
| Secrets accidentally pasted into a memory file | Audit `notes/memory/repo/` periodically; never paste tokens / passwords. If the workspace folder is cloud-synced, the backup propagates wherever that sync goes |
| Examples copied verbatim with real values | Templates in `examples/` use placeholders only; replace before committing your own |

**Cloud-sync caveat:** if the workspace folder is mirrored by a cloud sync service (OneDrive, Dropbox, iCloud, Google Drive, etc.), `notes/memory/repo/` rides along automatically. That's a convenient cross-machine backup, but it also means the contents leave your local machine. If your sync target is shared, cross-tenant, or governed by DLP that prohibits storing security context, evaluate before adopting this workflow. For local-only backup, move the workspace outside any synced folder or override `$BackupRoot` in the sync script.

---

## Important: Make Copilot actually USE the memory

Repo memory files are **NOT auto-loaded into Copilot's context** — only their filenames are visible at the start of a chat. Copilot has to *decide* to read a file based on what it sees in the conversation.

**User memory** (`/memories/*.md`, NOT `/memories/repo/`) **IS auto-loaded** (first ~200 lines). So the way to make Copilot proactively pull a repo memory file is to add a short **trigger rule** to user memory pointing at it.

### Templates

Copy and adapt these — do NOT use them verbatim:

| Template | Goes into | Purpose |
|---|---|---|
| `examples/repo/example-tenant-context.md` | `/memories/repo/<your-tenant>.md` | Stores the rich tenant facts (IPs, personnel, FP patterns) |
| `examples/repo/example-investigation-patterns.md` | `/memories/repo/investigation-patterns.md` | Reusable investigation playbooks for your tenant |
| `examples/user/example-tenant-context-check.md` | `/memories/<your-tenant>-context-check.md` | The trigger rule that makes Copilot actually read the repo file above |

The first two go into **repo memory** (this workspace only, synced via the script).
The third goes into **user memory** (auto-loads in every chat across every workspace).

### Why this matters

| Without trigger rule | With trigger rule |
|---|---|
| Copilot sees `<tenant>.md` filename, may or may not read it | Copilot loads context-check rule every chat → reliably reads the right repo memory file when tenant signals appear |
| Risk: confident wrong verdicts on documented FP patterns | Reliably suppresses known FPs across all investigations |
| Memory file is "available but unused" | Memory file is "actively consulted" |

### How to create memory files

#### From scratch (first-time setup)

In a Copilot chat:

> ""Open `notes/memory/examples/user/example-tenant-context-check.md`, replace the placeholders with my real values (tenant id `<...>`, domain `@<...>`, repo file `<...>.md`), and create the result as a user memory file at `/memories/<your-tenant>-context-check.md`."

Copilot will use its `memory` tool to create the file. Repeat for the repo-tier templates, but create those at `/memories/repo/...` instead.

#### Fresh machine after restoring from backup

User memory is **global, not workspace-scoped**, so the sync script does not restore it. After running `FromBackup -Force` on a new machine, your repo memory is back in AppData but the user-memory trigger that makes Copilot actually read it is missing. To rebuild it in one step:

> "Read every file in `/memories/repo/`, then for each one create a short trigger rule in user memory at `/memories/<filename>-context-check.md` that tells you to open and read the matching repo memory file *before* writing any risk assessment. Use `notes/memory/examples/user/example-tenant-context-check.md` as the structural template. **Trigger signals MUST be limited to stable identifiers only: tenant IDs, Sentinel workspace IDs, and domain suffixes (UPN suffixes / email domains).** Do NOT include IP addresses, account names, validated personnel UPNs, infrastructure CIDR ranges, or any other volatile/enumerable details — those belong in the repo file, not the trigger. Keep each trigger under 15 lines."

Copilot reads the repo files (which it now has access to in this workspace), extracts only the stable identifiers from each, and writes one short trigger file per repo file. After that, every new chat in any workspace auto-loads the triggers and Copilot reliably consults the repo memory when those signals appear.

**Why the constraint:** trigger files share a ~200-line auto-load budget across every workspace and every chat. A 30-line trigger packed with IPs and account lists eats budget that other triggers (other tenants, other workspaces) need. Stable identifiers (tenant GUID, workspace GUID, domain suffix) almost never change, are highly distinctive, and are enough to make Copilot pull the repo file — which is the actual source of truth for the volatile facts.

---

## 🎛️ Mission Control integration (GitHub Copilot app)

If you run this repo in the **GitHub Copilot app**, the **Mission Control** canvas (`.github/extensions/skills-canvas/`) exposes the memory loop as one-click actions in its **Findings** tab — no chat prompts to hand-write. These operate on the **CLI/app memory store** (`%USERPROFILE%\.copilot\memories\repo\`), i.e. the same `cli-repo` tier the sync script mirrors with `-IncludeCopilotCli`.

| Action | What it does | Relationship to this workflow |
|---|---|---|
| **⚙️ Set memory file** | Writes a `memory_file` name into `config.json` (defaults to a per-tenant `<name>-context.md` on first run). | Names *which* repo memory file the other two actions target. The extension never reads the file — it only references it by name. |
| **🧠 Use memory** | Prepends a review directive to every investigation you launch, telling the agent to read the named context-memory file and apply its ground truth *before* rendering a verdict. | A **per-launch alternative to the auto-loaded user-memory trigger rule** above. Handy when the trigger isn't set up — e.g. a fresh worktree that never restored user memory. Both can coexist. |
| **🧠 Compact to memory** | Hands the agent a propose-only prompt (via the [`context-memory-review`](../../.github/skills/context-memory-review/SKILL.md) skill) that distills accumulated findings into candidate ADD / MODIFY / FLAG changes for the memory file, for human approval. | Automates the "keep the repo memory file current" step. It **proposes only** — you still review and apply, then run the sync script to back the change up here. |

**End-to-end loop:** record findings in the canvas → **🧠 Compact to memory** proposes updates → you approve/apply into `.copilot/memories/repo/<file>.md` → `sync-repo-memory.ps1 -IncludeCopilotCli` backs it up into `notes/memory/repo/` → **🧠 Use memory** (or the trigger rule) applies it on the next investigation.

> The **🧠 Use memory** directive and the **user-memory trigger rule** solve the same problem (making Copilot actually consult repo memory) from two angles: the trigger rule is passive and global (auto-loaded in every chat), while **Use memory** is explicit and per-launch. In the non-interactive app/CLI context — where repo memory does *not* auto-load — the explicit directive is often the more reliable path.

