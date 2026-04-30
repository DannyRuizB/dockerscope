// Parses a Dockerfile string into a stage-aware model.
// Output:
// {
//   stages: [{
//     from: "node:20-alpine",        // image[:tag]
//     name: "builder" | null,        // AS <name>
//     expose: ["3000", "443/udp"],
//     env: [{key, value}],
//     cmd: { exec: [...] } | { shell: "..." } | null,
//     entrypoint: { exec: [...] } | { shell: "..." } | null,
//     workdir: "/app" | null,
//     user: "node" | null,
//   }],
//   finalStage: <last stage> | null,
//   multiStage: boolean,
// }

window.DockerScope = window.DockerScope || {};

window.DockerScope.parseDockerfile = function (text) {
  const lines = collapseContinuations(String(text || ""));
  const stages = [];
  let current = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const spaceIdx = trimmed.search(/\s/);
    if (spaceIdx === -1) continue;
    const instruction = trimmed.slice(0, spaceIdx).toUpperCase();
    const args = trimmed.slice(spaceIdx + 1).trim();

    if (instruction === "FROM") {
      current = makeStageFromArgs(args);
      stages.push(current);
      continue;
    }
    if (!current) continue; // instructions before any FROM are illegal — ignore

    switch (instruction) {
      case "EXPOSE":
        for (const tok of args.split(/\s+/)) if (tok) current.expose.push(tok);
        break;
      case "ENV":
        current.env.push(...parseEnvArgs(args));
        break;
      case "CMD":
        current.cmd = parseExecOrShell(args);
        break;
      case "ENTRYPOINT":
        current.entrypoint = parseExecOrShell(args);
        break;
      case "WORKDIR":
        current.workdir = args;
        break;
      case "USER":
        current.user = args;
        break;
    }
  }

  return {
    stages,
    finalStage: stages.length ? stages[stages.length - 1] : null,
    multiStage: stages.length > 1,
  };
};

function collapseContinuations(text) {
  const out = [];
  const raw = text.split(/\r?\n/);
  let buf = "";
  for (const line of raw) {
    const stripped = line.replace(/\s+$/, "");
    if (stripped.endsWith("\\")) {
      buf += stripped.slice(0, -1) + " ";
    } else {
      buf += stripped;
      out.push(buf);
      buf = "";
    }
  }
  if (buf) out.push(buf);
  return out;
}

function makeStageFromArgs(args) {
  // Strip leading `--platform=...` flag if present.
  let rest = args.replace(/^--platform=\S+\s+/, "");
  const m = rest.match(/^(\S+)(?:\s+as\s+(\S+))?$/i);
  const from = m ? m[1] : rest;
  const name = m && m[2] ? m[2] : null;
  return {
    from,
    name,
    expose: [],
    env: [],
    cmd: null,
    entrypoint: null,
    workdir: null,
    user: null,
  };
}

function parseEnvArgs(args) {
  const trimmed = args.trim();
  if (!trimmed.includes("=")) {
    // Legacy form: ENV KEY value (single key, value is rest of line)
    const m = trimmed.match(/^(\S+)\s+(.+)$/);
    if (m) return [{ key: m[1], value: stripQuotes(m[2]) }];
    return [];
  }
  // Modern form: ENV KEY=value [KEY2=value2 ...]. Quoted values can contain spaces.
  const tokens = tokenizeShell(trimmed);
  const out = [];
  for (const tok of tokens) {
    const eq = tok.indexOf("=");
    if (eq === -1) continue;
    out.push({ key: tok.slice(0, eq), value: stripQuotes(tok.slice(eq + 1)) });
  }
  return out;
}

function parseExecOrShell(args) {
  const trimmed = args.trim();
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed);
      if (Array.isArray(arr)) return { exec: arr };
    } catch (_) { /* fall back to shell */ }
  }
  return { shell: trimmed };
}

function tokenizeShell(s) {
  const out = [];
  let buf = "";
  let quote = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (quote) {
      if (c === quote) { quote = null; continue; }
      buf += c;
    } else if (c === '"' || c === "'") {
      quote = c;
    } else if (/\s/.test(c)) {
      if (buf) { out.push(buf); buf = ""; }
    } else {
      buf += c;
    }
  }
  if (buf) out.push(buf);
  return out;
}

function stripQuotes(s) {
  if (!s) return s;
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}
