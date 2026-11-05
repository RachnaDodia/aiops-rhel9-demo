#!/usr/bin/env python3
"""Static policy gate for LLM-generated remediation playbooks.

Exit 0 = acceptable (warnings may be printed), exit 1 = rejected.
It removes the obviously dangerous; it does not replace review of the pull request.
"""
import json
import re
import sys

import yaml

ALLOWED_MODULES = {
    "ansible.builtin.service", "ansible.builtin.systemd", "ansible.builtin.systemd_service",
    "ansible.builtin.file", "ansible.builtin.lineinfile", "ansible.builtin.replace",
    "ansible.builtin.blockinfile", "ansible.builtin.copy", "ansible.builtin.stat",
    "ansible.builtin.find", "ansible.builtin.dnf", "ansible.builtin.command",
    "ansible.builtin.shell", "ansible.builtin.assert", "ansible.builtin.debug",
    "ansible.builtin.wait_for", "ansible.builtin.service_facts", "ansible.builtin.set_fact",
    "ansible.builtin.uri",
    "ansible.posix.seboolean", "ansible.posix.sysctl", "ansible.posix.firewalld",
}

TASK_KEYWORDS = {
    "name", "when", "register", "become", "become_user", "become_method", "vars", "tags",
    "notify", "loop", "loop_control", "until", "retries", "delay", "changed_when",
    "failed_when", "ignore_errors", "ignore_unreachable", "block", "rescue", "always",
    "args", "environment", "delegate_to", "delegate_facts", "run_once", "no_log",
    "check_mode", "diff", "timeout", "listen", "any_errors_fatal", "throttle", "async",
    "poll", "connection", "remote_user", "module_defaults", "collections",
}

FORBIDDEN_CMD = [
    (r"\brm\b", "use ansible.builtin.file instead of rm"),
    (r"\bmkfs", "filesystem creation"),
    (r"\bdd\s+if=", "raw disk writes"),
    (r"\b(shutdown|reboot|poweroff|halt)\b", "reboot/shutdown"),
    (r"\binit\s+[06]\b", "reboot/shutdown"),
    (r"systemctl\s+(reboot|poweroff|halt|isolate)", "reboot/shutdown"),
    (r"\b(curl|wget)\b", "remote downloads are not allowed"),
    (r"\buser(add|del|mod)\b|\bpasswd\b|\bchpasswd\b", "account changes"),
    (r"iptables\s+-F|nft\s+flush", "flushing the firewall"),
    (r">\s*/dev/(sd|nvme|xvd)", "raw device writes"),
    (r"\bchmod\s+(-R\s+)?0?777\b", "world-writable permissions"),
]

# Applied to the text of EVERY task, whatever the module.
FORBIDDEN_ANY = [
    (r"setenforce", "changing the SELinux mode"),
    (r"semanage\s+permissive|semodule|audit2allow", "weakening SELinux policy"),
    (r"/etc/selinux/config|SELINUX\s*=\s*(disabled|permissive)", "persistently disabling SELinux"),
    (r"/etc/(shadow|sudoers)|\.ssh/", "credential files"),
]

SAFE_DELETE_PREFIXES = ("/tmp/", "/var/tmp/", "/var/cache/", "/var/log/")
LOCAL_URL = re.compile(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?(/|$)")

violations, warnings = [], []


def command_text(args):
    if isinstance(args, str):
        return args
    if isinstance(args, dict):
        argv = args.get("argv")
        if isinstance(argv, list):
            return " ".join(str(a) for a in argv)
        return str(args.get("cmd", "") or "")
    return ""


def walk(tasks, where):
    for i, task in enumerate(tasks or []):
        if not isinstance(task, dict):
            violations.append(f"{where}: task #{i + 1} is not a mapping")
            continue
        label = f"{where}: {task.get('name', f'task #{i + 1}')}"
        for sub in ("block", "rescue", "always"):
            if sub in task:
                walk(task[sub], label + f"/{sub}")
        flat = json.dumps({k: v for k, v in task.items() if k not in ("block", "rescue", "always")}, default=str)
        for pattern, reason in FORBIDDEN_ANY:
            if re.search(pattern, flat, re.IGNORECASE):
                violations.append(f"{label}: forbidden ({reason})")
        mods = [k for k in task if k not in TASK_KEYWORDS and not k.startswith("with_")]
        if not mods:
            if "block" not in task:
                violations.append(f"{label} has no module")
            continue
        if len(mods) != 1:
            violations.append(f"{label} has unexpected keys {mods}")
            continue
        mod, args = mods[0], task[mods[0]]
        if mod not in ALLOWED_MODULES:
            violations.append(f"{label} uses module '{mod}' which is not on the allow-list")
            continue
        if mod in ("ansible.builtin.command", "ansible.builtin.shell"):
            text = command_text(args)
            for pattern, reason in FORBIDDEN_CMD:
                if re.search(pattern, text, re.IGNORECASE):
                    violations.append(f"{label}: forbidden command ({reason}): {text.strip()[:80]}")
        if mod == "ansible.builtin.uri":
            url = str(args.get("url", "")) if isinstance(args, dict) else ""
            if not LOCAL_URL.match(url):
                violations.append(f"{label}: uri may only call localhost (got '{url}')")
        if mod in ("ansible.builtin.file", "ansible.builtin.copy") and isinstance(args, dict):
            if str(args.get("mode", "")).lstrip("0o") == "777":
                violations.append(f"{label}: mode 0777 is not allowed")
        if mod == "ansible.builtin.file" and isinstance(args, dict) and args.get("state") == "absent":
            path = str(args.get("path") or args.get("dest") or "")
            if ".." in path:
                violations.append(f"{label}: path traversal in delete path {path}")
            elif "{{" in path:
                warnings.append(f"{label}: deletes a templated path ({path}); review the selection criteria")
            elif not path.startswith(SAFE_DELETE_PREFIXES):
                violations.append(f"{label}: deleting {path} is outside the safe prefixes")


def main(path):
    try:
        with open(path) as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"REJECTED: not valid YAML: {exc}")
        return 1
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        print("REJECTED: playbook must contain exactly one play")
        return 1
    play = data[0]
    if str(play.get("hosts")) != "all":
        violations.append("play must use hosts: all (the job limit chooses the target)")
    for key in ("roles", "import_playbook", "vars_prompt", "vars_files"):
        if key in play:
            violations.append(f"play must not use '{key}'")
    for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
        walk(play.get(section), section)
    for w in warnings:
        print(f"WARNING: {w}")
    if violations:
        for v in violations:
            print(f"VIOLATION: {v}")
        print("REJECTED")
        return 1
    print("OK: policy check passed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
