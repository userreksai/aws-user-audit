#!/usr/bin/env python3
"""Prepare a minimal audit-location patch without changing the live Nginx file.

This deliberately supports a conservative subset of Nginx configurations.  It
keeps source spans instead of serializing the configuration, so unrelated proxy
routes, comments, whitespace and line endings remain byte-for-byte unchanged.
The installer owns backup, replacement, ``nginx -t`` and reload/rollback.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import re
import sys


class NginxConfigError(ValueError):
    """A fixed diagnostic that never includes configuration contents."""


@dataclass(frozen=True)
class _Token:
    value: str
    start: int
    end: int
    punctuation: bool = False


@dataclass(frozen=True)
class _Directive:
    words: tuple[str, ...]
    start: int
    end: int
    children: tuple["_Directive", ...] | None = None
    closing: int | None = None


def _tokens(text):
    """Recognize structural punctuation, excluding quoted/escaped content."""
    result = []
    offset = 0
    while offset < len(text):
        char = text[offset]
        if char.isspace():
            offset += 1
            continue
        if char == "#":
            while offset < len(text) and text[offset] not in "\r\n":
                offset += 1
            continue
        if char in "{};":
            result.append(_Token(char, offset, offset + 1, True))
            offset += 1
            continue
        start = offset
        value = []
        quote = None
        while offset < len(text):
            char = text[offset]
            if char == "\\":
                if offset + 1 >= len(text):
                    raise NginxConfigError("Nginx 配置包含无法安全解析的转义；请人工检查配置。")
                following = text[offset + 1]
                if following in "\\\"'":
                    value.append(following)
                elif following in "trn":
                    value.append({"t": "\t", "r": "\r", "n": "\n"}[following])
                else:
                    value.extend(("\\", following))
                offset += 2
                continue
            if quote is not None:
                if char == quote:
                    quote = None
                else:
                    value.append(char)
                offset += 1
                continue
            if char in "\"'":
                quote = char
                offset += 1
                continue
            # Nginx variables may contain braces without opening a block.
            if char == "$" and text[offset:offset + 2] == "${":
                end = text.find("}", offset + 2)
                if end < 0 or not re.fullmatch(r"[A-Za-z0-9_]+", text[offset + 2:end]):
                    raise NginxConfigError("Nginx 配置包含无法安全解析的变量；请人工检查配置。")
                value.append(text[offset:end + 1])
                offset = end + 1
                continue
            if char.isspace() or char in "{};#":
                break
            value.append(char)
            offset += 1
        if quote is not None:
            raise NginxConfigError("Nginx 配置引号未闭合；请人工检查配置。")
        if offset == start:
            raise NginxConfigError("Nginx 配置无法安全解析；请人工检查配置。")
        result.append(_Token("".join(value), start, offset))
    return result


def _parse(text):
    if not isinstance(text, str) or "\x00" in text:
        raise NginxConfigError("Nginx 配置文本格式无效。")
    tokens = _tokens(text)
    position = 0

    def sequence(nested=False, depth=0):
        nonlocal position
        if depth > 64:
            raise NginxConfigError("Nginx 配置嵌套过深；请人工修改审计路由。")
        directives = []
        while position < len(tokens):
            first = tokens[position]
            if first.punctuation and first.value == "}":
                if not nested:
                    raise NginxConfigError("Nginx 配置括号不匹配；请人工检查配置。")
                position += 1
                return tuple(directives), first
            words = []
            while position < len(tokens) and not tokens[position].punctuation:
                words.append(tokens[position].value)
                position += 1
            if not words or position >= len(tokens):
                raise NginxConfigError("Nginx 配置指令不完整；请人工检查配置。")
            separator = tokens[position]
            position += 1
            if separator.value == ";":
                directives.append(_Directive(tuple(words), first.start, separator.end))
            elif separator.value == "{":
                children, closing = sequence(True, depth + 1)
                directives.append(_Directive(tuple(words), first.start, closing.end, children, closing.start))
            else:
                raise NginxConfigError("Nginx 配置括号不匹配；请人工检查配置。")
        if nested:
            raise NginxConfigError("Nginx 配置括号未闭合；请人工检查配置。")
        return tuple(directives), None

    return sequence()[0]


def _validate_target(server_name, listen_port):
    if (not isinstance(server_name, str)
            or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", server_name)):
        raise NginxConfigError("必须显式提供准确的 Nginx server_name 域名。")
    if isinstance(listen_port, bool) or not isinstance(listen_port, int) or not 1 <= listen_port <= 65535:
        raise NginxConfigError("必须显式提供有效的 Nginx 监听端口。")


def _listen_matches(words, port):
    if len(words) < 2:
        return False
    address = words[1]
    if address.isdigit():
        return int(address) == port
    if address.startswith("unix:") or ":" not in address:
        return False
    suffix = address.rsplit(":", 1)[-1]
    return suffix.isdigit() and int(suffix) == port


def _servers(nodes):
    for node in nodes:
        if node.children is None:
            continue
        if node.words == ("server",):
            yield node
        elif node.words == ("http",):
            yield from _servers(node.children)


def _matching_servers(text, server_name, listen_port):
    _validate_target(server_name, listen_port)
    matches = []
    for node in _servers(_parse(text)):
        names = [word.lower() for child in node.children
                 if child.words and child.words[0] == "server_name" for word in child.words[1:]]
        if server_name.lower() not in names:
            continue
        if any(child.words and child.words[0] == "listen" and _listen_matches(child.words, listen_port)
               for child in node.children):
            matches.append(node)
    return matches


def _location(node):
    if not node.words or node.words[0] != "location" or node.children is None:
        return None
    arguments = node.words[1:]
    if len(arguments) == 1:
        value = arguments[0]
        for modifier in ("^~", "=", "~*", "~"):
            if value.startswith(modifier):
                return modifier, value[len(modifier):]
        return "", value
    if len(arguments) == 2 and arguments[0] in {"=", "^~", "~", "~*"}:
        return arguments
    raise NginxConfigError("目标 server 包含复杂 location；请人工确认审计路由。")


def _routes(server):
    if any(child.words and child.words[0] == "include" for child in server.children):
        raise NginxConfigError("目标 server 含 include，可能隐藏审计或业务路由；请先人工确认并展开相关配置后重试。")
    audit = []
    roots = []
    for child in server.children:
        location = _location(child)
        if location is None:
            continue
        modifier, path = location
        if modifier == "" and path == "/":
            roots.append(child)
        if (modifier == "=" and path == "/audit") or (modifier in {"", "^~"} and path == "/audit/"):
            audit.append(child)
        elif path.startswith("/audit") or (modifier in {"~", "~*"} and "audit" in path):
            raise NginxConfigError("目标 server 存在额外或正则审计路由；请先人工确认，脚本不会覆盖未知路由。")
    frontend_proxies = [child for child in roots[0].children
                        if child.words and child.words[0] == "proxy_pass"] if len(roots) == 1 else []
    if len(roots) != 1 or len(frontend_proxies) != 1 or len(frontend_proxies[0].words) != 2:
        raise NginxConfigError("目标 server 缺少唯一的原有 location / 代理；请先恢复原前端路由，脚本不会自行添加业务代理。")
    return audit, roots[0]


def _alias_path(publish_dir):
    try:
        value = os.fspath(publish_dir)
    except TypeError:
        raise NginxConfigError("必须显式提供 Linux 网页发布目录。") from None
    if (not isinstance(value, str) or not value.startswith("/") or value.startswith("//")
            or any(char in value for char in "\x00\r\n$\\")
            or any(part in {".", ".."} for part in value.split("/"))):
        raise NginxConfigError("网页发布目录必须为明确的 Linux 绝对路径，不能包含变量、换行或相对路径。")
    result = str(PurePosixPath(value))
    if result == "/":
        raise NginxConfigError("不能将 Linux 根目录作为审计网页目录。")
    return '"' + (result + "/").replace('"', '\\"') + '"'


def _render_locations(indent, newline, alias):
    lines = [
        "location = /audit {",
        "    absolute_redirect off;",
        "    return 302 /audit/;",
        "}",
        "",
        "location ^~ /audit/ {",
        "    absolute_redirect off;",
        "    alias " + alias + ";",
        "    index index.html;",
        "    autoindex off;",
        "    expires -1;",
        "    default_type application/octet-stream;",
        "    types {",
        "        text/html html;",
        "        text/css css;",
        "        application/javascript js;",
        "    }",
        "}",
    ]
    return lines[0] + "".join(newline + (indent + line if line else "") for line in lines[1:])


def _indent_before(text, offset, fallback="    "):
    beginning = max(text.rfind("\n", 0, offset), text.rfind("\r", 0, offset)) + 1
    prefix = text[beginning:offset]
    return prefix if not prefix.strip() else fallback


def prepare_text(text, server_name, listen_port, publish_dir):
    """Return a candidate; replace only the target server's audit locations."""
    alias = _alias_path(publish_dir)
    matches = _matching_servers(text, server_name, listen_port)
    if len(matches) != 1:
        raise NginxConfigError("未找到唯一匹配域名和端口的 server；请明确配置文件及目标 server，脚本不会猜测。")
    server = matches[0]
    audit, root = _routes(server)
    newline_match = re.search(r"\r\n|\n|\r", text)
    newline = newline_match.group() if newline_match else "\n"
    if audit:
        ordered = sorted(audit, key=lambda node: node.start)
        first = ordered[0]
        indent = _indent_before(text, first.start)
        replacement = _render_locations(indent, newline, alias)
        canonical = _parse(replacement)
        if len(ordered) == 2 and all(
            text[actual.start:actual.end] == replacement[expected.start:expected.end]
            for actual, expected in zip(ordered, canonical)
        ):
            # Do not accumulate the whitespace left between two replaced
            # blocks when the installer is run again with the same settings.
            return text
        edits = [(first.start, first.end, replacement)]
        edits.extend((node.start, node.end, "") for node in ordered[1:])
    else:
        server_indent = _indent_before(text, server.start, "")
        indent = server_indent + "    "
        replacement = newline + indent + _render_locations(indent, newline, alias) + newline + server_indent
        edits = [(server.closing, server.closing, replacement)]
    candidate = text
    for start, end, replacement in sorted(edits, reverse=True):
        candidate = candidate[:start] + replacement + candidate[end:]
    # The edit intervals are disjoint from the frontend.  Re-parse as a second
    # guard so the candidate must still have exactly the original frontend.
    updated = _matching_servers(candidate, server_name, listen_port)
    updated_audit, updated_root = _routes(updated[0]) if len(updated) == 1 else ([], None)
    if (len(updated_audit) != 2 or updated_root is None
            or candidate[updated_root.start:updated_root.end] != text[root.start:root.end]):
        raise NginxConfigError("候选配置未通过原前端保留校验；没有修改原配置。")
    return candidate


def discover_config(dump, server_name, listen_port):
    """Find one source file in ``nginx -T`` output; never follow includes."""
    _validate_target(server_name, listen_port)
    if not isinstance(dump, str):
        raise NginxConfigError("Nginx 配置转储格式无效。")
    headers = list(re.finditer(r"(?m)^# configuration file ([^\r\n]+):\r?$", dump))
    if not headers:
        raise NginxConfigError("配置转储没有可识别的源文件；请显式提供 Nginx 配置路径。")
    found = []
    seen = set()
    for number, header in enumerate(headers):
        source = header.group(1)
        if not source.startswith("/") or "\x00" in source or source in seen:
            raise NginxConfigError("配置转储中的源文件不明确；请显式提供 Nginx 配置路径。")
        seen.add(source)
        stop = headers[number + 1].start() if number + 1 < len(headers) else len(dump)
        text = dump[header.end():stop]
        matches = _matching_servers(text, server_name, listen_port)
        for server in matches:
            _routes(server)
            found.append(Path(source))
    if len(found) != 1:
        raise NginxConfigError("无法从配置转储确定唯一目标源文件；请显式提供 Nginx 配置路径。")
    return found[0]


def _read_text(path):
    with Path(path).open("r", encoding="utf-8", errors="surrogateescape", newline="") as stream:
        return stream.read()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    discover = commands.add_parser("discover", help="Only identify a unique source from saved nginx -T output")
    discover.add_argument("--dump", required=True)
    plan = commands.add_parser("plan", help="Write a candidate file; never modify the original configuration")
    plan.add_argument("--nginx-config", required=True)
    plan.add_argument("--publish-dir", required=True)
    plan.add_argument("--output", required=True)
    for command in (discover, plan):
        command.add_argument("--server-name", required=True)
        command.add_argument("--listen-port", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "discover":
            print(discover_config(_read_text(args.dump), args.server_name, args.listen_port))
            return 0
        source = Path(args.nginx_config).resolve(strict=True)
        output = Path(args.output)
        if output.exists() or output.is_symlink() or output.resolve() == source:
            raise NginxConfigError("候选输出必须是新的独立文件，不能覆盖原配置或已有文件。")
        candidate = prepare_text(_read_text(source), args.server_name, args.listen_port, args.publish_dir)
        # Exclusive creation also refuses a symlink created after the checks.
        fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as stream:
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        print("候选配置已生成；原 Nginx 配置未修改。")
        return 0
    except NginxConfigError as exc:
        print("Nginx 配置准备失败：" + str(exc), file=sys.stderr)
    except (OSError, UnicodeError):
        print("Nginx 配置准备失败：无法安全读取源文件或写入候选文件；请检查明确路径及权限。", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
