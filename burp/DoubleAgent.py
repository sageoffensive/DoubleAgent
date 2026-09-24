# -*- coding: utf-8 -*-
# Burp Suite Python Extension: DoubleAgent v3
# This is the only file an operator selects in Burp. The implementation lives
# in ./src and remains split to stay below Jython/JVM bytecode limits.
# MCP loopback transport uses Java-native, proxy-free, Unicode-safe SSE handshakes.
import os as _bootstrap_os
import sys as _bootstrap_sys

# Burp executes Jython extensions with execfile() and may not define __file__.
# Locate the private source folder without baking a developer-specific path
# into the release. DOUBLE_AGENT_EXTENSION_DIR may point to burp/, burp/src/,
# or the repository root for unusual loaders.
_loader_candidates = []
_extension_filename = globals().get("__file__", "")
if _extension_filename:
    _loader_candidates.append(_bootstrap_os.path.dirname(
        _bootstrap_os.path.abspath(_extension_filename)
    ))
_configured_extension_dir = _bootstrap_os.environ.get(
    "DOUBLE_AGENT_EXTENSION_DIR", "")
if _configured_extension_dir:
    _loader_candidates.append(_bootstrap_os.path.abspath(
        _bootstrap_os.path.expanduser(_configured_extension_dir)
    ))
try:
    _frame_filename = _bootstrap_sys._getframe(0).f_code.co_filename
    if _frame_filename and not _frame_filename.startswith("<"):
        _loader_candidates.append(_bootstrap_os.path.dirname(
            _bootstrap_os.path.abspath(_frame_filename)
        ))
except Exception:
    pass
_loader_candidates.extend(
    _bootstrap_os.path.abspath(path or _bootstrap_os.curdir)
    for path in list(_bootstrap_sys.path)
)
_loader_candidates.append(_bootstrap_os.getcwd())

_extension_candidates = []
for _candidate in _loader_candidates:
    for _module_candidate in (
            _bootstrap_os.path.join(_candidate, "src"),
            _bootstrap_os.path.join(_candidate, "burp", "src"),
            _candidate):
        if _module_candidate not in _extension_candidates:
            _extension_candidates.append(_module_candidate)

_extension_directory = ""
for _candidate in _extension_candidates:
    if _bootstrap_os.path.isfile(
            _bootstrap_os.path.join(_candidate, "double_agent_prelude.py")):
        _extension_directory = _candidate
        break
if not _extension_directory:
    raise ImportError(
        "DoubleAgent modules were not found. Keep DoubleAgent.py beside the "
        "src folder, or set DOUBLE_AGENT_EXTENSION_DIR to burp or burp/src."
    )
if _extension_directory not in _bootstrap_sys.path:
    _bootstrap_sys.path.insert(0, _extension_directory)

# Burp reloads an extension inside the SAME Jython interpreter, so sibling
# modules imported below stay cached in sys.modules and source edits are silently
# ignored on reload. Drop them first so every (re)load re-reads current source.
for _cached_name in list(_bootstrap_sys.modules):
    _root = _cached_name.split(".")[0]
    if _root.startswith("double_agent") or _root == "jev_duplicate_review":
        del _bootstrap_sys.modules[_cached_name]

from double_agent_prelude import *
from double_agent_prelude import _BurpExtenderBase
from double_agent_api import AgentAPIHandler
from double_agent_ui import *
from double_agent_extender_part1 import BurpExtenderChunk1
from double_agent_extender_part1_chunk2 import BurpExtenderChunk1Chunk2
from double_agent_extender_part1_chunk3 import BurpExtenderChunk1Chunk3
from double_agent_extender_part2 import BurpExtenderChunk2
from double_agent_extender_part2_chunk2 import BurpExtenderChunk2Chunk2
from double_agent_extender_part2_chunk3 import BurpExtenderChunk2Chunk3
from double_agent_extender_part3 import BurpExtenderChunk3
from double_agent_extender_part3_chunk2 import BurpExtenderChunk3Chunk2
from double_agent_extender_part3_chunk3 import BurpExtenderChunk3Chunk3
from double_agent_extender_part4 import BurpExtenderChunk4
from double_agent_extender_part4_chunk2 import BurpExtenderChunk4Chunk2
from double_agent_extender_part4_chunk3 import BurpExtenderChunk4Chunk3
from double_agent_extender_part5 import BurpExtenderChunk5
from double_agent_extender_part5_chunk2 import BurpExtenderChunk5Chunk2
from double_agent_extender_part6 import BurpExtenderChunk6
from double_agent_extender_part6_chunk2 import BurpExtenderChunk6Chunk2
from double_agent_extender_part6_chunk3 import BurpExtenderChunk6Chunk3
from double_agent_extender_part7 import BurpExtenderChunk7
from double_agent_jev import JevReviewMixin


class BurpExtender(
        BurpExtenderChunk1, BurpExtenderChunk1Chunk2,
        BurpExtenderChunk1Chunk3, BurpExtenderChunk2,
        BurpExtenderChunk2Chunk2, BurpExtenderChunk2Chunk3,
        BurpExtenderChunk3, BurpExtenderChunk3Chunk2,
        BurpExtenderChunk3Chunk3, BurpExtenderChunk4,
        BurpExtenderChunk4Chunk2, BurpExtenderChunk4Chunk3,
        BurpExtenderChunk5, BurpExtenderChunk5Chunk2,
        BurpExtenderChunk6, BurpExtenderChunk6Chunk2,
        BurpExtenderChunk6Chunk3, BurpExtenderChunk7,
        JevReviewMixin, RemoteReportingMixin, _BurpExtenderBase):
    """Double Agent Burp entry point."""

    # Burp's Jython loader checks for this method on the entry class itself.
    # Keep the implementation in the chunk, but expose a tiny direct wrapper
    # so the loader recognizes the extension.
    def registerExtenderCallbacks(self, callbacks):
        return BurpExtenderChunk1Chunk2.registerExtenderCallbacks(self, callbacks)
