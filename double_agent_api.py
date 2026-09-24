# -*- coding: utf-8 -*-
from double_agent_prelude import *
from double_agent_api_part1 import AgentAPIChunk1
from double_agent_api_part1_chunk2 import AgentAPIChunk1Chunk2
from double_agent_api_part1_chunk3 import AgentAPIChunk1Chunk3
from double_agent_api_part1_chunk4 import AgentAPIChunk1Chunk4
from double_agent_api_part2 import AgentAPIChunk2
from double_agent_api_part2_chunk2 import AgentAPIChunk2Chunk2
from double_agent_api_part2_chunk3 import AgentAPIChunk2Chunk3
from double_agent_api_part3 import AgentAPIChunk3
from double_agent_api_part3_chunk2 import AgentAPIChunk3Chunk2
from double_agent_api_part3_chunk3 import AgentAPIChunk3Chunk3
from double_agent_api_part4 import AgentAPIChunk4
from double_agent_api_part4_chunk2 import AgentAPIChunk4Chunk2


class AgentAPIHandler(
        AgentAPIChunk1, AgentAPIChunk1Chunk2, AgentAPIChunk1Chunk3,
        AgentAPIChunk1Chunk4, AgentAPIChunk2, AgentAPIChunk2Chunk2,
        AgentAPIChunk2Chunk3, AgentAPIChunk3, AgentAPIChunk3Chunk2,
        AgentAPIChunk3Chunk3, AgentAPIChunk4, AgentAPIChunk4Chunk2,
        AgentScannerCampaignMixin, AgentCoverageOverwatchMixin,
        BaseHTTPRequestHandler):
    """Loopback API used by Agent B and other authorized local harnesses."""
    pass
