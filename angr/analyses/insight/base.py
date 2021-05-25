from typing import TYPE_CHECKING

from ..analysis import Analysis

if TYPE_CHECKING:
    from angr.knowledge_plugins.cfg import CFGModel


class InsightBase(Analysis):
    DESCRIPTION = None

    def __init__(self, cfg=None):
        super().__init__()

        self.cfg: 'CFGModel' = cfg
