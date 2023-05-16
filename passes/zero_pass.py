from .base_pass import *


class ZeroPass(BasePass):
    def __init__(self, md, ks, optpass):
        super().__init__(md, ks)
        self.optpass = optpass if isinstance(optpass, BasePass) else optpass(md, ks)

    def __call__(self, insns, profile=False, profile_sub=False):
        reduction = 100
        start = len(insns)
        while reduction != 0:
            beforeloop = len(insns)
            insns = self.optpass(insns, profile=profile_sub, profile_sub=profile_sub)
            afterloop = len(insns)
            reduction = beforeloop - afterloop
        end = len(insns)
        if profile:
            print("Reduction by zero pass is", start - end)
        return insns
