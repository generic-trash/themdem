from .base_pass import *


class CombinePass(BasePass):
    def __init__(self, md, ks, passes=[]):
        super().__init__(md, ks)
        self.passes = [optpass if isinstance(optpass, BasePass) else optpass(md, ks) for optpass in passes]

    def __call__(self, insns, profile=False, profile_sub=False):
        start = len(insns)
        for optpass in self.passes:
            insns = optpass(insns, profile=profile_sub, profile_sub=profile_sub)
        end = len(insns)
        if profile:
            print("Reduction by combined pass is", start - end)

        return insns