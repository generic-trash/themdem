from .indirect_push_pass import *
from .combine_pass import *
from .zero_pass import *
from .indirect_stack_move_pass import *
from .pop_esp_pass import *
from .indirect_sp_add_pass import *
from .indirect_sp_sub_pass import *
from .sandwich_arithmetic_pass import *
from .indirect_pop_pass import *
from .constant_propagation import *
from .indirect_xchg_pass_1 import *
from .indirect_mov_pass import *
from .indirect_xchg_pass_2 import *

class AllPass(ZeroPass):
    def __init__(self, md, ks):
        super().__init__(md, ks, CombinePass(md, ks, [
            IndirectPushPass,
            IndirectPopPass,
            IndirectStackMovePass,
            IndirectMovPass,
            ConstantPropagationPass,
            PopEspPass,
            IndirectXchgPassStack,
            SandwichArithmeticPass,
            IndirectSpAddPass,
            IndirectSpSubPass,
            IndirectXchgPassStackLarge
        ]))
