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
from .sandwich_arithmetic_pass_2 import *
from .indirect_xchg_pass_3 import *
from .push_esp_pass import *
from .sandwich_arithmetic_pass_3 import *
from .stack_neg_pass import *
from .double_xchg_pass import *
from .stack_neg_pass_2 import *
from .lea_create_pass import *
from .dead_store_elimination_pass import *
from .fuse_lea_pass import *
from .sandwich_arithmetic_pass_stack import *
class AllPass(ZeroPass):
    def __init__(self, md, ks):
        super().__init__(md, ks, CombinePass(md, ks, [
            IndirectPushPass,
            IndirectPushEspPass,
            IndirectPopPass,
            IndirectStackMovePass,
            IndirectMovPass,
            StackNegPass,
            StackNegPassLarge,
            ConstantPropagationPass,
            PopEspPass,
            IndirectXchgPassStack,
            IndirectXchgPass,
            DoubleXchgPass,
            SandwichArithmeticPass,
            SandwichArithmeticPass2,
            SandwichArithmeticPassStack,
            SandwichArithmeticPassStack2,
            IndirectSpAddPass,
            IndirectSpSubPass,
            IndirectXchgPassStackLarge,
            LeaCreatePass,
            FuseLeaPass,
            DSEPass
        ]))
