import ida_graph
import ida_hexrays as hr
import ida_kernwin as kw
from ida_hexrays import mblock_t, mop_t, optblock_t, minsn_visitor_t, mbl_array_t,mop_n

import ida_lines
import re
from typing import List, Tuple
FLATTENING_JUMP_OPCODES = [hr.m_jnz, hr.m_jz, hr.m_jae, hr.m_jb, hr.m_ja, hr.m_jbe,hr.m_jg, hr.m_jge, hr.m_jl, hr.m_jle]


def graphviz(mba,output_path):
    from graphviz import Digraph
    dot = Digraph()
    dot.attr(splines='ortho')
    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        if blk.head == None:
            continue
        lines = []

        lines.append("{0}:{1}".format(blk_idx, hex(blk.head.ea)))
        insn = blk.head
        while insn:
            lines.append(insn.dstr())
            if insn == blk.tail:
                break
            insn = insn.next
        label = "\n".join(lines)
        dot.node(str(blk_idx), label=label, shape="rect", style="filled", fillcolor="lightblue")

    for blk_idx in range(mba.qty):
        blk = mba.get_mblock(blk_idx)
        succset = [x for x in blk.succset]
        for succ in succset:
            blk_succ = mba.get_mblock(succ)
            if blk_succ.head is None:
                continue
            if blk.head is None:
                continue
            dot.edge(str(blk_idx), str(succ))

    # dot.render("/home/chic/graph_with_contentgraph_with_content", format="png")
    with open(output_path, "w") as f:
        f.write(dot.source)
    # dot.render("/home/chic/graph_with_content", format="png")
    print("dot已保存到 :",output_path)



def extract_num_mop(ins: hr.minsn_t) -> Tuple[mop_t, mop_t]:
    num_mop = None
    other_mop = None

    if ins.l.t == mop_n:
        num_mop = ins.l
        other_mop = ins.r
    if ins.r.t == mop_n:
        num_mop = ins.r
        other_mop = ins.l
    return [num_mop, other_mop]

def get_comparison_info(blk: hr.mblock_t) -> Tuple[hr.mop_t, mop_t]:
    # We check if blk is a good candidate for dispatcher entry block: blk.tail must be a conditional branch
    if (blk.tail is None) or (blk.tail.opcode not in FLATTENING_JUMP_OPCODES):
        return None, None
    # One operand must be numerical
    num_mop, mop_compared = extract_num_mop(blk.tail)
    if num_mop is None or mop_compared is None:
        return None, None
    return num_mop, mop_compared



def dominanceFlow(mba,dispatch_block):
    from d810.optimizers.flow.flattening.generic import GenericDispatcherBlockInfo
    from d810.tracker import MopHistory, MopTracker
    from d810.optimizers.flow.flattening.utils import NotResolvableFatherException, get_all_possibles_values
    # import pydevd_pycharm
    # pydevd_pycharm.settrace('localhost', port=31235, stdoutToServer=True, stderrToServer=True)

    print("dispatch_block serial:",hex(dispatch_block.serial))
    blk_preset_list = [x for x in dispatch_block.predset]
    print("dispatch_block father list:",blk_preset_list)

    def dfs( current_node, target_node, path, paths, visited):
        path.append(current_node.serial)
        visited.add(current_node.serial)

        for neighbor in current_node.succs():
            if neighbor.serial == target_node.serial and len(path) > 1:
                paths.append(list(path))
            elif neighbor.serial not in visited:
                dfs(neighbor, target_node, path, paths, visited)

        path.pop()
        visited.remove(current_node.serial)
    paths = []

    dfs(dispatch_block,dispatch_block,[],paths,set())
    entry_block = GenericDispatcherBlockInfo(dispatch_block)
    #  初始化ud链，如果不想用GenericDispatcherBlockInfo，自己写初始化就可以了，然后直接使用ud链传入
    entry_block.parse()
    num_mop, mop_compared = get_comparison_info(entry_block.blk)
    # father_tracker.reset()

    for dispatcher_father_serial in dispatch_block.predset:
        father_tracker = MopTracker(entry_block.use_before_def_list, max_nb_block=100, max_path=100)
        father_tracker.reset()
        print("----current father: {0} ----------".format(dispatcher_father_serial))
        dispatcher_father_block = mba.get_mblock(dispatcher_father_serial)
        father_histories = father_tracker.search_backward(dispatcher_father_block, None)
        father_histories_cst = get_all_possibles_values(father_histories, entry_block.use_before_def_list,verbose=False)
        Const_Hex_str=""
        for list1 in father_histories_cst:
            for print_const in list1:
                Const_Hex_str =  Const_Hex_str+hex(print_const)+":"
        print(Const_Hex_str)

    for path in paths:
        print("path:",path)






class microcode_graphviewer_t(ida_graph.GraphViewer):
    """Displays the graph view of Hex-Rays microcode."""

    def __init__(self, mba, title, lines):
        title = "Microcode graph: %s" % title
        ida_graph.GraphViewer.__init__(self, title, True)
        self._mba = mba
        self._mba.set_mba_flags(hr.MBA_SHORT)
        self._process_lines(lines)
        if mba.maturity == hr.MMAT_GENERATED or mba.maturity == hr.MMAT_PREOPTIMIZED:
            mba.build_graph()

    def _process_lines(self, lines):
        self._blockcmts = {}
        curblk = "-1"
        self._blockcmts[curblk] = []
        for i, line in enumerate(lines):
            plain_line = ida_lines.tag_remove(line).lstrip()
            if plain_line.startswith(';'):
                # msg("%s" % plain_line)
                re_ret = re.findall("BLOCK ([0-9]+) ", plain_line)
                if len(re_ret) > 0:
                    curblk = re_ret[0]
                    self._blockcmts[curblk] = [line]
                else:
                    self._blockcmts[curblk].append(line)
        if "0" in self._blockcmts:
            self._blockcmts["0"] = self._blockcmts["-1"] + self._blockcmts["0"]
        del self._blockcmts["-1"]

    def OnRefresh(self):
        self.Clear()
        qty = self._mba.qty
        for src in range(qty):
            self.AddNode(src)
        for src in range(qty):
            mblock = self._mba.get_mblock(src)
            for dest in mblock.succset:
                self.AddEdge(src, dest)
        return True

    def OnGetText(self, node):
        mblock = self._mba.get_mblock(node)
        vp = hr.qstring_printer_t(None, True)
        mblock._print(vp)

        node_key = "%d" % node
        if node_key in self._blockcmts:
            return ''.join(self._blockcmts[node_key]) + vp.s
        else:
            return vp.s




class dominance_graphviewer_t(microcode_graphviewer_t):

    def __init__(self, *args):
        microcode_graphviewer_t.__init__(self, *args)
        self.dom_command_id = self.AddCommand("Show Dominance Graph", "D")
        self.full_command_id = self.AddCommand("Show Full Graph", "F")
        self.back_command_id = self.AddCommand("Show Previous Graph", "P")
        self.save_graphviz_id = self.AddCommand("save Graph to graphviz ", "S")
        self.show_dom_log_id = self.AddCommand("show current Dominance log ", "A")
        self.state = "cfg"
        self.back_stack = []
        self.select_block = None
        self.select_node = -1
        self.dom = {}

        self.compute_dominates()

    def OnCommand(self, cmd_id):
        if self.select_node != -1:
            node = self[self.select_node]
            if isinstance(node, hr.mblock_t):
                self.select_block = node
            elif isinstance(node, int):
                self.select_block = self._mba.get_mblock(node)
        if cmd_id == self.dom_command_id and self.select_node != -1:
            self.state = "dom"
            self.Refresh()
            self.Select(self.select_node)
            self.back_stack.append(self.select_block.serial)
        elif cmd_id == self.full_command_id:
            self.state = "cfg"
            last_select = self.select_block.serial if self.select_block else -1
            self.select_node = -1
            self.select_block = None
            self.Refresh()
            if last_select >= 0:
                self.Select(last_select)
        elif cmd_id == self.back_command_id and len(self.back_stack) > 0:
            self.back_stack.pop()
            if not self.back_stack:
                return self.OnCommand(self.full_command_id)
            else:
                serial = self.back_stack[-1]
                self.select_block = self._mba.get_mblock(serial)
                self.state = "dom"
                self.Refresh()
                self.Select(self.select_node)
        elif cmd_id == self.show_dom_log_id:
            dominanceFlow(self._mba,self.select_block)
        elif cmd_id == self.save_graphviz_id:
            file_path = kw.ask_file(True, "*.dot", "Please select a file")
            if file_path:
                kw.msg("Selected file: {}\n".format(file_path))
                graphviz(self._mba,file_path)
            else:
                kw.msg("No file selected\n")
            print("save_graphviz_id")

    def OnClick(self, node_id):
        self.select_node = node_id
        return True

    def compute_dominates(self):
        nodes = set(list(range(self._mba.qty)))
        self.dom = {}
        for node in nodes:
            self.dom[node] = set(nodes)

        self.dom[0] = set([0])
        todo = set(nodes)

        while todo:
            node = todo.pop()

            if node == 0:
                continue

            new_dom = None
            mblock = self._mba.get_mblock(node)
            for pred in mblock.predset:
                if not pred in nodes:
                    continue

                if new_dom is None:
                    new_dom = set(self.dom[pred])
                new_dom &= self.dom[pred]
            if new_dom is None:
                new_dom = set([node])
            else:
                new_dom |= set([node])

            if new_dom == self.dom[node]:
                continue

            self.dom[node] = new_dom
            for succ in mblock.succset:
                todo.add(succ)

    def _get_dominates(self, blk):
        result = []
        for dom in self.dom:
            if blk.serial in self.dom[dom]:
                result.append(self._mba.get_mblock(dom))
        return result

    def OnRefresh(self):
        if self.state == "dom" and self.select_block:
            self.Clear()
            node_ids = {}
            dominates = self._get_dominates(self.select_block)
            for block in dominates:
                node_id = self.AddNode(block)
                if block.serial == self.select_block.serial:
                    self.select_node = node_id
                node_ids[block.serial] = node_id
            for block in dominates:
                for dest in block.succset:
                    if dest in node_ids:
                        self.AddEdge(node_ids[block.serial], node_ids[dest])
            return True
        return microcode_graphviewer_t.OnRefresh(self)

    def OnGetText(self, node_id):
        if isinstance(self[node_id], hr.mblock_t):
            node_id = self[node_id].serial
        return microcode_graphviewer_t.OnGetText(self, node_id)


class printer_t(hr.vd_printer_t):
    """Converts microcode output to an array of strings."""

    def __init__(self, *args):
        hr.vd_printer_t.__init__(self)
        self.mc = []

    def get_mc(self):
        return self.mc

    def _print(self, indent, line):    # 被动调用，一行行的传入microcode反编译结果
        self.mc.append(line)
        return 1


def show_microcode_graph(mba,fn_name,lines=None):
    if lines == None:
        vp = printer_t()
        mba.set_mba_flags(mba.get_mba_flags())
        mba._print(vp)
        g = dominance_graphviewer_t(mba, fn_name, vp.get_mc())
        if g:
            g.Show()
        return g
    else:
        g = dominance_graphviewer_t(mba, fn_name, lines)
        if g:
            g.Show()
        return g

