import idaapi
import idautils
import idc
import networkx as nx
import matplotlib.pyplot as plt

def get_callers(func_ea):
    callers = []
    for ref in idautils.CodeRefsTo(func_ea, 0):
        func_name = idc.get_func_name(ref)
        if func_name not in callers:
            callers.append(func_name)
    return callers

def get_callees(func_ea):
    callees = []
    for head in idautils.FuncItems(func_ea):
        if idc.print_insn_mnem(head) == "call":
            callee = idc.get_operand_value(head, 0)
            func_name = idc.get_func_name(callee)
            if func_name not in callees:
                callees.append(func_name)
    return callees

def analyze_function(func_name, graph):
    func_ea = idc.get_name_ea_simple(func_name)
    if func_ea == idc.BADADDR:
        print(f"Function {func_name} not found!")
        return

    callers = get_callers(func_ea)
    callees = get_callees(func_ea)

    for caller in callers:
        graph.add_edge(caller, func_name)

    for callee in callees:
        graph.add_edge(func_name, callee)

def visualize_call_graph(graph):
    plt.figure(figsize=(12, 12))
    pos = nx.spring_layout(graph, k=0.5)
    nx.draw(graph, pos, with_labels=True, node_size=3000, node_color='skyblue', font_size=10, font_weight='bold', edge_color='gray')
    plt.title("Function Call Graph")
    plt.show()

def main():
    function_name = "sub_10079651C"
    call_graph = nx.DiGraph()

    analyze_function(function_name, call_graph)
 
    functions_to_analyze = list(call_graph.nodes)
    for func in functions_to_analyze:
        analyze_function(func, call_graph)

    
    visualize_call_graph(call_graph)

if __name__ == "__main__":
    main()
    
    
    
    
    
    # تم تحسينه وتعديله بواسطه Mataz_4@ من قبل ai تجربه
    
