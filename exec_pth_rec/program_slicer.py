import pickle
import networkx as nx
import configs.analysis_config as config
import os


class ProgramSlicer:
    """
    Input: cfg, the starting node of the first program, the reboot node of the last program
    Output: a list of program slices
    """
    def __init__(self):
        self.cfg_dict = {}
        self.paths = {}

    # there may be more than one ufg, we need to slice each ufg
    def slice(self, ufg, entry_node, target_nodes):
        for target in target_nodes:
            source = entry_node
            all_paths = list(nx.all_simple_paths(ufg, source, target))
            if not all_paths:
                all_paths = self.find_paths(ufg, target)
                source = 'Non-entry'
                if not all_paths:
                    continue
  
            self.paths[str(source)+":"+str(target)] = []
            for path in all_paths:
                path_dict = {}
                path_dict['path'] = path
                path_dict['funcs'] = {}
            
                for node in path:
                    program = ufg.nodes[node]['program']
                    program_type = ufg.nodes[node]['type']
                    
                    if program_type == "elf":
                        if program in self.cfg_dict:
                            cfg = self.cfg_dict[program]
                        else:
                            program_name = program.split("/")[-1]
                            cfg_path = os.path.join(config.UFG_RESULTS, program_name+".pkl" )
                            with open(cfg_path, 'rb') as f:
                                cfg = pickle.load(f)

                        if program not in path_dict['funcs']:
                            path_dict['funcs'][program] = []
                        
                        path_dict['funcs'][program].append(cfg.kb.functions[node])    
                        
                self.paths[str(source)+":"+str(target)].append(path_dict)
                
        return self.paths

    def path_dfs(self, ufg, node, target_node, path, paths):
        path.append(node)
        
        if node == target_node:
            is_subset = any(set(path).issubset(set(p)) for p in paths)
            is_superset = any(set(p).issubset(set(path)) for p in paths)
            
            if not is_subset:
                if is_superset:
                    paths[:] = [p for p in paths if not set(p).issubset(set(path))]
                paths.append(list(path))
        else:
            for next_node in ufg.successors(node):
                if next_node not in path:
                    self.path_dfs(ufg, next_node, target_node, path, paths)

        path.pop()

    def find_paths(self, ufg, target_node):
        paths = []
        for node in ufg.nodes():
            if node != target_node:
                self.path_dfs(ufg, node, target_node, [], paths)

        return paths

    def print_paths(self, paths):
        for target, paths in paths.items():
            print(target)
            for path in paths:
                print(path)
            
    def read_ufgs(self):
        ufgs = []
        for ufg_file in os.listdir(config.UFG_RESULTS):
            ufg_path = os.path.join(config.UFG_RESULTS, ufg_file)
            with open(ufg_path, 'rb') as f:
                ufg = pickle.load(f)
                ufgs.append(ufg)
        return ufgs
            
# Function to print edges for a node
def print_edges_of_node(graph, node):
    if node in graph:
        print(f"Edges connected to node {node}:")
        for neighbor in graph[node]:
            edge_info = graph[node][neighbor]
            print(f"  {node} -- {neighbor} with attributes: {edge_info}")
    else:
        print(f"Node {node} is not in the graph.")
