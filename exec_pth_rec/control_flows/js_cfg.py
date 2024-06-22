import networkx as nx
import subprocess
import pydot
import js2py
import time
import configs.analysis_config as config

class JSCFGGenerator:
    def __init__(self):
        self.script_path = config.JSCFG_SCRIPT
        
    def generate_cfg(self, js_path):
        start_time = time.time()
        cfg = None
        
        try:
            with open(js_path) as f:
                source = f.read()

            # Generate control flow graph
            result = subprocess.run(['node', self.script_path, source], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            dot_graph = result.stdout
            dot_graph = "digraph {\n"+dot_graph.strip()+"\n}"
            
            P = pydot.graph_from_dot_data(dot_graph)
            if P:
                P = P[0]

            # Convert to a NetworkX graph
            cfg = nx.nx_pydot.from_pydot(P) if P else None
    
            if cfg:
                cfg = nx.MultiDiGraph(cfg)

        except Exception as e:
            print(f"An error occurred: {e}")
            

        finally:
            end_time = time.time()
            duration = end_time - start_time
            return cfg, duration


    def generate_cfg_jsfromhtml(self, func_dict):
        start_time = time.time()
        cfg = None
        
        try:
            source = ""
            for funcname in func_dict:
                source = source + func_dict[funcname]['code'] + "\n"
            
            # Generate control flow graph
            result = subprocess.run(['node', self.script_path, source], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
            dot_graph = result.stdout
            dot_graph = "digraph {\n"+dot_graph.strip()+"\n}"
            
            P = pydot.graph_from_dot_data(dot_graph)
            if P:
                P = P[0]

            # Convert to a NetworkX graph
            cfg = nx.nx_pydot.from_pydot(P) if P else None
            
            if cfg:
                cfg = nx.MultiDiGraph(cfg)

        except Exception as e:
            print(f"An error occurred: {e}")
            

        finally:
            end_time = time.time()
            duration = end_time - start_time
            return cfg, duration

    def get_entry_node(self, cfg):
        for node in cfg.nodes():
            if cfg.in_degree(node) == 0:
                return node
        return None

    def get_exit_node(self, cfg):
        for node in cfg.nodes():
            if len(list(cfg.successors(node))) == 0:
                return node
        return None

    def get_node_by_str(self, cfg, str):
        node_list = []
        for node in cfg.nodes(data=True):
            if str in node[1]['label']:
                node_list.append(node[0])
    
        return node_list
