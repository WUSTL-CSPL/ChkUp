from collections import OrderedDict

class Node:
    def __init__(self, prenode, filepath, filetype, way, keywords={}):
        self.caller = prenode
        self.path = filepath
        self.filetype = filetype
        self.callway = way
        self.calls = []
        self.keywords = keywords
        self.functions = {
            'checksum': [],
            'device': [],
            'version': [],
            'signature': [],
            'write': [],
            'reboot': [],
            'delivery': []
        }
        
    # when reaching the reboot node, use this function to print the full path
    def get_path(self):
        reverse_path = []
        reverse_path.append(self)
        node = self.caller
        while node != None:
            reverse_path.append(node)
            node = node.caller
        
        reverse_path.reverse()

        update_path = OrderedDict()
        for node in reverse_path:
            update_path[node.path] = OrderedDict()
            update_path[node.path]['filetype'] = node.filetype
            if node.caller:
                update_path[node.path]['caller'] = node.caller.path
            else:
                update_path[node.path]['caller'] = ''
            if node.callway:
                update_path[node.path]['callway'] = node.callway
            else:
                update_path[node.path]['callway'] = ''
            if node.calls:
                update_path[node.path]['callee'] = [callnode.path for callnode in node.calls]
            else:
                update_path[node.path]['callee'] = []
            if node.keywords:
                update_path[node.path]['keywords'] = OrderedDict(node.keywords)
            else:
                update_path[node.path]['keywords'] = OrderedDict()
            update_path[node.path]['function'] = node.functions
        
        return update_path, reverse_path[0]
