'''
Created on 2015.8.27

@author: shengrulee
'''

from digraph import *
import copy
adjacency = defaultdict(lambda: defaultdict(lambda: None))
# 14 node nsfnet
adjacency[1][2] = (3, 0, 1050)
adjacency[2][1] = (3, 22, 1050)
adjacency[1][3] = (1, 2, 1500)
adjacency[3][1] = (1, 24, 1500)
adjacency[1][8] = (2, 3, 2400)
adjacency[8][1] = (2, 25, 2400)
adjacency[2][3] = (1, 1, 600)
adjacency[3][2] = (2, 23, 600)
adjacency[2][4] = (2, 4, 750)
adjacency[4][2] = (1, 26, 750)
adjacency[3][6] = (3, 5, 1800)
adjacency[6][3] = (4, 27, 1800)
adjacency[4][5] = (2, 6, 600)
adjacency[5][4] = (2, 28, 600)
adjacency[4][11] = (3, 7, 1950)
adjacency[11][4] = (3, 29, 1950)
adjacency[5][6] = (1, 8, 1200)
adjacency[6][5] = (3, 30, 1200)
adjacency[5][7] = (3, 9, 600)
adjacency[7][5] = (3, 31, 600)
adjacency[6][10] = (1, 10, 1050)
adjacency[10][6] = (3, 32, 1050)
adjacency[6][14] = (2, 11, 1800)
adjacency[14][6] = (1, 33, 1800)
adjacency[7][8] = (1, 12, 750)
adjacency[8][7] = (1, 34, 750)
adjacency[7][10] = (2, 13, 1350)
adjacency[10][7] = (2, 35, 1350)
adjacency[8][9] = (3, 14, 750)
adjacency[9][8] = (1, 36, 750)
adjacency[9][10] = (2, 15, 750)
adjacency[10][9] = (1, 37, 750)
adjacency[9][12] = (3, 16, 300)
adjacency[12][9] = (2, 38, 300)
adjacency[9][13] = (4, 17, 300)
adjacency[13][9] = (3, 39, 300)
adjacency[11][12] = (2, 18, 600)
adjacency[12][11] = (3, 40, 600)
adjacency[11][13] = (1, 19, 750)
adjacency[13][11] = (1, 41, 750)
adjacency[12][14] = (1, 20, 300)
adjacency[14][12] = (3, 42, 300)
adjacency[13][14] = (2, 21, 150)
adjacency[14][13] = (2, 43, 150)

adjacency[1][1] = (4, 44, 0)
adjacency[2][2] = (4, 45, 0)
adjacency[3][3] = (4, 46, 0)
adjacency[4][4] = (4, 47, 0)
adjacency[5][5] = (4, 48, 0)
adjacency[6][6] = (5, 49, 0)
adjacency[7][7] = (4, 50, 0)
adjacency[8][8] = (4, 51, 0)
adjacency[9][9] = (5, 52, 0)
adjacency[10][10] = (4, 53, 0)
adjacency[11][11] = (4, 54, 0)
adjacency[12][12] = (4, 55, 0)
adjacency[13][13] = (4, 56, 0)
adjacency[14][14] = (4, 57, 0)

tree_adj =defaultdict(lambda: defaultdict(lambda: None))
tree_adj[1][2] = 2
tree_adj[2][3] = 4
tree_adj[2][4] = 2
tree_adj[2][5] = 1
tree_adj[5][9] = 4
tree_adj[5][10] = 2
tree_adj[10][11] = 1
tree_adj[4][7] = 2
tree_adj[3][6] = 3
tree_adj[6][16] = 3 

def cut_branch(tree_adj, node):
    if node in topo_adj.keys():
        while tree_adj[node] in tree_adj.keys():
            node = tree_adj[node]
            del tree_adj[node]
    else:
        print "this node is not in this tree"
    

def findSplittingNodesOnPath(split_nodes, path):
    nodes_on_path = []
    for each_node in split_nodes:
        if each_node in path:
            nodes_on_path.append(each_node)
            
    return nodes_on_path

def findSplittingNodesInTree(adj, dsts):
    splitting_nodes = []
    for each in adj.keys():
        if len(adj[each]) > 1:
            # spliting node
            splitting_nodes.append(each)
        elif len(adj[each]) == 1:
            if each in dsts:
                splitting_nodes.append(each)

    return splitting_nodes


def toMulticastPathList(tree, src, dsts):
    path_dict = defaultdict(lambda:[])
    shortestleafpath = findShortestLeafNode(tree, src, dsts)
    split_nodes = findSplittingNodesInTree(tree, dsts)
    path_dict[src].append(shortestleafpath)
    for node in split_nodes:
        if node in shortestleafpath:
            for _ in range(len(tree[node].keys())-1):
                i = shortestleafpath.index(node)
                del tree[shortestleafpath[i]][shortestleafpath[i+1]]
                shortestleafpath = findShortestLeafNode(tree, node, dsts)
                path_dict[node].append(shortestleafpath)
        else:
            for _ in range(len(tree[node].keys())):
                shortestleafpath = findShortestLeafNode(tree, node, dsts)
                path_dict[node].append(shortestleafpath)
 
    return path_dict
    
def vportReplace(path_dict, path_port_dict, src, vport):
    fork_node_list = path_dict.keys()
    fork_node_list.remove(src)
    for each_fork_node in path_dict.keys():
        for path in path_dict[each_fork_node]:
            j = path_dict[each_fork_node].index(path)
            for node in path:
#                print node
                if node in fork_node_list:
                    i = path.index(node)
                    path_port_dict[each_fork_node][j][i] = vport
    return path_dict
    
def toMulticastPathPortDict(path_dict, adj, vport):
    fork_node_list = path_dict.keys()
    fork_node_list.remove(src)
    path_port_dict = {}
    fork_node_output_dict = {}
    for encap_node in path_dict.keys():
        path_port_list = []
        for path in path_dict[encap_node]:
            port_list = []
            for i in range(len(path)-1):
                if path[i] not in fork_node_list:
                    port = adj[path[i]][path[i+1]]
                else:
                    port = vport
                    fork_node_output_dict[path[i]]=adj[path[i]][path[i+1]]
                port_list.append(port)
            path_port_list.append(port_list)
        path_port_dict[encap_node] = path_port_list
    return path_port_dict, fork_node_output_dict
    


src = 1
dsts = [6,7,9,11,16]
vport = 1
tree = copy.deepcopy(tree_adj)

print findSplittingNodesInTree(tree, dsts)
path_dict =  toMulticastPathList(tree, 1, dsts)
print path_dict
path_port_dict = toMulticastPathPortDict(path_dict, tree_adj, vport)
print path_port_dict
#print vportReplace(path_dict, path_port_dict, src, vport)
PORT_FIELD_LEN = 16  # bit

def cal_offset_on_fork(path_dict, path_port_dict):
    offset_dict = {}
    for fork_node in path_dict.keys()[1:]:
        print fork_node
        offset_dict[fork_node] = []
        for node in path_dict.keys():
            for path in path_dict[node]:
                if fork_node in path[1:]:
                    i = path.index(fork_node)
                    offset = PORT_FIELD_LEN * (len(path)-i)
                    offset_dict[fork_node].append(offset)
    return offset_dict
                    
        
print cal_offset_on_fork(path_dict, path_port_dict)

def cal_pri_output_on_forknode(path_dict, path_port_dict):
    pri_port_dict = {}
    for fork_node in path_dict.keys():
        for path in path_dict[fork_node]:
            for node in path[1:]:
                if node in path_dict.keys():
                    i= path.index(node)
                    if i < len(path)-1:
                        pri_port_dict[node] = tree_adj[path[i]][path[i+1]]
#                   try:
#                       pri_port_dict[node] = tree_adj[path[i]][path[i+1]]
#                   except:                    
#                       pri_port_dict[node] = None
    return pri_port_dict
    
#print cal_pri_output_on_forknode(path_dict, path_port_dict)
print cal_pri_output_on_forknode(path_dict, path_port_dict)

import random
def gen_dpid_group():
    group_size = random.randint(2,3)
    print group_size
    return random.sample(adjacency.keys(), group_size)
    
print gen_dpid_group()


abc = [1,2,3]
ab = abc
ab.append(5)
print abc
