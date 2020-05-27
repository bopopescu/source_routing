"""
@author: Shengru Li, USTC

This module includes some directed graph data structrues and MST, Dijkstra and Minimum Steiner Tree approximate algorithms.
"""
from collections import defaultdict
from Queue import PriorityQueue
import copy


def C(r, n):  # return a combinatorial number
    return reduce(lambda x, y: x * y, range(n - r + 1, n + 1)) / reduce(lambda x, y: x * y, range(1, r + 1))


class EnhancedPQ(PriorityQueue):
    '''
    Add two new functions: contain() and change(),
    contain() is used to check whether the value is in the priority queue,
    change() is used to change the priority of the value.
    '''

    def contain(self, value):  # check whether the value is in the queue
        value_list = []
        for each_value in self.queue:
            value_list.append(each_value[1])
        if value in value_list:
            return True
        else:
            return False

    def change(self, value, newPriority):
        valueToPriority_dict = {}
        for each_item in self.queue:
            valueToPriority_dict[each_item[1]] = each_item[0]  # {value:priority}
        if self.contain(value):
            self.queue.remove((valueToPriority_dict[value], value))
            self.put((newPriority, value))
        return


class DirectedEdge(object):
    def __init__(self, v, w, weight):  # v--> w, v is edge source, w is edge target
        self.v = v
        self.w = w
        self.weight = weight

    def edgeFrom(self):
        return self.v

    def edgeTo(self):
        return self.w

    def toString(self):
        directedEdge_string = "%d -> %d: %r" % (self.edgeFrom(), self.edgeTo(), self.weight)
        return directedEdge_string


class EdgeWeightedDigraph(object):
    '''
    This class is used for store a weighted digraph.
    Invoke function addGraph() to add a digraph from a two dimension dictionary type graph.
    '''

    def __init__(self):
        self.adj = defaultdict(lambda: list())  # type of adj is dict
        self.vertex_num = 0
        self.edge_num = 0

    def addGraphFromDict(self, adj_dict):  # add a graph from a dictionary type
        self.adj_dict = adj_dict

        edge_count = 0
        for v in adj_dict.keys():  # v -> w
            adj_edges = []
            for w in adj_dict[v].keys():
                weight = adj_dict[v][w][2]
                edge = DirectedEdge(v, w, weight)
                self.addEdge(edge)
                edge_count += 1

        self.vertex_num = len(self.adj)
        self.edge_num = edge_count
        return

    def addEdge(self, edge_obj):
        v = edge_obj.edgeFrom()
        self.adj[v].append(edge_obj)

    def V(self):
        return self.vertex_num

    def E(self):
        return self.edge_num

    def adjTo(self, v):
        return self.adj[v]

    def edgeWeight(self, v, w):
        return self.adj_dict[v][w][2]

    def printG(self):
        for i in self.adj.keys():
            for j in range(len(self.adj[i])):
                each_edge = self.adj[i][j]
                print "%d -> %d: %r" % (each_edge.edgeFrom(), each_edge.edgeTo(), each_edge.weight)


class DigraphPrimMST(object):

    def __init__(self, G, src):  # G is a EdgeWeightedGraph object
        self.marked = []  # true if v on tree, self.marked[v] = true
        self.pq = PriorityQueue()  # eligible crossing edges
        self.mst = []  # store the edge of self.mst
        self.G = G

        self._visit(self.G, src)

        while (self.pq.empty() == False):
            lowest_weight = self.pq.get()  # it is a tuple
            e = lowest_weight[1]
            v = e.edgeFrom()
            w = e.edgeTo()
            if v in self.marked and w in self.marked:
                continue
            self.mst.append(e)
            if v not in self.marked:
                self._visit(G, v)
            if w not in self.marked:
                self._visit(G, w)

    def _visit(self, G, v):
        self.marked.append(v)
        for e in G.adjTo(v):
            if e not in self.mst:
                self.pq.put((e.weight, e))

    def mstEdge(self):
        return self.mst

    def printG(self):
        print "Minimum Spanning Tree edges :"
        for edge in self.mst:
            print edge.toString()
        return


class DijkstraSP(object):
    def __init__(self, G, src):  # G is a EdgeWeightedGraph object
        self.src = src
        self.edgeTo = {}
        self.distTo = {}
        self.pq = EnhancedPQ()
        self.G = G

        for i in range(G.V()):
            self.distTo[i + 1] = float('Inf')  # index starts from 1
        self.distTo[self.src] = 0

        self.pq.put((0, self.src))

        while (self.pq.empty() == False):
            self._relax(G, self.pq.get())

    def _relax(self, G, v):
        # print v
        v = v[1]
        for e in G.adjTo(v):  # v -> w
            w = e.edgeTo()

            # print "w:",w
            # print self.distTo[w],self.distTo[v],e.weight

            if self.distTo[w] > self.distTo[v] + e.weight:
                self.distTo[w] = self.distTo[v] + e.weight
                self.edgeTo[w] = e
                if self.pq.contain(w):
                    self.pq.change(w, self.distTo[w])
                else:
                    self.pq.put((self.distTo[w], w))
        return

    def pathTo(self, dst):
        current = dst
        path = [dst]
        # while (self.edgeTo[current].edgeFrom() != self.src):
        #     prev = self.edgeTo[current].edgeFrom()
        #     path.append(prev)
        #     current = prev

        try:
            while (self.edgeTo[current].edgeFrom() != self.src):
                prev = self.edgeTo[current].edgeFrom()
                path.append(prev)
                current = prev
        except KeyError:
            pass
            # print 'current', current
            # print '*********************************source*********************************', self.src

        path.append(self.src)
        path.reverse()
        return path, self.distTo[dst]

    def pathToDigraph(self, dst):
        path = self.pathTo(dst)[0]
        path_graph = EdgeWeightedDigraph()
        for i in range(len(path) - 1):
            edge_obj = DirectedEdge(path[i], path[i + 1], self.G.edgeWeight(path[i], path[i + 1]))
            path_graph.addEdge(edge_obj)
        return path_graph  # an EdgeWeightedDigraph object

    def printG(self):
        for j in self.edgeTo.keys():
            print self.edgeTo[j].toString()
        return


class DijkstraAllPairSP(object):
    def __init__(self, G):  # G is a EdgeWeightedGraph object
        self.G = G
        self.all_SPT = {}

        for s in range(self.G.V()):
            self.all_SPT[s + 1] = DijkstraSP(self.G, s + 1)

    def path(self, src, dst):
        return self.all_SPT[src].pathTo(dst)  # return a tuple (path, weight)
        # try:
        #     return self.all_SPT[src].pathTo(dst)  # return a tuple (path, weight)
        # except KeyError:
        #     print 'src', src
        #     print self.all_SPT

    def pathEdge(self, src, dst):
        SP_Edge_list = []
        path = self.path(src, dst)[0]
        for i in range(len(path) - 1):
            edge_obj = DirectedEdge(path[i], path[i + 1], self.G.edgeWeight(path[i], path[i + 1]))
            SP_Edge_list.append(edge_obj)

        return SP_Edge_list  # a list of edge object in the path


class MinSteinerTree(object):
    '''
    This algorithm realization is referring to
    A Fast Algorithm for Steiner Tree
    which is published by L.Kou, G.Markowsky, and L.Berman in 1981
    '''

    def __init__(self, G, src, Dst):  # G is an EdgeWeightedDigraph object
        self.original_graph = G
        self.src = src
        self.Dst = copy.deepcopy(Dst)  # Dst is a list of destination node
        self.dsts = copy.deepcopy(Dst)

        self.SteinerNode = copy.deepcopy(Dst)
        self.SteinerNode.append(src)

        # step 1
        SteinerNode_SPTs = DijkstraAllPairSP(self.original_graph)
        SteinerNode_SP_complete_graph_weight = defaultdict(lambda: defaultdict(lambda: None))

        for i in self.SteinerNode:
            for j in self.SteinerNode:
                if i == j:
                    continue
                else:
                    SteinerNode_SP_complete_graph_weight[i][j] = (0, 0, SteinerNode_SPTs.path(i, j)[1])

        # vertex_num = len(self.SteinerNode)
        # edge_num = C(2,vertex_num)
        SteinerNode_SP_complete_graph = EdgeWeightedDigraph()
        SteinerNode_SP_complete_graph.addGraphFromDict(SteinerNode_SP_complete_graph_weight)
        #print "SteinerNode Shortest Path complete:"
        #SteinerNode_SP_complete_graph.printG()

        # step 2
        SteinerNode_SP_MST = DigraphPrimMST(SteinerNode_SP_complete_graph, src)

        #print "SteinerNode_SP_MST:"
        #SteinerNode_SP_MST.printG()
        # step 3
        # resume the subgraph of the original graph from the SteinerNode_SP_MST
        SteinerNode_sub_dict = defaultdict(lambda: defaultdict(lambda: None))

        #print SteinerNode_sub_dict
        for each_complete_edge in SteinerNode_SP_MST.mstEdge():
            v = each_complete_edge.edgeFrom()
            w = each_complete_edge.edgeTo()
            # print v,w,SteinerNode_SPTs.path(v, w)[1]
            path = SteinerNode_SPTs.path(v, w)[0]

            for i in range(len(path) - 1):
                # print "i",i
                # print "%d->%d:%d" % (path[i],path[i+1],SteinerNode_SPTs.path(path[i], path[i+1])[1])
                SteinerNode_sub_dict[path[i]][path[i + 1]] = self.original_graph.adj_dict[path[i]][path[i + 1]]

        SteinerNode_subgraph = EdgeWeightedDigraph()
        SteinerNode_subgraph.addGraphFromDict(SteinerNode_sub_dict)

        # Step 4
        self.SteinerNode_subgraph_MST = DigraphPrimMST(SteinerNode_subgraph, src)

        # Step 5 : cutting

        ######
        self.branches = []

    def SteinerEdges(self):
        return self.SteinerNode_subgraph_MST.mstEdge()

    def printG(self):
        print self.SteinerNode_subgraph_MST.printG()

    def toAdjacency(self):
        steiner_tree_adj = defaultdict(lambda: defaultdict(lambda: None))

        for each_edge in self.SteinerEdges():
            v = each_edge.edgeFrom()  # v -> w
            w = each_edge.edgeTo()
            steiner_tree_adj[v][w] = each_edge.weight

        return steiner_tree_adj

    def findSplittingNodes(self):
        steiner_tree_adj = self.toAdjacency()
        splitting_nodes = []
        for each in steiner_tree_adj.keys():
            if len(steiner_tree_adj[each]) != 1:
                # spliting node
                splitting_nodes.append(each)
            elif each in self.dsts:
                splitting_nodes.append(each)

        return splitting_nodes

    def toBranches(self, root = None, branch = [], branch_list = []):
        if root == None:
            root = self.src
        steiner_tree_adj = self.toAdjacency()
        splitting_nodes = self.findSplittingNodes()

        for child_node in steiner_tree_adj[root].keys():
            if len(steiner_tree_adj[child_node].keys()) == 0:
                # leaf node
                branch.append(root)
                branch.append(child_node)
                branch_list.append(branch)
                branch = []
            elif len(steiner_tree_adj[child_node].keys()) == 1 and child_node not in self.Dst:
                # not spliting node
                branch.append(root)
                branch, branch_list = self.toBranches(child_node, branch, branch_list)
            else:
                # splitting node
                branch.append(root)
                branch.append(child_node)
                branch_list.append(branch)
                branch = []
                branch, branch_list = self.toBranches(child_node, branch, branch_list)
        return branch, branch_list


def findShortestLeafNode(tree, root, leaf_nodes_list):
    # find the nearest leaf node to root node
    if isinstance(tree, defaultdict):
        # ensure tree is in defaultdict structure
        edgeTo = {}
        has_traversed = []
        has_traversed.append(root)

        while (len(has_traversed) != 0):
            node = has_traversed.pop(0)
            neighbors = tree[node].keys()

            for child_node in neighbors:
                if child_node not in (has_traversed):
                    edgeTo[child_node] = node
                    if child_node in leaf_nodes_list:
                        ret = child_node
                        # print edgeTo
                        path = []
                        while child_node in edgeTo.keys():
                            path.append(edgeTo[child_node])
                            child_node = edgeTo[child_node]
                            # print 'child node:', child_node
                        path.reverse()
                        path.append(ret)
                        # print 'path in shortestleaf', path

                        return path
                    else:
                        has_traversed.append(child_node)


def findSplittingNodes(adj):
    splitting_nodes = []
    for each in adj.keys():
        if len(adj[each]) != 1:
            # spliting node
            splitting_nodes.append(each)

    return splitting_nodes


if __name__ == "__main__":
    # Adjacency map.  [sw1][sw2] -> port from sw1 to sw2
    adjacency = defaultdict(lambda: defaultdict(lambda: None))

    # adjacency[1][2] = (1,0,300) #(port,link_id,weight)
    # adjacency[2][1] = (3,8,300)
    # adjacency[1][6] = (2,1,700)
    # adjacency[6][1] = (1,9,700)
    # adjacency[2][3] = (4,3,1000)
    # adjacency[3][2] = (1,11,1000)
    # adjacency[2][6] = (5,2,500)
    # adjacency[6][2] = (3,10,500)
    # adjacency[6][5] = (2,4,750)
    # adjacency[5][6] = (2,12,750)
    # adjacency[3][5] = (2,5,400)
    # adjacency[5][3] = (1,13,400)
    # adjacency[3][4] = (3,6,600)
    # adjacency[4][3] = (1,14,600)
    # adjacency[5][4] = (3,15,200)
    # adjacency[4][5] = (2,7,200)

    # adjacency[1][2] = (1, 0, 1)  # (port,link_id,weight)
    # adjacency[2][1] = (3, 8, 1)
    # adjacency[1][6] = (2, 1, 1)
    # adjacency[6][1] = (1, 9, 1)
    # adjacency[2][3] = (4, 3, 1)
    # adjacency[3][2] = (1, 11, 1)
    # adjacency[2][6] = (5, 2, 1)
    # adjacency[6][2] = (3, 10, 1)
    # adjacency[6][5] = (2, 4, 1)
    # adjacency[5][6] = (2, 12, 1)
    # adjacency[3][5] = (2, 5, 1)
    # adjacency[5][3] = (1, 13, 1)
    # adjacency[3][4] = (3, 6, 1)
    # adjacency[4][3] = (1, 14, 1)
    # adjacency[5][4] = (3, 15, 1)
    # adjacency[4][5] = (2, 7, 1)
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

    # test EdgeWeightedDigraph()
    # six_node_graph = EdgeWeightedDigraph()
    # six_node_graph.addGraphFromDict(adjacency)
    # six_node_graph.printG()
    #
    # print "number of vertexes:", six_node_graph.V()
    # print "number of edges:", six_node_graph.E()

    # test Mst
    src = 1
    dst = 4
    # six_node_MST = DigraphPrimMST(six_node_graph, src)
    # six_node_MST.printG()

    # test Dijkstra
    # six_node_SPTs = DijkstraAllPairSP(six_node_graph)
    # print six_node_SPTs.pathEdge(src, dst)
    # # print six_node_SPTs.path(1,4)
    # dst = 4
    # six_node_SP = DijkstraSP(six_node_graph, src)
    # six_node_SP.pathToDigraph(dst)
    # six_node_SP.printG()



    def traverseFrom(adj, splitting_nodes, root, branch=[], branch_list=[]):
        # this method will traverse the tree from a root node to next splitting nodes
        # branch.append(root)

        for child_node in adj[root].keys():
            if len(adj[child_node].keys()) == 0:
                # leaf node
                branch.append(root)
                branch.append(child_node)
                branch_list.append(branch)
                branch = []

            elif len(adj[child_node].keys()) == 1:
                # not spliting node
                branch.append(root)
                branch, branch_list = traverseFrom(adj, splitting_nodes, child_node, branch, branch_list)

            else:
                # splitting node
                branch.append(root)
                branch.append(child_node)
                branch_list.append(branch)
                branch = []
                branch, branch_list = traverseFrom(adj, splitting_nodes, child_node, branch, branch_list)

        return branch, branch_list

    # def findShortestLeafNode(tree, root, leaf_nodes_list):
    #     if isinstance(tree, defaultdict):
    #         # ensure tree is in defaultdict structure
    #         has_traversed = []
    #         has_traversed.append(root)
    #         while (len(has_traversed) != 0):
    #             node = has_traversed.pop(0)
    #             # print 'node:', node
    #             for neighbor_node in tree[node].keys():
    #                 if neighbor_node in leaf_nodes_list:
    #                     return neighbor_node
    #                 else:
    #                     has_traversed.append(neighbor_node)


    adjacency2 = defaultdict(lambda: defaultdict(lambda: None))

    adjacency2[1][2] = (1, 0, 1)  # (port,link_id,weight)
    # adjacency2[2][1] = (1, 0, 1)
    adjacency2[2][3] = (4, 3, 1)
    adjacency2[2][6] = (5, 2, 1)
    adjacency2[6][5] = (2, 4, 1)
    adjacency2[1][4] = (3, 6, 1)
    adjacency2[4][9] = (3, 6, 1)
    adjacency2[4][8] = (3, 6, 1)
    adjacency2[3][10] = (3, 6, 1)
    adjacency2[10][11] = (3, 6, 1)
    adjacency2[11][12] = (3, 6, 1)
    adjacency2[6][5] = (3, 6, 1)
    adjacency2[5][13] = (3, 6, 1)
    adjacency2[9][14] = (3, 6, 1)


    test_tree_graph = EdgeWeightedDigraph()
    test_tree_graph.addGraphFromDict(adjacency)
    test_tree_graph.printG()

    splitting_nodes =  findSplittingNodes(adjacency)

    print traverseFrom(adjacency2, splitting_nodes, 1)[1]

    Dst = [12,13,6]

    print 'test steiner tree'
    six_node_steiner = MinSteinerTree(test_tree_graph, src, Dst)
    six_node_steiner.printG()
    print 'test-----'
    # steiner_tree_adj = six_node_steiner.toAdjacency()

    nearest_node = findShortestLeafNode(adjacency2, 1, Dst)
    print nearest_node
    # print steiner_tree_adj
    #
    # steiner_tree_spt = EdgeWeightedDigraph()
    # steiner_tree_spt.addGraphFromDict(steiner_tree_adj)
    # steiner_tree_spt_graph = DijkstraSP(steiner_tree_spt, 1)
    # steiner_tree_spt_graph.printG()
    #


    # for each in six_node_steiner.SteinerEdges():
    #     if isinstance(each, DirectedEdge):
    #         print '--------'
    #         print each.edgeFrom()
    #         print each.edgeTo()
    #         print each.toString()

    print 'steiner tree to adj structure:', six_node_steiner.toAdjacency()
    print 'splitting node', six_node_steiner.findSplittingNodes()
    print six_node_steiner.toBranches()

















