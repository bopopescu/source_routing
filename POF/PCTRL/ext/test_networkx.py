import networkx as nx
import matplotlib as mpl

G = nx.read_gml('Nsfnet.gml')

#print G.adj

print nx.shortest_path(G, source = 'BARRnet, Palo Alto')


