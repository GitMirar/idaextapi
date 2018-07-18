#!/home/user/venv/graphviz/bin/python2

from graphviz import Digraph
import sys
import json


def main():
    if len(sys.argv) != 2:
        sys.exit(-1)

    with open(sys.argv[1], "rb") as f:
        data = f.read()

    jdata = json.loads(data)

    g = Digraph(comment="Xrefs")
    for func in jdata:
        g.node(func, func)
        for xref in jdata[func]:
            g.edge(xref, func)
            print("%s -> %s" % (xref, func))

    g.render("neato", "png", "%s.png" % sys.argv[1])
    print("wrote graph to %s" % ("%s.png" % sys.argv[1]))


if __name__ == "__main__":
    main()
