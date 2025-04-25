import dash
from dash import dcc, html, Input, Output, State
import pandas as pd
import networkx as nx
import plotly.graph_objs as go

TYPE_COLORS = {                        # Color settings for node types
    'local': '#d6786b', 'remote': '#0000FF', 'selected': '#e4c35c', 'unknown': '#000000'}

TELEFONICA = "#0066ff"
ANNOTATIONS = "#000000" #
LINKS = "#b0b6ca"

class AltoGui:
    def __init__(self, alto):
        self.alto = alto
        print("Remotes:", self.alto.remotes)
        self.get_graph_callback = self.get_merged_graph  # función que devuelve el grafo de networkx
        # self.df_llm    = pd.read_excel('Topology_Reference.xlsx', sheet_name='LLM')         # LLMs
        self.positions = {}
        self.created_services = []     # List for storing created services
        self.app = dash.Dash(__name__) # Create the Dash application
        self.create_dash()          # Initialize the Dash application
        self.highlighted_edges = []
        # self.app.run(debug=True)

    def get_merged_graph(self):
        base_graph = self.alto.topology.copy()  # Copia para no alterar el original

        for remote_graph in self.alto.remotes.values():
            for node, attrs in remote_graph.nodes(data=True):
                if node not in base_graph:
                    base_graph.add_node(node, **attrs)
                else:
                    # Nodo ya existe
                    base_type = base_graph.nodes[node].get('type', 'unknown')
                    remote_type = attrs.get('type', 'unknown')
                    if base_type == 'unknown' or base_type is None:
                        # Sobrescribimos atributos excepto enlaces
                        base_graph.nodes[node].update(attrs)

            for u, v, edge_attrs in remote_graph.edges(data=True):
                if not base_graph.has_edge(u, v):
                    base_graph.add_edge(u, v, **edge_attrs)

        return base_graph


    def add_node(self, node, type="local"):
        self.graph.add_node(node, type=type, color=TYPE_COLORS.get(type, 'gray'))

    def add_edge(self, node1, node2, weight=1):
        if node1 not in self.graph.nodes:
            self.add_node(node1)
        if node2 not in self.graph.nodes:
            self.add_node(node2)
        if self.graph.has_edge(node1, node2):
            self.graph[node1][node2]['weight'] = weight
        else:
            self.graph.add_edge(node1, node2, weight=weight)    
        
        
    def assign_default_positions(self, missing_positions, existing_positions):    # Assign random positions to nodes with no position
        x = 15
        y= 130
        for node in missing_positions:
            existing_positions[node] = (x,y)
            x +=10
        return existing_positions

    # Update the position dictionary

    def create_network_graph(self):
        self.graph = self.get_graph_callback()

        for node in self.graph.nodes():
            tipo = self.graph.nodes[node].get('type', 'unknown')
            self.graph.nodes[node]['color'] = TYPE_COLORS.get(tipo, TYPE_COLORS['unknown'])

        if not self.positions or set(self.graph.nodes()) != set(self.positions.keys()):
            self.positions = nx.circular_layout(self.graph)

        pos = self.positions
        edge_traces = []
        node_trace = go.Scatter(
            x=[], y=[], text=[],
            mode='markers+text',
            textposition="top center",
            hoverinfo='text',
            marker=dict(
                color=[],
                size=20,
                line=dict(width=[])
            )
        )

        # Edges
        annotations = []

        for u, v, data in self.graph.edges(data=True):
            if u == v:  # Skip self-loops
                continue
            x0, y0 = pos[u]
            x1, y1 = pos[v]
            mid_x = (x0 + x1) / 2
            mid_y = (y0 + y1) / 2

            #color = LINKS

            edge_data = self.graph.get_edge_data(u, v, default={})
            edege_hover_text = f"<br>Key Rate: {data['weight']}"
            annotations.append(dict(
                x=mid_x,
                y=mid_y,
                text=edege_hover_text.replace("<br>", "<br>"), 
                showarrow=False,
                font=dict(size=14, color=ANNOTATIONS),
                align="center",
                bgcolor="rgba(255,255,255,0.6)",
                bordercolor="gray",
                borderwidth=1,
                borderpad=4,
                opacity=0.8
            ))

            if self.highlighted_edges and ((u,v) in self.highlighted_edges):
                print("Highlighted edges:", self.highlighted_edges)
                color = TYPE_COLORS['selected']
                line_width = 4
                #reversed_edges = [(b, a) for a, b in highlighted_edges]
                #if (u, v) in highlighted_edges or (u, v) in reversed_edges:
                #    color = 'red'    
                #elif equally_weighted_edges and ((u, v) in equally_weighted_edges or (v, u) in equally_weighted_edges):
                #    color = 'green'
                #else:
                #    color = 'rgba(136,136,136,0.2)'
            #elif equally_weighted_edges and ((u, v) in equally_weighted_edges or (v, u) in equally_weighted_edges):
            #    color = 'green'
            else:
                color = LINKS
                line_width = 2

            edege_hover_text = f"Enlace: {u} ↔ {v}"
            for key, value in data.items():
                edege_hover_text += f"<br>{key}: {value}"
            edege_hover_text += f"<br>Key Rate: {data['weight']}"
            edge_trace = go.Scatter(
                x=[x0, x1, None], y=[y0, y1, None],
                line=dict(width=line_width, color=color),
                hoverinfo='text',
                text=[f'{edege_hover_text}'] * 3,
                mode='lines'
            )
            edge_trace["text"] += (edege_hover_text,)
            edge_traces.append(edge_trace)

        # Nodes
        for node in self.graph.nodes():
            x, y = pos[node]
            node_trace['x'] += (x,)
            node_trace['y'] += (y,)

            tipo = self.graph.nodes[node].get('type', 'unknown')
            attrs = self.graph.nodes[node]
            text = f"<b>{node}</b><br>Type: {tipo}"
            for key, value in attrs.items():
                if key not in ['color', 'type']:
                    text += f"<br>{key}: {value}"

            node_trace['text'] += (text,)
            # if self.highlighted_edges:
            #     involved_nodes = set(n for e in self.highlighted_edges for n in e)
            #     if node in involved_nodes:
            #         color = self.graph.nodes[node]['color']
            #         line_width = 2
            #     else:
            #         color = 'rgba(136,136,136,0.2)'
            #         line_width = 0
            # else:
            #     color = self.graph.nodes[node]['color']
            #     line_width = 2
            color = self.graph.nodes[node]['color']
            line_width = 2
            node_trace['mode'] = 'markers'
            node_trace['marker']['color'] += (color,)
            node_trace['marker']['line']['width'] += (line_width,)

        fig = go.Figure(data=edge_traces + [node_trace],
                        layout=go.Layout(
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=0, l=0, r=0, t=40),
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            annotations=annotations  
                        ))
        return fig

    def create_dash(self):
        self.app.layout = html.Div([
            html.Div([
                html.H1("Network Federation", style={
                    'margin': '0',
                    'color': 'white',
                    'font-family': 'Segoe UI, sans-serif',
                    'fontSize': '28px'
                }),
                html.Img(src="assets/telefonica.png", style={
                    'height': '100%',
                    'marginLeft': 'auto' #'float': 'right'
                })
            ], style={
                'backgroundColor': TELEFONICA,
                'padding': '10px 20px',
                'display': 'flex',
                'justifyContent': 'space-between',
                'alignItems': 'center',
                'height': '60px'
            }),

            html.Div([
                dcc.Graph(id='network-graph', style={
                    'height': 'calc(100vh - 180px)',  # 60 (header) + 80 (footer)
                    'width': '100%'
                }),
                dcc.Interval(id='interval-component', interval=5000, n_intervals=0)
            ], style={
                'padding': '0 20px',
                'font-family': 'Segoe UI, sans-serif',
                'flexGrow': '1'
            }),
            
            # Pie de página con logos
            html.Div([
                html.Img(src='assets/eu_funded_en.jpg', style={'height': '60px', 'margin': '0 20px'}),
                html.Img(src='assets/discretion_logo.png', style={'height': '60px', 'margin': '0 20px'}),
                html.Img(src='assets/logo_mindef.jpg', style={'height': '60px', 'margin': '0 20px'})
            ], style={
                'display': 'flex',
                'justifyContent': 'center',
                'alignItems': 'center',
                'padding': '10px 0',
                'backgroundColor': TELEFONICA, #'#f5f5f5',
                'borderTop': '1px solid #ccc'
            })
        ])

        @self.app.callback(
            Output('network-graph', 'figure'),
            Input('interval-component', 'n_intervals')
        )
        def update_graph(n):
            return self.create_network_graph()



    def create_service(self, n_clicks, origin, destination):
        if not n_clicks or not origin or not destination:
            return "Por favor selecciona nodos válidos para crear un servicio.", []

        try:
            neighbors = list(self.graph.neighbors(destination))
            paths = {}
            for u, v in self.graph.edges():
                if 'weight' not in self.graph[u][v]:
                    self.graph[u][v]['weight'] = 1

            for neighbor in neighbors:
                try:
                    path = nx.shortest_path(self.graph, source=origin, target=neighbor, weight='weight')
                    total_length = nx.path_weight(self.graph, path, weight='weight') - ((len(path) - 2) * 5)
                    paths[tuple(path)] = total_length
                except nx.NetworkXNoPath:
                    continue

            if paths:
                shortest_path = min(paths, key=paths.get)
                shortest_length = paths[shortest_path]

                self.created_services.append(list(shortest_path))

                # Encuentra todos los caminos con el mismo peso total
                matching_edges = set()
                for path, weight in paths.items():
                    if abs(weight - shortest_length) < 1e-6:  # tolerancia por flotantes
                        matching_edges.update(zip(path, path[1:]))

                # Guarda los edges para resaltar en verde
                #self.equally_weighted_edges = matching_edges

                options = [{'label': f"{path[0]} → {path[-1]}", 'value': i}
                        for i, path in enumerate(self.created_services)]

                return (
                    f"Ruta más eficiente: {' → '.join(shortest_path)} (Consumo DDCC: {shortest_length:.2f} MWh)",
                    options
                )
            else:
                return "No hay rutas disponibles.", []

        except nx.NetworkXNoPath:
            return "No existe una ruta entre los nodos seleccionados.", []


    def highlight_selected_service(self, selected_index, reset_clicks):
        ctx = dash.callback_context
        if ctx.triggered[0]['prop_id'] == 'reset-button.n_clicks':
            return self.create_network_graph()

        if selected_index is None:
            return self.create_network_graph()

        path = self.created_services[selected_index]
        path_edges = list(zip(path, path[1:]))

        # Usamos los edges marcados previamente
        return self.create_network_graph()


    def highlight_link(self, node_a, node_b):
        self.highlighted_edges = [(node_a, node_b), (node_b, node_a)]  # soporta grafos no dirigidos
        return self.create_network_graph()


if __name__ == '__main__':
    app.run(debug=True)