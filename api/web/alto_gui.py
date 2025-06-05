import dash
from dash import dcc, html, Input, Output
import networkx as nx
import plotly.graph_objs as go

TYPE_COLORS = {                        # Color settings for node types
    'local': '#d6786b', 'remote': '#0000FF', 'selected': '#e4c35c', 'unknown': '#000000'}

TELEFONICA = "#0066ff"
ANNOTATIONS = "#000000" #
LINKS = "#b0b6ca"

class AltoGui:
    '''
    Clase para crear la interfaz gráfica de usuario (GUI) para la visualización de la topología
    de red. Esta clase utiliza Dash y Plotly para crear una aplicación web que muestra un grafo
    interactivo de la topología de red. La clase también incluye métodos para actualizar el grafo
    en tiempo real y resaltar enlaces seleccionados.
    '''
    def __init__(self, alto):
        self.alto = alto
        print("Remotes:", self.alto.remotes)
        self.get_graph_callback = self.get_merged_graph  # función que devuelve el grafo de networkx
        self.positions = {}
        self.created_services = []     # List for storing created services
        self.app = dash.Dash(__name__) # Create the Dash application
        self.create_dash()          # Initialize the Dash application
        self.highlighted_edges = []
        self.graph = None #TO be initialized later
        # self.app.run(debug=True)

    def get_merged_graph(self):
        '''
        Combina la topología local y las remotas en un solo grafo.
        La topología local se obtiene de self.alto.topology y las remotas de self.alto.remotes.
        Se copian los nodos y enlaces de las topologías remotas al grafo base.
        Si un nodo ya existe en el grafo base, se actualizan sus atributos.
        Los enlaces se añaden solo si no existen en el grafo base.
        :return: Un grafo de NetworkX que representa la topología combinada.
        '''
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
                u_type = base_graph.nodes[u].get('type', 'unknown')
                v_type = base_graph.nodes[v].get('type', 'unknown')

                # Evita enlaces entre local y remote
                if u_type == v_type:
                    base_graph.add_edge(u, v, **edge_attrs)


        return base_graph


    def add_node(self, node, type="local"):
        '''
        Añade un nodo al grafo con un tipo y color específicos.
        :param node: El nodo a añadir.
        :param type: El tipo de nodo (local, remote, etc.).
        :return: None
        '''
        self.graph.add_node(node, type=type, color=TYPE_COLORS.get(type, 'gray'))

    def add_edge(self, node1, node2, weight=1):
        '''
        Añade un enlace entre dos nodos en el grafo.
        Si alguno de los nodos no existe, se añade al grafo.
        :param node1: El primer nodo.
        :param node2: El segundo nodo.
        :param weight: El peso del enlace.
        :return: None
        '''
        if node1 not in self.graph.nodes:
            self.add_node(node1)
        if node2 not in self.graph.nodes:
            self.add_node(node2)
        if self.graph.has_edge(node1, node2):
            self.graph[node1][node2]['weight'] = weight
        else:
            self.graph.add_edge(node1, node2, weight=weight)


    def assign_default_positions(self, missing_positions, existing_positions):
        '''
        Asigna posiciones por defecto a los nodos que no tienen una posición definida.
        :param missing_positions: Lista de nodos que no tienen posición definida.
        :param existing_positions: Diccionario de posiciones existentes.
        :return: Diccionario actualizado de posiciones.
        '''
        x = 15
        y= 130
        for node in missing_positions:
            existing_positions[node] = (x,y)
            x +=10
        return existing_positions

    # Update the position dictionary

    def create_network_graph(self):
        '''
        Crea el grafo de la red utilizando Plotly y lo devuelve como un objeto de figura.
        :return: Un objeto de figura de Plotly que representa el grafo de la red.
        '''
        self.graph = self.get_graph_callback()

        for node in self.graph.nodes():
            tipo = self.graph.nodes[node].get('type', 'unknown')
            self.graph.nodes[node]['color'] = TYPE_COLORS.get(tipo, TYPE_COLORS['unknown'])

        if not self.positions or set(self.graph.nodes()) != set(self.positions.keys()):
            self.positions = nx.circular_layout(self.graph)
            for node in self.graph.nodes():
                if self.graph.nodes[node].get('type', 'unknown') == "local":
                    self.positions[node] = \
                        (self.positions[node][0] + 1.5, self.positions[node][1])
                else:
                    self.positions[node] = \
                        (self.positions[node][0] - 1.5, self.positions[node][1])

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
            else:
                color = LINKS
                line_width = 2

            edege_hover_text = f"Enlace: {u} ↔ {v}"
            for key, value in data.items():
                edege_hover_text += f"<br>{key}: {value}"
            edege_hover_text += f"<br>Key Rate: {data['weight']}"
            u_type = self.graph.nodes[u].get('type', 'unknown')
            v_type = self.graph.nodes[v].get('type', 'unknown')
            is_remote_edge = (u_type == 'unknown' and v_type == 'unknown')

            edge_trace = go.Scatter(
                x=[x0, x1, None], y=[y0, y1, None],
                line=dict(
                    width=line_width,
                    color=color,
                    dash='dot' if is_remote_edge else 'solid'
                ),
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
            color = self.graph.nodes[node]['color']
            line_width = 2
            node_trace['mode'] = 'markers'
            node_trace['marker']['color'] += (color,)
            node_trace['marker']['line']['width'] += (line_width,)

        # Fondo: mitad izquierda gris, mitad derecha rojo pálido
        shapes = [
            # Mitad izquierda - gris
            dict(
                type="rect",
                xref="paper", yref="paper",
                x0=0, y0=0, x1=0.5, y1=1,
                fillcolor="lightgray",
                line=dict(width=0),
                layer="below"
            ),
            # Mitad derecha - rojo pálido
            dict(
                type="rect",
                xref="paper", yref="paper",
                x0=0.5, y0=0, x1=1, y1=1,
                fillcolor="#ffe6e6",  # rojo pálido
                line=dict(width=0),
                layer="below"
            )
        ]


        fig = go.Figure(data=edge_traces + [node_trace],
                        layout=go.Layout(
                            showlegend=False,
                            hovermode='closest',
                            margin=dict(b=0, l=0, r=0, t=40),
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            annotations=annotations,
                            shapes=shapes   # fondo dividido
                        ))
        return fig

    def create_dash(self):
        '''
        Crea la aplicación Dash y define el diseño de la interfaz gráfica.
        :return: None
        '''
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
                html.Img(src='assets/eu_funded_en.jpg',
                         style={'height': '60px', 'margin': '0 20px'}),
                html.Img(src='assets/discretion_logo.png',
                         style={'height': '60px', 'margin': '0 20px'}),
                html.Img(src='assets/logo_mindef.jpg',
                         style={'height': '60px', 'margin': '0 20px'})
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

    def highlight_link(self, node_a, node_b):
        self.highlighted_edges = [(node_a, node_b), (node_b, node_a)]  # soporta grafos no dirigidos
        self.create_network_graph()


    def create_service(self, n_clicks, origin, destination):
        '''
        Crea un servicio entre dos nodos seleccionados en el grafo.
        :param n_clicks: Número de clics en el botón de crear servicio.
        :param origin: Nodo de origen.
        :param destination: Nodo de destino.
        :return: Mensaje de éxito o error y una lista de opciones para el menú desplegable.
        '''
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
                    path = nx.shortest_path(self.graph,
                                            source=origin, target=neighbor, weight='weight')
                    total_length = nx.path_weight(self.graph,
                                                  path, weight='weight') - ((len(path) - 2) * 5)
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
                    f"Ruta más eficiente: {' → '.join(shortest_path)} \
                        (Consumo DDCC: {shortest_length:.2f} MWh)",
                    options
                )
            else:
                return "No hay rutas disponibles.", []

        except nx.NetworkXNoPath:
            return "No existe una ruta entre los nodos seleccionados.", []

