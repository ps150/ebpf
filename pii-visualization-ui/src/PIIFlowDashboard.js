import React, { useState, useEffect } from 'react';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Dropdown } from 'primereact/dropdown';
import { Button } from 'primereact/button';
import { ReactFlow, Controls, Background, ReactFlowProvider, MarkerType } from 'reactflow';
import { useNavigate } from 'react-router-dom';
import api from './api';
import authService from './authService';
import dagre from 'dagre';
import 'reactflow/dist/style.css';

// Helper function to track edge counts between node pairs
// Using a function factory pattern instead of a global variable
const createEdgeCounter = () => {
  const counters = new Map();
  
  return {
    getCount: (source, target) => {
      const key = `${source}-${target}`;
      return counters.get(key) || 0;
    },
    incrementCount: (source, target) => {
      const key = `${source}-${target}`;
      const currentCount = counters.get(key) || 0;
      counters.set(key, currentCount + 1);
      return currentCount;
    },
    reset: () => {
      counters.clear();
    }
  };
};

// Improved layout function using dagre with support for multiple edges
const getLayoutedElements = (nodes, edges, direction = 'LR') => {
  const dagreGraph = new dagre.graphlib.Graph({
    multigraph: true,  // Enable multigraph to support multiple edges between same nodes
    compound: false
  });
  
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ 
    rankdir: direction,
    nodesep: 150, // Increase node separation
    ranksep: 200, // Increase rank separation
    edgesep: 80  // Important: increase edge separation
  });

  // Add nodes to the graph
  nodes.forEach(node => {
    dagreGraph.setNode(node.id, { width: 220, height: 120 });
  });

  // Add edges to the graph with unique names to preserve multiple edges
  edges.forEach(edge => {
    // Ensure edge.id is always passed as the unique name parameter
    dagreGraph.setEdge(edge.source, edge.target, {}, edge.id);
  });

  // Calculate layout
  dagre.layout(dagreGraph);

  // Update node positions
  const layoutedNodes = nodes.map(node => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 110, // Half of node width
        y: nodeWithPosition.y - 60,  // Half of node height
      },
    };
  });

  return { nodes: layoutedNodes, edges };
};

// Helper function to get style for PII type
const getPiiTypeStyle = (piiType) => {
  const styles = {
    email: {
      type: 'smoothstep',
      stroke: '#4CAF50',
      textColor: '#2E7D32',
      strokeDasharray: '5 5',
      icon: '📧'
    },
    phone: {
      type: 'smoothstep',
      stroke: '#0288D1',
      textColor: '#01579B',
      strokeDasharray: '3 3',
      icon: '📱'
    },
    default: {
      type: 'smoothstep',
      stroke: '#78909C',
      textColor: '#546E7A',
      strokeDasharray: '2 2',
      icon: '🔒'
    }
  };
  
  return styles[piiType] || styles.default;
};

function PIIFlowDashboard() {
  const [piiInstances, setPIIInstances] = useState([]);
  const [services, setServices] = useState([]);
  const [selectedServiceNode, setSelectedServiceNode] = useState(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [uniqueServices, setUniqueServices] = useState([]);
  const [allEdges, setAllEdges] = useState([]);
  const [allNodes, setAllNodes] = useState([]);
  const navigate = useNavigate();
  
  // Create an edge counter once, and we'll use its methods without reassigning
  const [edgeCounter] = useState(createEdgeCounter());

  useEffect(() => {
    const fetchData = async () => {
      try {
        // Using api service with auth token handling instead of axios directly
        const [servicesRes, piiRes, flowsRes] = await Promise.all([
          api.get('/api/services'),
          api.get('/api/pii-instances'),
          api.get('/api/pii-flows')
        ]);

        const servicesData = servicesRes.data;
        const piiData = piiRes.data;
        const flowsData = flowsRes.data;

        // Debug logs to verify data
        console.log('Services:', servicesData);
        console.log('PII Instances:', piiData);
        console.log('PII Flows:', flowsData);

        setUniqueServices(servicesData.map(service => ({
          label: `${service.serviceName} (${service.environment})`,
          value: service.serviceName
        })));

        setServices(servicesData);
        setPIIInstances(piiData);

        // Create nodes for each service with premium styling
        const serviceNodes = servicesData.map(service => {
          // Get environment-specific styling
          const isProduction = service.environment === 'prod';
          const envColor = isProduction ? '#4CAF50' : '#ffc107';
          
          return {
            id: `service-${service.serviceId}`,
            position: { x: 0, y: 0 }, // Will be set by layout algorithm
            data: { 
              label: (
                <div className="node-container">
                  <div className="node-header">
                    <i className={`pi ${isProduction ? 'pi-server' : 'pi-cloud'} mr-2`}></i>
                    {service.serviceName}
                  </div>
                  <div className="node-environment" style={{ backgroundColor: envColor }}>
                    {service.environment.toUpperCase()}
                  </div>
                  <div className="confidence-meter">
                    <div 
                      className="confidence-fill" 
                      style={{ 
                        width: `${Math.min(service.piiInstanceCount * 20, 100)}%`,
                        background: isProduction 
                          ? 'linear-gradient(90deg, #3a36db 0%, #6c63ff 100%)' 
                          : 'linear-gradient(90deg, #ff9800 0%, #ffc107 100%)'
                      }}
                    >
                      <span>{service.piiInstanceCount} PII</span>
                    </div>
                  </div>
                </div>
              )
            },
            style: {
              backgroundColor: '#ffffff',
              borderRadius: '12px',
              border: `2px solid ${envColor}`,
              padding: '0',
              boxShadow: '0 4px 8px rgba(0,0,0,0.1)'
            }
          };
        });

        // Reset the edge counter instead of reassigning it
        edgeCounter.reset();

        // Create edges for each flow with guaranteed unique IDs
        const initialEdges = flowsData.map(flow => {
          const sourceService = servicesData.find(s => s.serviceName === flow.sourceService);
          const destService = servicesData.find(s => s.serviceName === flow.destinationService);
          
          if (!sourceService || !destService) return null;
          
          const sourceNodeId = `service-${sourceService.serviceId}`;
          const targetNodeId = `service-${destService.serviceId}`;
          
          // Get the edge index for this source-target pair
          const edgeIndex = edgeCounter.incrementCount(sourceNodeId, targetNodeId);
          
          // Calculate offset for parallel edges to make them visually distinct
          const offset = edgeIndex === 0 ? 0 : (edgeIndex % 2 === 0 ? 25 : -25);
          
          // Get style based on PII type
          const edgeStyle = getPiiTypeStyle(flow.piiType);
          
          // Create a truly unique edge ID using flow ID, type, and index
          const uniqueEdgeId = `flow-${flow.flowId}-${flow.piiType}-${edgeIndex}`;
          
          return {
            id: uniqueEdgeId,
            source: sourceNodeId,
            target: targetNodeId,
            type: edgeStyle.type,
            label: (
              <div className="edge-label">
                <span className="pii-type">{edgeStyle.icon} {flow.piiType}</span>
                <span className="instance-count">{flow.instanceCount} instance{flow.instanceCount !== 1 ? 's' : ''}</span>
              </div>
            ),
            animated: true,
            style: { 
              stroke: edgeStyle.stroke,
              strokeWidth: 2,
              strokeDasharray: edgeStyle.strokeDasharray
            },
            // Add directional arrow marker
            markerEnd: {
              type: MarkerType.ArrowClosed,
              width: 20,
              height: 20,
              color: edgeStyle.stroke
            },
            // Store original flow data and offset for reference
            data: {
              flowId: flow.flowId,
              piiType: flow.piiType,
              sourceService: flow.sourceService,
              destinationService: flow.destinationService,
              instanceCount: flow.instanceCount,
              offset: offset,
              edgeIndex: edgeIndex
            }
          };
        }).filter(Boolean);

        console.log('Initial Edges:', initialEdges);

        setAllEdges(initialEdges);
        setAllNodes(serviceNodes);
        
        // Apply automatic layout
        const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
          serviceNodes,
          initialEdges
        );
        
        setNodes(layoutedNodes);
        setEdges(layoutedEdges);

      } catch (error) {
        console.error('Error fetching data:', error);
        if (error.response && error.response.status === 401) {
          // Handle unauthorized access by redirecting to login
          authService.logout();
          navigate('/login');
        }
      }
    };

    fetchData();
  }, [navigate, edgeCounter]);

  useEffect(() => {
    if (!selectedServiceNode) {
      // No service selected, show all nodes and edges with layout
      const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
        allNodes,
        allEdges
      );
      setNodes(layoutedNodes);
      setEdges(layoutedEdges);
      return;
    }

    const selectedService = services.find(s => s.serviceName === selectedServiceNode);
    if (!selectedService) return;
    
    const selectedNodeId = `service-${selectedService.serviceId}`;
    
    // Find all nodes connected to the selected service
    const connectedNodeIds = new Set([selectedNodeId]);
    
    allEdges.forEach(edge => {
      if (edge.source === selectedNodeId) {
        connectedNodeIds.add(edge.target);
      } else if (edge.target === selectedNodeId) {
        connectedNodeIds.add(edge.source);
      }
    });
    
    // Filter nodes and edges
    const filteredNodes = allNodes.filter(node => connectedNodeIds.has(node.id));
    const filteredEdges = allEdges.filter(edge => 
      connectedNodeIds.has(edge.source) && connectedNodeIds.has(edge.target)
    );
    
    // Apply layout to the filtered nodes and edges
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
      filteredNodes,
      filteredEdges
    );
    
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
  }, [selectedServiceNode, services, allEdges, allNodes]);

  const handleLogout = () => {
    authService.logout().then(() => {
      navigate('/login');
    });
  };

  // Function to render the confidence indicator in the data table
  const confidenceTemplate = (rowData) => {
    const percentage = Math.round(rowData.confidence * 100);
    let color = '#4CAF50'; // Default green
    
    if (percentage < 70) {
      color = '#ff5757'; // Red for low confidence
    } else if (percentage < 90) {
      color = '#ffc107'; // Yellow for medium confidence
    }
    
    return (
      <div className="confidence-meter">
        <div 
          className="confidence-fill" 
          style={{ 
            width: `${percentage}%`,
            background: `linear-gradient(90deg, ${color} 0%, ${color === '#4CAF50' ? '#45a049' : color === '#ffc107' ? '#ffce3a' : '#ff7070'} 100%)`
          }}
        >
          <span>{percentage}%</span>
        </div>
      </div>
    );
  };

  // Function to render the PII type with icon in the data table
  const piiTypeTemplate = (rowData) => {
    const style = getPiiTypeStyle(rowData.piiType);
    return (
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <span style={{ marginRight: '8px' }}>{style.icon}</span>
        <span style={{ color: style.textColor, fontWeight: 600 }}>{rowData.piiType}</span>
      </div>
    );
  };

  // Function to render severity indicator
  const severityTemplate = (rowData) => {
    const severityColors = {
      'CRITICAL': '#ff5757',
      'HIGH': '#ff9800',
      'MEDIUM': '#ffc107',
      'LOW': '#4CAF50'
    };
    
    const color = severityColors[rowData.severity] || '#8f9bb3';
    
    return (
      <div style={{ 
        backgroundColor: color,
        color: 'white',
        padding: '4px 8px',
        borderRadius: '12px',
        fontWeight: 600,
        fontSize: '0.75rem',
        display: 'inline-block',
        textAlign: 'center'
      }}>
        {rowData.severity}
      </div>
    );
  };

  return (
    <div className="pii-dashboard">
      <div className="dashboard-header p-4 shadow-3">
        <div className="flex justify-content-between align-items-center">
          <h1 className="text-3xl font-bold mb-4">
            <i className="pi pi-shield mr-3"></i>
            Enterprise PII Flow Monitor
          </h1>
          <Button 
            icon="pi pi-sign-out" 
            label="Logout" 
            className="p-button-rounded p-button-text" 
            onClick={handleLogout} 
          />
        </div>
        <Dropdown 
          value={selectedServiceNode} 
          options={uniqueServices} 
          onChange={(e) => setSelectedServiceNode(e.value)} 
          placeholder="Select Service Node" 
          showClear 
          filter 
          className="w-full md:w-30rem"
        />
      </div>

      <div className="dashboard-content p-4">
        <div className="flow-visualization">
          <ReactFlowProvider>
            <ReactFlow 
              nodes={nodes} 
              edges={edges} 
              fitView
              nodesDraggable={true}
              zoomOnScroll={false}
              zoomOnPinch={true}
              panOnScroll={true}
              panOnDrag={true}
              minZoom={0.5}
              maxZoom={1.5}
            >
              <Background 
                variant="dots"
                gap={20} 
                size={1}
                color="#e0e0e0" 
              />
              <Controls />
            </ReactFlow>
          </ReactFlowProvider>
        </div>
      </div>

      <div className="data-section p-4">
        <div className="surface-card p-4 border-round shadow-2">
          <DataTable 
            value={piiInstances} 
            paginator 
            rows={10}
            stripedRows
            responsiveLayout="scroll"
            emptyMessage="No PII instances found"
            className="p-datatable-sm"
          >
            <Column field="piiType" header="Type" body={piiTypeTemplate} sortable filter />
            <Column field="category" header="Value" sortable filter />
            <Column field="sourceService" header="Source" sortable filter />
            <Column field="destinationService" header="Destination" sortable filter />
            <Column field="severity" header="Severity" body={severityTemplate} sortable />
            <Column field="confidence" header="Confidence" body={confidenceTemplate} sortable />
          </DataTable>
        </div>
      </div>
    </div>
  );
}

export default PIIFlowDashboard;
