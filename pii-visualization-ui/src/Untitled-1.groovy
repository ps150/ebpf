curl -X POST http://localhost:8080/api/transactions \
-H "Content-Type: application/json" \
-d '{
    "processName": "user-service",
    "pid": 1001,
    "httpMethod": "POST",
    "urlPath": "/api/register",
    "host": "payment-service.prod",
    "payload": "{\"user\":{\"email\":\"john.doe+security@company.com\",\"phone\":\"+1-555-123-4567\"}}",
    "isRequest": true,
    "sourceIp": "10.0.1.100",
    "destinationIp": "10.0.2.5",
    "timestamp": "2025-02-23T10:00:00Z"
}'
curl -X POST http://localhost:8080/api/transactions \
-H "Content-Type: application/json" \
-d '{
    "processName": "payment-service",
    "pid": 2001,
    "httpMethod": "POST",
    "urlPath": "/process-transaction",
    "host": "geo-service.staging",
    "payload": "{\"transaction\":{\"email\":\"JOHN.DOE@COMPANY.COM\",\"card\":\"4111-1111-1111-1111\"}}",
    "isRequest": true,
    "sourceIp": "10.0.2.5",
    "destinationIp": "10.0.3.10",
    "timestamp": "2025-02-23T10:05:00Z"
}'

curl -X POST http://localhost:8080/api/transactions \
-H "Content-Type: application/json" \
-d '{
    "processName": "geo-service",
    "pid": 3001,
    "httpMethod": "POST",
    "urlPath": "/analytics",
    "host": "user-service.prod",
    "payload": "{\"report\":{\"contact\":\"johndoe@company.com\",\"last4\":\"1111\"}}",
    "isRequest": true,
    "sourceIp": "10.0.3.10",
    "destinationIp": "192.168.1.50",
    "timestamp": "2025-02-23T10:10:00Z"
}'

axios.defaults.baseURL = 'http://localhost:8080';



Service api response
[
{
"serviceId": 1,
"serviceName": "user-service",
"environment": "prod",
"piiInstanceCount": 2
},
{
"serviceId": 2,
"serviceName": "payment-service",
"environment": "prod",
"piiInstanceCount": 3
},
{
"serviceId": 3,
"serviceName": "geo-service",
"environment": "staging",
"piiInstanceCount": 1
}
]PII instance api response
[
{
"instanceId": 33,
"piiType": "email",
"category": "john.doe@company.com",
"confidence": 0.949999988079071,
"severity": "CRITICAL",
"sourceService": "user-service",
"destinationService": "payment-service",
"firstSeen": "2025-02-23T10:00:00Z",
"lastSeen": "2025-02-23T10:00:00Z"
},
{
"instanceId": 34,
"piiType": "email",
"category": "johndoe@company.com",
"confidence": 0.949999988079071,
"severity": "CRITICAL",
"sourceService": "payment-service",
"destinationService": "geo-service",
"firstSeen": "2025-02-23T10:05:00Z",
"lastSeen": "2025-02-23T10:05:00Z"
},
{
"instanceId": 35,
"piiType": "phone",
"category": "555-123-4567",
"confidence": 0.949999988079071,
"severity": "HIGH",
"sourceService": "user-service",
"destinationService": "payment-service",
"firstSeen": "2025-02-23T11:00:00Z",
"lastSeen": "2025-02-23T11:00:00Z"
}
]

Pii flows apis response
[
{
"flowId": 14,
"piiType": "email",
"sourceService": "payment-service",
"destinationService": "geo-service",
"instanceCount": 1,
"latestTransfer": "2025-02-23T10:05:00Z"
},
{
"flowId": 15,
"piiType": "phone",
"sourceService": "user-service",
"destinationService": "payment-service",
"instanceCount": 1,
"latestTransfer": "2025-02-23T11:00:00Z"
},
{
"flowId": 13,
"piiType": "email",
"sourceService": "user-service",
"destinationService": "payment-service",
"instanceCount": 1,
"latestTransfer": "2025-02-23T10:00:00Z"
}
]

and current code
import React, { useState, useEffect } from 'react';
import { DataTable } from 'primereact/datatable';
import { Column } from 'primereact/column';
import { Tag } from 'primereact/tag';
import { Dropdown } from 'primereact/dropdown';
import { ReactFlow, Controls, Background, ReactFlowProvider } from 'reactflow';
import axios from 'axios';
import 'primereact/resources/themes/lara-light-indigo/theme.css';
import 'primereact/resources/primereact.css';
import 'primeicons/primeicons.css';
import 'reactflow/dist/style.css';

function PIIFlowDashboard() {
const [piiInstances, setPIIInstances] = useState([]);
const [services, setServices] = useState([]);
const [selectedPIIInstance, setSelectedPIIInstance] = useState(null);
const [nodes, setNodes] = useState([]);
const [edges, setEdges] = useState([]);
const [uniquePIIInstances, setUniquePIIInstances] = useState([]);

useEffect(() => {
const fetchData = async () => {
try {
axios.defaults.baseURL = 'http://localhost:8080';
const [servicesRes, piiRes, flowsRes] = await Promise.all([
axios.get('/api/services'),
axios.get('/api/pii-instances'),
axios.get('/api/pii-flows')
]);

const servicesData = servicesRes.data;
const piiData = piiRes.data;
const flowsData = flowsRes.data;

// Process unique PII instances for dropdown
const uniqueCategories = [...new Set(piiData.map(instance => instance.category))];
setUniquePIIInstances(uniqueCategories.map(category => ({
label: `${piiData.find(i => i.category === category).piiType}: ${category}`,
value: category
})));

setServices(servicesData);
setPIIInstances(piiData);

// Filter services and edges based on selected PII instance
let filteredServices = servicesData;
let filteredEdges = [];

if (selectedPIIInstance) {
// Filter relevant services
filteredServices = servicesData.filter(service =>
piiData.some(instance =>
instance.category === selectedPIIInstance.value &&
(instance.sourceService === service.serviceName ||
instance.destinationService === service.serviceName)
)
);

// Filter relevant edges
filteredEdges = flowsData
.filter(flow =>
piiData.some(instance =>
instance.category === selectedPIIInstance.value &&
instance.sourceService === flow.sourceService &&
instance.destinationService === flow.destinationService
)
)
.map(flow => {
const sourceNodeId = `service-${services.find(s => s.serviceName === flow.sourceService)?.serviceId}`;
const targetNodeId = `service-${services.find(s => s.serviceName === flow.destinationService)?.serviceId}`;

return {
id: `flow-${flow.flowId}`,
source: sourceNodeId,
target: targetNodeId,
label: `${flow.piiType}: ${selectedPIIInstance.value}`,
animated: true,
style: { stroke: '#4caf50', strokeWidth: 3 }
};
});
}

// Create nodes for filtered services
const serviceNodes = filteredServices.map(service => ({
id: `service-${service.serviceId}`,
position: { x: Math.random() * 500, y: Math.random() * 500 },
data: { label: `${service.serviceName}\n(${service.environment})` },
style: {
backgroundColor: service.environment === 'prod' ? '#f8d7da' : '#fff3cd',
borderRadius: '8px',
borderWidth: '2px',
padding: '15px',
textAlign: 'center'
}
}));

setNodes(serviceNodes);
setEdges(filteredEdges);

} catch (error) {
console.error('Error fetching data:', error);
}
};

fetchData();
}, [selectedPIIInstance]);

return (
<div className="pii-dashboard">
<div className="dashboard-header">
<h1>PII Flow Monitoring System</h1>
<Dropdown
value={selectedPIIInstance}
options={uniquePIIInstances}
onChange={(e) => setSelectedPIIInstance(e.value)}
placeholder="Select PII Instance"
showClear
filter
style={{ width: '300px', marginRight: '20px' }}
/>
</div>

<div className="dashboard-content">
<ReactFlowProvider>
<ReactFlow nodes={nodes} edges={edges} fitView>
<Background />
<Controls />
</ReactFlow>
</ReactFlowProvider>
</div>

<div className="data-section">
<DataTable value={piiInstances} paginator rows={10}>
<Column field="piiType" header="PII Type" sortable />
<Column field="category" header="Value" sortable />
<Column field="sourceService" header="Source Service" sortable />
<Column field="destinationService" header="Destination Service" sortable />
</DataTable>
</div>
</div>
);
}

export default PIIFlowDashboard;

but I don't see the nodes when i select any PII instance, can we change like when I am selecting a service node, I should be able to draw all the edges of the PII instance flowing or coming to it ?