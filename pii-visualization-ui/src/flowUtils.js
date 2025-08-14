export const calculateNodeImpactScore = (service, edges) => {
    const outgoing = edges.filter(e => e.source === service.id).length;
    const incoming = edges.filter(e => e.target === service.id).length;
    return Math.sqrt(outgoing^2 + incoming^2);
  };
  
  export const sortByPIIRisk = (services, edges) => {
    return services.map(service => ({
      ...service,
      riskScore: calculateNodeImpactScore(service, edges)
    })).sort((a, b) => b.riskScore - a.riskScore);
  };
  