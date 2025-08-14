self.addEventListener('message', (e) => {
    const { edges, nodes } = e.data;
    
    // Perform edge calculations in worker
    const processedEdges = edges.map(edge => {
      // Add complex calculations here
      return {
        ...edge,
        calculated: true
      };
    });
  
    self.postMessage(processedEdges);
  });
  