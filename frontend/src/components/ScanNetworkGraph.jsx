import { useEffect, useMemo, useState } from "react";
import { API_BASE, API_KEY, WORKSPACE_ID } from "../context/ScanContext";

const authHeaders = () => ({
  "X-API-Key": API_KEY,
  "X-Workspace-ID": WORKSPACE_ID,
});

export default function ScanNetworkGraph({ job }) {
  const [requests, setRequests] = useState([]);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    loadRequests();
    if (autoRefresh) {
      const interval = setInterval(loadRequests, 2000);
      return () => clearInterval(interval);
    }
  }, [autoRefresh, job]);

  async function loadRequests() {
    try {
      const res = await fetch(`${API_BASE}/api/proxy/requests`, { headers: authHeaders() });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error || "Failed to load proxy history.");
        return;
      }
      setRequests(Array.isArray(data) ? data : []);
      setError("");
    } catch (err) {
      setError(err.message || "Failed to load proxy history.");
    }
  }

  // Filter requests to only show those from the current scan
  const scanRequests = useMemo(() => {
    if (!job?.id) return [];
    // For now, show all requests since we don't have scan-specific filtering
    // In a future enhancement, we could add scan ID tracking to proxy requests
    return requests.slice(-50); // Show last 50 requests to avoid overwhelming the graph
  }, [requests, job]);

  // Extract unique hosts from scan requests
  const hosts = useMemo(() => {
    const hostSet = new Set();
    scanRequests.forEach(req => {
      try {
        const url = new URL(req.url);
        hostSet.add(url.hostname);
      } catch {
        // Invalid URL, skip
      }
    });
    return Array.from(hostSet);
  }, [scanRequests]);

  // Create nodes and edges for the graph
  const graphData = useMemo(() => {
    const nodes = [];
    const edges = [];

    // Add client node
    nodes.push({
      id: 'client',
      label: 'Browser',
      type: 'client',
      x: 100,
      y: 200
    });

    // Add server nodes
    hosts.forEach((host, index) => {
      nodes.push({
        id: host,
        label: host.length > 20 ? host.substring(0, 17) + '...' : host,
        type: 'server',
        x: 600,
        y: 100 + (index * 80)
      });
    });

    // Add edges for requests and responses
    scanRequests.forEach((req, index) => {
      try {
        const url = new URL(req.url);
        const hostNode = nodes.find(n => n.id === url.hostname);
        if (hostNode) {
          // Request edge (client -> server)
          edges.push({
            id: `req-${req.id}`,
            source: 'client',
            target: url.hostname,
            type: 'request',
            method: req.method,
            status: req.responseStatus,
            url: req.url,
            timestamp: req.capturedAt
          });

          // Response edge (server -> client) if we have a response
          if (req.responseStatus) {
            edges.push({
              id: `res-${req.id}`,
              source: url.hostname,
              target: 'client',
              type: 'response',
              method: req.method,
              status: req.responseStatus,
              url: req.url,
              timestamp: req.capturedAt
            });
          }
        }
      } catch {
        // Invalid URL, skip
      }
    });

    return { nodes, edges };
  }, [scanRequests, hosts]);

  const getStatusColor = (status) => {
    if (!status) return '#gray';
    if (status >= 200 && status < 300) return '#10b981'; // green
    if (status >= 300 && status < 400) return '#f59e0b'; // yellow
    if (status >= 400 && status < 500) return '#f97316'; // orange
    if (status >= 500) return '#ef4444'; // red
    return '#gray';
  };

  const getMethodColor = (method) => {
    switch (method?.toUpperCase()) {
      case 'GET': return '#3b82f6'; // blue
      case 'POST': return '#8b5cf6'; // purple
      case 'PUT': return '#f59e0b'; // yellow
      case 'DELETE': return '#ef4444'; // red
      default: return '#6b7280'; // gray
    }
  };

  if (!job) {
    return (
      <div className="empty-state">
        No scan loaded. Network traffic will appear here during active scans.
      </div>
    );
  }

  return (
    <div>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <div>
          <h3>Scan Network Traffic</h3>
          <p className="meta">Real-time HTTP traffic captured through the proxy during this scan.</p>
        </div>
        <div className="button-row">
          <label style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            Auto-refresh
          </label>
        </div>
      </div>

      {error && (
        <div className="error" style={{ marginBottom: 12 }}>
          {error}
        </div>
      )}

      {scanRequests.length === 0 ? (
        <div className="empty-state">
          No network traffic captured yet. Traffic from browser-based scanning will appear here.
        </div>
      ) : (
        <div style={{ position: 'relative' }}>
          <svg width="800" height="400" style={{ border: '1px solid #e5e7eb', borderRadius: '4px' }}>
            {/* Edges */}
            {graphData.edges.map(edge => {
              const sourceNode = graphData.nodes.find(n => n.id === edge.source);
              const targetNode = graphData.nodes.find(n => n.id === edge.target);
              if (!sourceNode || !targetNode) return null;

              const isRequest = edge.type === 'request';
              const strokeColor = isRequest ? getMethodColor(edge.method) : getStatusColor(edge.status);
              const strokeWidth = isRequest ? 2 : 1.5;
              const strokeDasharray = isRequest ? 'none' : '5,5';

              return (
                <g key={edge.id}>
                  <line
                    x1={sourceNode.x}
                    y1={sourceNode.y}
                    x2={targetNode.x}
                    y2={targetNode.y}
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    strokeDasharray={strokeDasharray}
                    markerEnd={isRequest ? 'url(#arrowhead)' : 'url(#response-arrow)'}
                  />
                  {/* Edge label */}
                  <text
                    x={(sourceNode.x + targetNode.x) / 2}
                    y={(sourceNode.y + targetNode.y) / 2 - 5}
                    textAnchor="middle"
                    fontSize="10"
                    fill={strokeColor}
                    style={{ pointerEvents: 'none' }}
                  >
                    {isRequest ? edge.method : edge.status}
                  </text>
                </g>
              );
            })}

            {/* Arrow markers */}
            <defs>
              <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#3b82f6" />
              </marker>
              <marker id="response-arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
                <polygon points="0 0, 10 3.5, 0 7" fill="#10b981" />
              </marker>
            </defs>

            {/* Nodes */}
            {graphData.nodes.map(node => (
              <g key={node.id}>
                <circle
                  cx={node.x}
                  cy={node.y}
                  r="20"
                  fill={node.type === 'client' ? '#3b82f6' : '#f59e0b'}
                  stroke="#fff"
                  strokeWidth="2"
                />
                <text
                  x={node.x}
                  y={node.y + 25}
                  textAnchor="middle"
                  fontSize="11"
                  fill="#374151"
                  style={{ pointerEvents: 'none' }}
                >
                  {node.label}
                </text>
              </g>
            ))}
          </svg>

          {/* Legend */}
          <div style={{ marginTop: '16px', display: 'flex', gap: '16px', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <div style={{ width: '12px', height: '2px', backgroundColor: '#3b82f6', borderRadius: '1px' }}></div>
              <span style={{ fontSize: '12px', color: '#6b7280' }}>GET Request</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <div style={{ width: '12px', height: '2px', backgroundColor: '#8b5cf6', borderRadius: '1px' }}></div>
              <span style={{ fontSize: '12px', color: '#6b7280' }}>POST Request</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <div style={{ width: '12px', height: '2px', backgroundColor: '#10b981', borderRadius: '1px', border: '1px dashed #10b981' }}></div>
              <span style={{ fontSize: '12px', color: '#6b7280' }}>2xx Response</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
              <div style={{ width: '12px', height: '2px', backgroundColor: '#ef4444', borderRadius: '1px', border: '1px dashed #ef4444' }}></div>
              <span style={{ fontSize: '12px', color: '#6b7280' }}>5xx Response</span>
            </div>
          </div>

          {/* Stats */}
          <div style={{ marginTop: '16px', display: 'flex', gap: '16px' }}>
            <div style={{ fontSize: '12px', color: '#6b7280' }}>
              <strong>{scanRequests.length}</strong> requests captured
            </div>
            <div style={{ fontSize: '12px', color: '#6b7280' }}>
              <strong>{hosts.length}</strong> unique hosts
            </div>
          </div>
        </div>
      )}
    </div>
  );
}