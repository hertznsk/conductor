import { MetadataGrid } from './MetadataGrid';
import type { NodeData } from '@/stores/workflow-store';
import { NODE_STATUS_HEX } from '@/lib/constants';
import { formatElapsed } from '@/lib/utils';
import type { NodeStatus } from '@/lib/constants';

interface McpDetailProps {
  node: NodeData;
}

export function McpDetail({ node }: McpDetailProps) {
  const status = node.status as NodeStatus;
  const statusColor = NODE_STATUS_HEX[status] || NODE_STATUS_HEX.pending;

  const items: Array<{ label: string; value: string | number | null | undefined }> = [];
  if (node.elapsed != null) items.push({ label: 'Elapsed', value: formatElapsed(node.elapsed) });
  if (node.mcp_server) items.push({ label: 'Server', value: node.mcp_server });
  if (node.mcp_tool) items.push({ label: 'Tool', value: node.mcp_tool });
  if (node.mcp_is_error !== undefined) items.push({ label: 'Is Error', value: String(node.mcp_is_error) });
  if (node.mcp_result_bytes != null) items.push({ label: 'Result Bytes', value: `${node.mcp_result_bytes}${node.mcp_truncated ? ' (truncated)' : ''}` });
  if (node.mcp_spill_path) items.push({ label: 'Spill Path', value: node.mcp_spill_path });
  
  if (node.error_type) items.push({ label: 'Error', value: node.error_type });
  if (node.error_message) items.push({ label: 'Message', value: node.error_message });

  return (
    <div className="space-y-4">
      {/* Status badge */}
      <div className="flex items-center gap-2">
        <span
          className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider"
          style={{
            backgroundColor: `${statusColor}20`,
            color: statusColor,
          }}
        >
          {status}
        </span>
        <span className="text-xs text-[var(--text-muted)]">MCP</span>
      </div>

      <MetadataGrid items={items} />
    </div>
  );
}
