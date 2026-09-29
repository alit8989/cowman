"""Dynamic network topology generator and renderer."""

from __future__ import annotations

import socket
from typing import Dict, List, Optional
from rich.tree import Tree

from cowman.core.models import Device, NetworkTopologyNode
from cowman.network.interfaces import (
    get_default_gateway_and_interface,
    get_primary_interface,
)
from cowman.storage.repository import DeviceRepository


class TopologyGenerator:
    """Builds hierarchical network topology dynamically from live or stored inventory."""

    @classmethod
    def build_topology(cls, devices: Optional[List[Device]] = None) -> NetworkTopologyNode:
        """Construct the topology tree model."""
        if devices is None:
            devices = DeviceRepository.get_all(status_filter="ONLINE")

        gateway_ip, _ = get_default_gateway_and_interface()
        primary_iface = get_primary_interface()
        local_ip = primary_iface.ip if primary_iface else None
        local_hostname = socket.gethostname()

        # Root: WAN / Internet
        root = NetworkTopologyNode(
            id="wan",
            name="INTERNET / WAN",
            node_type="WAN",
            status="ONLINE",
        )

        # Find or create Router node
        router_device = None
        for d in devices:
            if d.ip == gateway_ip or d.device_type == "Router":
                router_device = d
                break

        router_name = "ROUTER / GATEWAY"
        if router_device and router_device.vendor and router_device.vendor != "Unknown":
            router_name = f"ROUTER ({router_device.vendor})"
        elif gateway_ip:
            router_name = f"ROUTER ({gateway_ip})"

        router_node = NetworkTopologyNode(
            id="router",
            name=router_name,
            ip=router_device.ip if router_device else gateway_ip,
            mac=router_device.mac if router_device else None,
            node_type="ROUTER",
            vendor=router_device.vendor if router_device else None,
            status="ONLINE",
            parent_id="wan",
        )
        root.children.append(router_node)

        # Add endpoints under Router
        seen_ips = set()
        if router_node.ip:
            seen_ips.add(router_node.ip)

        # Add local machine first if not already present
        if local_ip and local_ip not in seen_ips:
            local_node = NetworkTopologyNode(
                id=f"host-{local_ip}",
                name=f"LOCAL HOST ({local_hostname})",
                ip=local_ip,
                mac=primary_iface.mac if primary_iface else None,
                node_type="HOST",
                vendor="Local System",
                status="ONLINE",
                parent_id="router",
            )
            router_node.children.append(local_node)
            seen_ips.add(local_ip)

        # Add remaining discovered devices
        for d in devices:
            if d.ip in seen_ips:
                continue
            seen_ips.add(d.ip)

            display_name = d.hostname or d.vendor or d.device_type
            if display_name == "Unknown":
                display_name = d.device_type

            node = NetworkTopologyNode(
                id=f"device-{d.ip}",
                name=f"{display_name.upper()} ({d.ip})",
                ip=d.ip,
                mac=d.mac,
                node_type=d.device_type.upper(),
                vendor=d.vendor,
                status=d.status,
                parent_id="router",
            )
            router_node.children.append(node)

        return root

    @classmethod
    def render_ascii_diagram(cls, root: NetworkTopologyNode) -> str:
        """Render clean terminal ASCII box-drawing diagram dynamically."""
        lines: List[str] = []
        lines.append("                 INTERNET")
        lines.append("                     │   ")

        router_node = root.children[0] if root.children else None
        if not router_node:
            lines.append("                (NO ROUTER)")
            return "\n".join(lines)

        r_label = f"ROUTER"
        if router_node.ip:
            r_label += f" ({router_node.ip})"
        lines.append(f"{r_label.center(42)}")
        lines.append("                     │   ")

        endpoints = router_node.children
        if not endpoints:
            lines.append("             (NO HOSTS DETECTED)")
            return "\n".join(lines)

        if len(endpoints) == 1:
            ep = endpoints[0]
            label = f"{ep.node_type} ({ep.ip or ep.name})"
            lines.append(f"{label.center(42)}")
            return "\n".join(lines)

        # Dynamic multi-branch rendering (up to 5 columns per row to fit standard terminal)
        chunk_size = 4
        chunks = [endpoints[i : i + chunk_size] for i in range(0, len(endpoints), chunk_size)]

        for chunk_idx, chunk in enumerate(chunks):
            if chunk_idx > 0:
                lines.append("                     │   ")

            # Determine column labels
            col_labels = []
            for ep in chunk:
                lbl = ep.node_type
                if ep.ip:
                    # Shorten IP if needed (e.g. .20 or full IP)
                    ip_short = ep.ip.split(".")[-1]
                    lbl = f"{lbl} (.{ip_short})"
                col_labels.append(lbl)

            col_width = 16
            total_cols = len(col_labels)

            # Draw top connector line
            if total_cols == 1:
                lines.append(f"{'│'.center(col_width)}")
            elif total_cols == 2:
                lines.append("          ┌──────────┴──────────┐")
                lines.append("          │                     │")
            elif total_cols == 3:
                lines.append("          ┌──────────┼──────────┐")
                lines.append("          │          │          │")
            elif total_cols >= 4:
                lines.append("     ┌──────────┬──────────┬──────────┐")
                lines.append("     │          │          │          │")

            # Format bottom labels row
            formatted_cells = [lbl.center(12) for lbl in col_labels]
            row_str = " ".join(formatted_cells)
            lines.append(f"{row_str.center(46)}")

        return "\n".join(lines)

    @classmethod
    def render_rich_tree(cls, root: NetworkTopologyNode) -> Tree:
        """Render interactive Rich Tree structure."""
        tree = Tree(f"[bold cyan][WAN] {root.name}[/bold cyan]")
        for child in root.children:
            r_label = f"[bold green][ROUTER] {child.name}[/bold green]"
            if child.ip:
                r_label += f" [dim]({child.ip})[/dim]"
            if child.mac and child.mac != "Unknown":
                r_label += f" [dim italic][{child.mac}][/dim italic]"
            router_branch = tree.add(r_label)

            for ep in child.children:
                icon_map = {
                    "LAPTOP": "[LAPTOP]",
                    "PHONE": "[PHONE]",
                    "SERVER": "[SERVER]",
                    "IOT": "[IOT]",
                    "ROUTER": "[ROUTER]",
                    "HOST": "[HOST]",
                }
                icon = icon_map.get(ep.node_type, "[DEVICE]")
                color = "green" if ep.status == "ONLINE" else "red"
                ep_text = f"[{color}]{icon} {ep.name}[/{color}]"
                if ep.vendor and ep.vendor != "Unknown":
                    ep_text += f" [cyan]<{ep.vendor}>[/cyan]"
                if ep.mac and ep.mac != "Unknown":
                    ep_text += f" [dim][{ep.mac}][/dim]"
                router_branch.add(ep_text)

        return tree
