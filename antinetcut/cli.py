#!/usr/bin/env python3
"""
CLI interface for Anti-Netcut
"""

import argparse
import sys
import json
import logging

from .core import AntiNetCut
from .mitigation.queue import MitigationQueue
from .utils.config import load_config, DEFAULT_CONFIG

logger = logging.getLogger("antinetcut")

def parse_args():
    parser = argparse.ArgumentParser(
        description="AntiNetCut - Linux defensive network security tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo antinetcut --iface wlan0
  sudo antinetcut --iface wlan0 --auto-remediate
  antinetcut --list-queue
  sudo antinetcut --approve 0
        """
    )
    
    parser.add_argument(
        "--iface", 
        help="Network interface to monitor (default: auto-detect)",
        default=None
    )
    
    parser.add_argument(
        "--config", 
        help="Path to JSON config file",
        default=None
    )
    
    parser.add_argument(
        "--auto-remediate", 
        help="Enable auto remediation (requires root)",
        action="store_true"
    )
    
    parser.add_argument(
        "--detect-only", 
        help="Run detection only (no remediation)",
        action="store_true"
    )
    
    parser.add_argument(
        "--list-queue", 
        help="List mitigation queue and exit",
        action="store_true"
    )
    
    parser.add_argument(
        "--approve", 
        help="Approve and execute queue item by index (0-based)",
        type=int,
        default=None
    )
    
    parser.add_argument(
        "--clear-queue", 
        help="Clear mitigation queue",
        action="store_true"
    )
    
    parser.add_argument(
        "--export-log", 
        help="Export log to JSON file",
        default=None
    )
    
    parser.add_argument(
        "--verbose", "-v",
        help="Increase output verbosity",
        action="store_true"
    )
    
    return parser.parse_args()

def setup_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(DEFAULT_CONFIG["log_file"])
        ]
    )

def handle_queue_actions(args, cfg):
    """Handle queue management commands"""
    queue = MitigationQueue(cfg["queue_file"])
    
    if args.list_queue:
        items = queue.list()
        if not items:
            print("Mitigation queue is empty")
            return True
            
        print(f"Mitigation Queue ({len(items)} items):")
        print("-" * 80)
        for i, item in enumerate(items):
            print(f"[{i}] {item['title']}")
            print(f"    Time: {item['ts']}")
            print(f"    Details: {item['details']}")
            if item.get('meta'):
                print(f"    Meta: {json.dumps(item['meta'])}")
            print()
        return True
        
    if args.clear_queue:
        queue.clear()
        print("Mitigation queue cleared")
        return True
        
    if args.approve is not None:
        from .mitigation.commands import MitigationExecutor
        executor = MitigationExecutor(cfg)
        
        entry = queue.pop(args.approve)
        if not entry:
            print(f"Error: No queue item at index {args.approve}")
            return True
            
        print(f"Approving: {entry['title']}")
        success = executor.execute_from_queue_entry(entry)
        
        if success:
            print("Mitigation executed successfully")
        else:
            print("Mitigation failed - see logs for details")
        return True
        
    return False

def main():
    args = parse_args()
    setup_logging(args.verbose)
    
    # Load configuration
    cfg = load_config(args.config)
    
    # Apply CLI overrides
    if args.iface:
        cfg["iface"] = args.iface
    if args.auto_remediate:
        cfg["auto_remediate"] = True
    if args.detect_only:
        cfg["detect_only"] = True
        cfg["auto_remediate"] = False
    
    # Handle queue management commands first
    if handle_queue_actions(args, cfg):
        return
    
    # Check for root privileges if needed
    if not args.detect_only and cfg["auto_remediate"]:
        import os
        if os.geteuid() != 0:
            logger.error("Root privileges required for auto-remediation")
            sys.exit(1)
    
    # Start main application
    try:
        anti = AntiNetCut(cfg)
        logger.info("Starting AntiNetCut on interface %s", cfg["iface"])
        anti.start()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
        anti.stop()
    except Exception as e:
        logger.error("Fatal error: %s", e)
        sys.exit(1)

if __name__ == "__main__":
    main()