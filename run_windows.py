#!/usr/bin/env python3
"""
Windows-compatible runner for Anti-Netcut
"""
import os
import sys
import logging
import argparse

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

def setup_windows_logging(verbose=False, log_file="antinetcut.log"):
    """Setup logging for Windows"""
    level = logging.DEBUG if verbose else logging.INFO
    
    handlers = [logging.StreamHandler(sys.stdout)]
    
    try:
        handlers.append(logging.FileHandler(log_file))
    except Exception as e:
        print(f"Warning: Could not create log file {log_file}: {e}")
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=handlers
    )

def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="AntiNetCut - Windows Version")
    parser.add_argument("--iface", help="Network interface", default="Wi-Fi")
    parser.add_argument("--detect-only", action="store_true", help="Detection only mode")
    parser.add_argument("--auto-remediate", action="store_true", help="Auto remediation")
    parser.add_argument("--list-queue", action="store_true", help="List queue")
    parser.add_argument("--approve", type=int, help="Approve queue item")
    parser.add_argument("--clear-queue", action="store_true", help="Clear queue")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Setup logging first
    setup_windows_logging(args.verbose)
    
    # Import after path setup
    from antinetcut.core import AntiNetCut
    from antinetcut.mitigation.queue import MitigationQueue
    from antinetcut.utils.config import load_config
    
    # Load config with Windows defaults
    cfg = {
        "iface": args.iface,
        "auto_remediate": args.auto_remediate,
        "detect_only": args.detect_only or not args.auto_remediate,
        "whitelist_file": "whitelist.json",
        "queue_file": "queue.json", 
        "log_file": "antinetcut.log",
        "doh_provider": "cloudflare"
    }
    
    # Handle queue commands
    queue = MitigationQueue(cfg["queue_file"])
    
    if args.list_queue:
        items = queue.list()
        if not items:
            print("Queue is empty")
        else:
            for i, item in enumerate(items):
                print(f"[{i}] {item['title']} - {item['timestamp']}")
        return
        
    if args.clear_queue:
        queue.clear()
        print("Queue cleared")
        return
        
    if args.approve is not None:
        from antinetcut.mitigation.commands import MitigationExecutor
        executor = MitigationExecutor(cfg)
        entry = queue.pop(args.approve)
        if entry:
            print(f"Approving: {entry['title']}")
            success = executor.execute_from_queue_entry(entry)
            print("Success" if success else "Failed")
        else:
            print("Invalid queue index")
        return
    
    # Start main application
    try:
        anti = AntiNetCut(cfg)
        logging.info("Starting AntiNetCut on interface %s", cfg["iface"])
        anti.start()
    except KeyboardInterrupt:
        logging.info("Shutting down...")
        anti.stop()
    except Exception as e:
        logging.error("Fatal error: %s", e)
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()