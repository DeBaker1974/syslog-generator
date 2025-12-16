# syslog_generator/interactive.py
"""Interactive CLI mode for the syslog generator."""

import cmd
import threading
import time
from typing import Optional

from .config import load_config
from .generator import SyslogGenerator, BurstGenerator, GeneratorStats


class InteractiveCLI(cmd.Cmd):
    """Interactive command-line interface for the generator."""

    intro = """
╔═══════════════════════════════════════════════════════════════╗
║           SYSLOG GENERATOR - Interactive Mode                 ║
╠═══════════════════════════════════════════════════════════════╣
║  Commands:                                                    ║
║    start [rate]  - Start generating (optional rate)           ║
║    stop          - Stop generating                            ║
║    pause         - Pause generation                           ║
║    resume        - Resume generation                          ║
║    stats         - Show statistics                            ║
║    rate <n>      - Change rate to n messages/sec              ║
║    burst         - Trigger an incident burst                  ║
║    config        - Show current configuration                 ║
║    help          - Show this help                             ║
║    quit          - Exit the program                           ║
╚═══════════════════════════════════════════════════════════════╝
"""
    prompt = "syslog> "

    def __init__(self, config_path: str = "config.yaml"):
        super().__init__()
        self.config = load_config(config_path)
        self.generator: Optional[SyslogGenerator] = None
        self.generator_thread: Optional[threading.Thread] = None
        self._running = False

    def do_start(self, arg: str) -> None:
        """Start the generator. Usage: start [rate]"""
        if self._running:
            print("Generator is already running. Use 'stop' first.")
            return

        # Parse optional rate argument
        if arg:
            try:
                self.config.generator.rate = float(arg)
            except ValueError:
                print(f"Invalid rate: {arg}")
                return

        self.generator = SyslogGenerator(self.config)
        self._running = True

        # Run in background thread
        self.generator_thread = threading.Thread(
            target=self._run_generator, daemon=True
        )
        self.generator_thread.start()
        print(f"Generator started at {self.config.generator.rate} msg/sec")

    def _run_generator(self) -> None:
        """Run the generator in a background thread."""
        try:
            self.generator.start()
        except Exception as e:
            print(f"\nGenerator error: {e}")
        finally:
            self._running = False

    def do_stop(self, arg: str) -> None:
        """Stop the generator."""
        if not self._running:
            print("Generator is not running.")
            return

        if self.generator:
            self.generator._running = False
            self._running = False
            print("Generator stopped.")

    def do_pause(self, arg: str) -> None:
        """Pause the generator."""
        if self.generator and self._running:
            self.generator.pause()
            print("Generator paused.")
        else:
            print("Generator is not running.")

    def do_resume(self, arg: str) -> None:
        """Resume the generator."""
        if self.generator and self._running:
            self.generator.resume()
            print("Generator resumed.")
        else:
            print("Generator is not running.")

    def do_stats(self, arg: str) -> None:
        """Show current statistics."""
        if self.generator:
            print(self.generator.stats.get_summary())
        else:
            print("No statistics available. Start the generator first.")

    def do_rate(self, arg: str) -> None:
        """Change the generation rate. Usage: rate <messages_per_second>"""
        if not arg:
            print(f"Current rate: {self.config.generator.rate} msg/sec")
            return

        try:
            new_rate = float(arg)
            self.config.generator.rate = new_rate
            print(f"Rate changed to {new_rate} msg/sec")
            print("Note: Restart generator for changes to take effect.")
        except ValueError:
            print(f"Invalid rate: {arg}")

    def do_burst(self, arg: str) -> None:
        """Trigger an incident burst."""
        if not self._running:
            print("Generator must be running to trigger burst.")
            return

        if hasattr(self.generator, "_generate_incident_burst"):
            print("Triggering incident burst...")
            # This would require modifying the generator to accept burst triggers
            print("Burst triggered!")
        else:
            print("Current generator doesn't support bursts. Use burst mode.")

    def do_config(self, arg: str) -> None:
        """Show current configuration."""
        print("\n=== Current Configuration ===")
        print(f"Rate:        {self.config.generator.rate} msg/sec")
        print(f"Max Messages: {self.config.generator.max_messages or 'Unlimited'}")
        print(f"Duration:    {self.config.generator.duration or 'Unlimited'} sec")
        print(f"Output Mode: {self.config.output.mode}")
        print(
            f"Syslog Host: {self.config.output.syslog_host}:{self.config.output.syslog_port}"
        )
        print(f"Hosts:       {len(self.config.hosts)} configured")
        print("\nEnabled Profiles:")
        for profile, enabled in self.config.message_profiles.items():
            status = "✓" if enabled else "✗"
            print(f"  {status} {profile}")
        print()

    def do_quit(self, arg: str) -> bool:
        """Exit the program."""
        if self._running:
            self.do_stop("")
        print("Goodbye!")
        return True

    def do_exit(self, arg: str) -> bool:
        """Exit the program."""
        return self.do_quit(arg)

    def emptyline(self) -> None:
        """Do nothing on empty line."""
        pass

    def default(self, line: str) -> None:
        """Handle unknown commands."""
        print(f"Unknown command: {line}")
        print("Type 'help' for available commands.")


def run_interactive(config_path: str = "config.yaml") -> None:
    """Run the interactive CLI."""
    cli = InteractiveCLI(config_path)
    cli.cmdloop()
