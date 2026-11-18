
"""Process security events using the AI agent."""
import argparse
import time

from . import store, events


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--once",
        action="store_true",
        help="Process one event, then exit"
    )

    parser.add_argument(
        "--interval",
        type=float,
        default=3
    )

    args = parser.parse_args()

    store.init_db()
    events.ensure_tables()

    print("OpsPilot autonomous worker started", flush=True)

    while True:
        result = events.process_one()

        if result:
            print(result, flush=True)

        elif args.once:
            print("No pending events", flush=True)

        if args.once:
            break

        if not result:
            time.sleep(max(1, args.interval))


if __name__ == "__main__":
    main()
