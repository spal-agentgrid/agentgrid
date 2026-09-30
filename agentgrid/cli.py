"""Admin CLI for the local prototype: create account, issue key, grant credits."""
from __future__ import annotations

import argparse
import os

from .store import Store


def main():
    ap = argparse.ArgumentParser(description="AgentGrid local admin")
    ap.add_argument("--db", default=os.environ.get("AGENTGRID_DB", "agentgrid.db"))
    ap.add_argument("--database-url", default=os.environ.get("DATABASE_URL") or None,
                    help="Postgres URL (env DATABASE_URL); overrides --db")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create-account"); c.add_argument("name"); c.add_argument("--credits", type=int, default=100)
    g = sub.add_parser("grant"); g.add_argument("account_id"); g.add_argument("credits", type=int)
    b = sub.add_parser("balance"); b.add_argument("account_id")
    args = ap.parse_args()
    st = Store(args.db, database_url=args.database_url)
    if args.cmd == "create-account":
        acct = st.create_account(args.name)
        st.grant(acct, args.credits, reason="free_tier")
        print(f"account_id={acct}\napi_key={st.issue_key(acct)}\ncredits={args.credits}")
    elif args.cmd == "grant":
        st.grant(args.account_id, args.credits, reason="manual_grant")
        print(st.balance(args.account_id))
    elif args.cmd == "balance":
        print(st.balance(args.account_id))


if __name__ == "__main__":
    main()
