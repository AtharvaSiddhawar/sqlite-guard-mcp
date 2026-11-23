"""Utility script to create a sample SQLite database for testing SQLite Guard MCP.

Usage:
    python examples/create_sample_db.py [target_path.sqlite]
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path


def create_sample_database(db_path: Path) -> None:
    """Create a realistic sample database with diverse tables, foreign keys, and indexes."""
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute("PRAGMA journal_mode = WAL;")

        conn.executescript(
            """
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                first_name TEXT NOT NULL,
                last_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                api_key TEXT,
                credit_score INTEGER,
                internal_notes TEXT,
                city TEXT,
                country TEXT DEFAULT 'US'
            );

            CREATE TABLE categories (
                category_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL UNIQUE
            );

            CREATE TABLE products (
                product_id INTEGER PRIMARY KEY,
                category_id INTEGER,
                name TEXT NOT NULL,
                sku TEXT NOT NULL UNIQUE,
                price REAL NOT NULL,
                stock_quantity INTEGER DEFAULT 0,
                FOREIGN KEY (category_id) REFERENCES categories(category_id)
            );

            CREATE TABLE orders (
                order_id INTEGER PRIMARY KEY,
                customer_id INTEGER NOT NULL,
                order_date TEXT DEFAULT CURRENT_TIMESTAMP,
                total_amount REAL NOT NULL,
                margin REAL,
                status TEXT CHECK(status IN ('pending', 'processing', 'completed', 'cancelled')),
                FOREIGN KEY (customer_id) REFERENCES customers(id)
            );

            CREATE TABLE order_items (
                item_id INTEGER PRIMARY KEY,
                order_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER NOT NULL CHECK(quantity > 0),
                unit_price REAL NOT NULL,
                FOREIGN KEY (order_id) REFERENCES orders(order_id),
                FOREIGN KEY (product_id) REFERENCES products(product_id)
            );

            CREATE INDEX idx_products_category ON products(category_id);
            CREATE INDEX idx_orders_customer ON orders(customer_id);
            CREATE INDEX idx_orders_date ON orders(order_date);

            CREATE VIEW product_catalog_view AS
            SELECT
                p.product_id,
                p.name AS product_name,
                c.name AS category_name,
                p.price,
                p.stock_quantity
            FROM products p
            LEFT JOIN categories c ON p.category_id = c.category_id;
            """
        )

        # Seed data
        conn.executemany(
            "INSERT INTO categories (category_id, name) VALUES (?, ?);",
            [(1, "Electronics"), (2, "Home & Kitchen"), (3, "Books")],
        )

        conn.executemany(
            """
            INSERT INTO customers (
                id, first_name, last_name, email, password_hash,
                api_key, credit_score, internal_notes, city, country
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [
                (
                    1,
                    "Alice",
                    "Smith",
                    "alice@example.com",
                    "argon2$hash_secret_1",
                    "ak_live_xyz123",
                    750,
                    "VIP customer",
                    "Seattle",
                    "US",
                ),
                (
                    2,
                    "Bob",
                    "Jones",
                    "bob@example.com",
                    "argon2$hash_secret_2",
                    "ak_live_abc456",
                    680,
                    "Payment issue flagged",
                    "New York",
                    "US",
                ),
                (
                    3,
                    "Charlie",
                    "Brown",
                    "charlie@example.com",
                    "argon2$hash_secret_3",
                    None,
                    720,
                    "Regular shopper",
                    "London",
                    "UK",
                ),
            ],
        )

        conn.executemany(
            """
            INSERT INTO products (
                product_id, category_id, name, sku, price, stock_quantity
            )
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            [
                (1, 1, "Noise-Cancelling Headphones", "TECH-001", 199.99, 45),
                (2, 1, "Mechanical Keyboard", "TECH-002", 129.50, 80),
                (3, 2, "Pour-Over Coffee Maker", "HOME-001", 34.00, 120),
                (4, 3, "Designing Data-Intensive Applications", "BOOK-001", 45.00, 200),
            ],
        )

        conn.executemany(
            """
            INSERT INTO orders (
                order_id, customer_id, total_amount, margin, status
            )
            VALUES (?, ?, ?, ?, ?);
            """,
            [
                (101, 1, 199.99, 50.00, "completed"),
                (102, 1, 79.00, 20.00, "completed"),
                (103, 2, 129.50, 35.00, "processing"),
            ],
        )

        conn.commit()
    finally:
        conn.close()

    print(f"Sample database created successfully at: {db_path.resolve()}")


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("sample.sqlite")
    create_sample_database(target)
