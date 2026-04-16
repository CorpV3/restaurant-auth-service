#!/bin/bash
# DB migration bootstrap for auth-service.
# Migration 001 is a no-op baseline — safe to run from scratch.
set -e

echo "=== DB Migration: auth-service ==="
echo "Running: alembic upgrade head"
alembic upgrade head
echo "=== Migration complete ==="
