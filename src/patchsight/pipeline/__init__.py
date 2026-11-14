"""Offline pipeline: ingestion, diff mapping, LLM extraction, database build.

This is the only package allowed to use an LLM. Nothing on the scan path may import it.
"""
