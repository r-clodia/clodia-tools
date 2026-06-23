"""Sottosistema Topic v2 — storage astratto pluggable + servizio verbi.

Vedi spec "Topic System v2". Il gateway è il reference monitor: gli agenti
toccano i topic SOLO via i verbi del servizio; lo storage (local-fs, Drive, …)
è dietro, raggiungibile solo dal gateway.
"""
