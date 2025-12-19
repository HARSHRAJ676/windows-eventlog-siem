import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class AlertsConfig:
    enabled_channels: List[str] = field(default_factory=list)
    telegram: Dict[str, Any] = field(default_factory=dict)
    discord: Dict[str, Any] = field(default_factory=dict)
    email: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AppConfig:
    interval_seconds: int = 10
    channels: List[str] = field(default_factory=lambda: ["System", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"])
    alerts: AlertsConfig = field(default_factory=AlertsConfig)
    thresholds: Dict[str, Any] = field(default_factory=dict)
    database: Dict[str, str] = field(default_factory=dict)
    export: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def load(path: str) -> "AppConfig":
        if not os.path.exists(path):
            default = AppConfig()
            AppConfig.write_default(path, default)
            return default
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        alerts = AlertsConfig(**data.get('alerts', {}))
        cfg = AppConfig(
            interval_seconds=data.get('interval_seconds', 10),
            channels=data.get('channels', ["System", "Security", "Windows PowerShell", "Microsoft-Windows-PowerShell/Operational"]),
            alerts=alerts,
            thresholds=data.get('thresholds', {}),
            database=data.get('database', {}),
            export=data.get('export', {}),
        )
        return cfg

    @staticmethod
    def write_default(path: str, cfg: "AppConfig"):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({
                'interval_seconds': cfg.interval_seconds,
                'channels': cfg.channels,
                'alerts': {
                    'enabled_channels': cfg.alerts.enabled_channels,
                    'telegram': cfg.alerts.telegram,
                    'discord': cfg.alerts.discord,
                    'email': cfg.alerts.email,
                },
                'thresholds': cfg.thresholds,
                'database': cfg.database,
                'export': cfg.export,
            }, f, indent=2)
