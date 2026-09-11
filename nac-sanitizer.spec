# SPDX-License-Identifier: MPL-2.0
# Copyright (c) 2025 Christopher Hart

"""PyInstaller spec for building nac-sanitizer standalone binary."""

import os

block_cipher = None

a = Analysis(
    ["nac_sanitizer/__main__.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("nac_sanitizer/resources", "nac_sanitizer/resources"),
    ],
    hiddenimports=[
        "nac_sanitizer",
        "nac_sanitizer.cli",
        "nac_sanitizer.cli.main",
        "nac_sanitizer.config",
        "nac_sanitizer.config.loader",
        "nac_sanitizer.config.models",
        "nac_sanitizer.engine",
        "nac_sanitizer.engine.ip_allocator",
        "nac_sanitizer.engine.ip_scanner",
        "nac_sanitizer.engine.resolver",
        "nac_sanitizer.engine.strategies",
        "nac_sanitizer.profiles",
        "nac_sanitizer.profiles.registry",
        "nac_sanitizer.resources",
        "nac_sanitizer.rosetta",
        "nac_sanitizer.rosetta.writer",
        "nac_sanitizer.sanitizer",
        "nac_sanitizer.zip_handler",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="nac-sanitizer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
