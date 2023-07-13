# Copyright (C) 2020 Mandiant, Inc. All Rights Reserved.

from PyInstaller.utils.hooks import copy_metadata

hiddenimports = [
    "textual.widgets._tab_pane",
]
